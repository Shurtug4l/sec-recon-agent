"""FastAPI surface for the triage agent.

Endpoints:
- POST /v1/triage: streams agent progress over Server-Sent Events. Emits
  a `started` event, one `node` event per agent step (model request,
  tool call, tool result), and a final `final` event carrying the
  TriageReport JSON.
- GET /v1/health: liveness probe.
- GET /v1/meta: exposes the system prompt and the tool inventory so the
  UI's transparency view can show what the agent is told and what it can
  reach. Read-only, no auth, single-tenant demo.

The agent reaches the MCP server over its own HTTP+SSE connection; the
API process and the MCP server are independent.
"""

from collections.abc import AsyncIterator
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from sec_recon_agent.agent.prompts import SYSTEM_PROMPT
from sec_recon_agent.agent.triage import build_agent, export_anthropic_api_key_to_env
from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.errors import CveNotFoundError
from sec_recon_agent.observability import setup_tracing

# Exceptions whose string form is safe to surface to the SSE client.
# Everything else is replaced with a generic message: internal exception
# messages can leak filesystem paths, query parameters, or library
# internals that the client should not see.
_SAFE_TO_ECHO: tuple[type[BaseException], ...] = (CveNotFoundError,)

log = structlog.get_logger()

app = FastAPI(
    title="sec-recon-agent",
    description="Type-safe security triage via Pydantic AI + MCP.",
    version="0.1.0",
)


class TriageRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)


@app.get("/v1/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


class ToolMeta(BaseModel):
    name: str
    description: str


class MetaResponse(BaseModel):
    system_prompt: str
    model: str
    tools: list[ToolMeta]


@app.get("/v1/meta", response_model=MetaResponse)
async def meta() -> MetaResponse:
    """Expose the agent's "what is it told" and "what can it reach" so a
    transparency UI can render them. The system prompt is the literal
    string the LLM receives. The tool list is curated here, not introspected
    from the MCP server: the tools are part of the project contract,
    not a runtime discovery (which would couple this endpoint to live MCP
    connectivity)."""
    return MetaResponse(
        system_prompt=SYSTEM_PROMPT,
        model=f"{settings.llm_provider}:{settings.llm_model}",
        tools=[
            ToolMeta(
                name="cve_lookup",
                description=(
                    "Fetch the full NVD record for a known CVE ID. "
                    "Returns CVSS v3 score and severity, CWE IDs, affected "
                    "CPEs, references."
                ),
            ),
            ToolMeta(
                name="cve_semantic_search",
                description=(
                    "Vector search over an indexed corpus of recent "
                    "high-severity CVEs. Use when the user describes a "
                    "product or symptom without naming a CVE."
                ),
            ),
            ToolMeta(
                name="exploit_check",
                description=(
                    "Look up public exploits and PoCs for a CVE. Queries "
                    "Exploit-DB and GitHub Code Search in parallel."
                ),
            ),
            ToolMeta(
                name="kev_check",
                description=(
                    "Check whether a CVE is on the CISA Known Exploited "
                    "Vulnerabilities catalog. Strongest 'patch now' signal "
                    "with federal due date and known-ransomware flag."
                ),
            ),
            ToolMeta(
                name="epss_score",
                description=(
                    "Fetch the FIRST.org EPSS probability that a CVE will "
                    "be exploited in the next 30 days, plus percentile "
                    "rank. Complements KEV for forward-looking prioritization."
                ),
            ),
            ToolMeta(
                name="nmap_parse_xml",
                description=(
                    "Parse Nmap XML scan output into structured hosts, "
                    "ports, services, and version banners. defusedxml-safe."
                ),
            ),
            ToolMeta(
                name="attack_mapping",
                description=(
                    "Map a list of CWE IDs to MITRE ATT&CK techniques and "
                    "their mitigations. Enriches the triage with "
                    "adversary-side context and defense-side guidance."
                ),
            ),
        ],
    )


@app.post("/v1/triage")
async def triage(req: TriageRequest) -> EventSourceResponse:
    """Run the triage agent and stream progress as SSE events."""

    async def event_generator() -> AsyncIterator[dict[str, Any]]:
        agent = build_agent()
        yield {"event": "started", "data": req.model_dump_json()}
        try:
            async with agent.iter(req.query) as run:
                async for node in run:
                    yield {
                        "event": "node",
                        "data": _node_event_payload(node),
                    }
                result_output = run.result.output  # type: ignore[union-attr]
            yield {"event": "final", "data": result_output.model_dump_json()}
        except Exception as exc:
            log.exception("triage_failed", error=str(exc))
            yield {
                "event": "error",
                "data": _error_payload(exc),
            }

    return EventSourceResponse(event_generator())


def _node_event_payload(node: object) -> str:
    """JSON-serialize a minimal node descriptor.

    We deliberately surface only the node class name (not the full state),
    because (a) the Pydantic AI node API churns across versions and (b)
    raw internal state can leak instruction-like content from tool output
    into the SSE stream. Class name is a stable progress signal.
    """
    import json
    return json.dumps({"node": node.__class__.__name__})


def _error_payload(exc: BaseException) -> str:
    import json
    message = str(exc) if isinstance(exc, _SAFE_TO_ECHO) else "Internal error; check server logs."
    return json.dumps({"type": exc.__class__.__name__, "message": message})


def main() -> None:
    """Entry point for `uv run sec-recon-api`."""
    setup_tracing("sec-recon-agent-api")
    # Instrument the FastAPI app after the tracer provider is in place.
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    FastAPIInstrumentor.instrument_app(app)
    export_anthropic_api_key_to_env()
    uvicorn.run(
        "sec_recon_agent.api.stream:app",
        host=settings.agent_api_host,
        port=settings.agent_api_port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
