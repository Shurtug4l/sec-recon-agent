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
    # Cap is generous to absorb pasted SBOMs (CycloneDX/SPDX can easily
    # hit tens of KB) while still bounding the worst case for both DoS
    # and LLM token cost. Tool-level caps (e.g. sbom_ingest's 5 MB,
    # cve_semantic_search's truncation at 1000 chars) provide the
    # downstream safety net.
    query: str = Field(min_length=1, max_length=100_000)
    # Optional per-request LLM override. Subject to the allowlist in
    # agent/triage.py::ALLOWED_MODELS (plus haiku/sonnet/opus aliases).
    # Used by sec-recon-eval --model for differential evaluation; the
    # frontend never sets it.
    model: str | None = Field(default=None, max_length=64)


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
                name="sbom_ingest",
                description=(
                    "Parse a CycloneDX / SPDX / requirements.txt SBOM "
                    "into a normalized list of components with name, "
                    "version, ecosystem, purl. Pairs with cve_semantic_"
                    "search for per-component triage."
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
        import time
        import uuid

        try:
            agent = build_agent(model_override=req.model)
        except ValueError as exc:
            # Bad model override -> emit one error event and bail.
            yield {"event": "started", "data": req.model_dump_json()}
            yield {
                "event": "error",
                "data": _error_payload(exc, safe_message=str(exc)),
            }
            return
        yield {"event": "started", "data": req.model_dump_json()}

        started_at = time.monotonic()
        outcome = "success"
        error_class: str | None = None
        result_json: str | None = None
        try:
            async with agent.iter(req.query) as run:
                async for node in run:
                    yield {
                        "event": "node",
                        "data": _node_event_payload(node),
                    }
                result_output = run.result.output  # type: ignore[union-attr]
            result_json = result_output.model_dump_json()
            yield {"event": "final", "data": result_json}
        except Exception as exc:
            outcome = "error"
            error_class = exc.__class__.__name__
            log.exception("triage_failed", error=str(exc))
            yield {
                "event": "error",
                "data": _error_payload(exc),
            }
        finally:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            # Best-effort: never fail the request because the audit log
            # failed. Worst case we log a warning and drop the event.
            try:
                _audit_triage(
                    event_id=uuid.uuid4().hex,
                    query=req.query,
                    result_json=result_json,
                    outcome=outcome,
                    error_class=error_class,
                    duration_ms=duration_ms,
                )
            except Exception:
                log.warning("audit_append_failed", exc_info=True)

    return EventSourceResponse(event_generator())


def _audit_triage(
    *,
    event_id: str,
    query: str,
    result_json: str | None,
    outcome: str,
    error_class: str | None,
    duration_ms: int,
) -> None:
    """Append one TriageEvent to the audit store. Settings gate everything."""
    if not settings.audit_log_enabled:
        return

    import json

    from sec_recon_agent.audit.models import (
        GENESIS_HASH,
        TriageEvent,
        sha256_hex,
        summarize_for_audit,
        utcnow_iso,
    )

    report_dict: dict[str, Any] = {}
    report_summary_plain: str | None = None
    if result_json is not None:
        try:
            report_dict = json.loads(result_json)
            if isinstance(report_dict.get("summary"), str):
                report_summary_plain = report_dict["summary"][:500]
        except (json.JSONDecodeError, TypeError):
            report_dict = {}

    summary = summarize_for_audit(report_dict)
    raw_for_hash = result_json if result_json is not None else ""

    event = TriageEvent(
        event_id=event_id,
        ts=utcnow_iso(),
        query_sha256=sha256_hex(query),
        query_length=len(query),
        query_plain=query if settings.audit_include_query else None,
        report_sha256=sha256_hex(raw_for_hash),
        severity=summary["severity"] if isinstance(summary["severity"], str) else None,
        confidence=(
            summary["confidence"] if isinstance(summary["confidence"], str) else None
        ),
        cves_count=int(summary["cves_count"] or 0),
        attack_techniques_count=int(summary["attack_techniques_count"] or 0),
        kev_hits=int(summary["kev_hits"] or 0),
        ransomware_hits=int(summary["ransomware_hits"] or 0),
        high_epss_hits=int(summary["high_epss_hits"] or 0),
        report_summary_plain=(
            report_summary_plain if settings.audit_include_summary else None
        ),
        model=f"{settings.llm_provider}:{settings.llm_model}",
        duration_ms=duration_ms,
        outcome=outcome,
        error_class=error_class,
        prev_event_hash=GENESIS_HASH,  # AuditStore.append overwrites under its lock
    )
    _get_audit_store().append(event)


_AUDIT_STORE: "Any | None" = None


def _get_audit_store() -> Any:
    """Lazy singleton so test fixtures can monkeypatch settings.audit_db_path
    before the first call."""
    global _AUDIT_STORE
    if _AUDIT_STORE is None:
        from sec_recon_agent.audit.store import AuditStore

        _AUDIT_STORE = AuditStore(settings.audit_db_path)
    return _AUDIT_STORE


def _reset_audit_store() -> None:
    """Test-only: drop the cached store so a new db_path takes effect."""
    global _AUDIT_STORE
    if _AUDIT_STORE is not None:
        _AUDIT_STORE.close()
    _AUDIT_STORE = None


def _node_event_payload(node: object) -> str:
    """JSON-serialize a minimal node descriptor.

    We deliberately surface only the node class name (not the full state),
    because (a) the Pydantic AI node API churns across versions and (b)
    raw internal state can leak instruction-like content from tool output
    into the SSE stream. Class name is a stable progress signal.
    """
    import json
    return json.dumps({"node": node.__class__.__name__})


def _error_payload(exc: BaseException, safe_message: str | None = None) -> str:
    import json

    if safe_message is not None:
        message = safe_message
    elif isinstance(exc, _SAFE_TO_ECHO):
        message = str(exc)
    else:
        message = "Internal error; check server logs."
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
