"""FastAPI surface for the triage agent.

Two endpoints:
- POST /v1/triage: streams agent progress over Server-Sent Events. Emits
  a `started` event, one `node` event per agent step (model request,
  tool call, tool result), and a final `final` event carrying the
  TriageReport JSON.
- GET /v1/health: liveness probe.

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

from sec_recon_agent.agent.triage import build_agent
from sec_recon_agent.config import settings

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
        except Exception as exc:  # noqa: BLE001
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
    return json.dumps({"type": exc.__class__.__name__, "message": str(exc)})


def main() -> None:
    """Entry point for `uv run sec-recon-api`."""
    uvicorn.run(
        "sec_recon_agent.api.stream:app",
        host=settings.agent_api_host,
        port=settings.agent_api_port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
