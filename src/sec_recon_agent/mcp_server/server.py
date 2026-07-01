"""MCP server entry point.

This module owns the FastMCP instance. Tool modules import `mcp` from here
and register handlers via @mcp.tool. main() triggers tool registration via
side-effect imports, then starts the SSE HTTP transport.

When `MCP_AUTH_TOKEN` is set, the SSE ASGI app is wrapped in a bearer-token
gate before being served by uvicorn. When unset, the server runs open
(legacy behavior, suitable for docker-compose-internal usage only).
"""

from typing import cast

import structlog
import uvicorn
from mcp.server.fastmcp import FastMCP

from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.auth import ASGIApp, BearerAuthASGI
from sec_recon_agent.observability import setup_tracing

log = structlog.get_logger()

mcp = FastMCP(
    "sec-recon",
    host=settings.mcp_server_host,
    port=settings.mcp_server_port,
)


@mcp.tool()
def ping() -> str:
    """Liveness probe; returns 'pong'."""
    return "pong"


def _register_tools() -> None:
    """Side-effect imports so tool modules execute their @mcp.tool decorators."""
    from sec_recon_agent.mcp_server.tools import (
        attack,  # noqa: F401
        cve,  # noqa: F401
        cve_search,  # noqa: F401
        epss,  # noqa: F401
        exploits,  # noqa: F401
        kev,  # noqa: F401
        nmap,  # noqa: F401
        osv,  # noqa: F401
        patch,  # noqa: F401
        sbom,  # noqa: F401
    )


def build_app() -> ASGIApp:
    """Return the ASGI app to serve, with optional bearer-auth wrap.

    Pulled out of `main()` so tests can exercise both the open and the
    authenticated path without binding a real socket.
    """
    # FastMCP.sse_app() returns a Starlette instance whose __call__ matches
    # the ASGI protocol but uses MutableMapping in its signature, so mypy
    # treats it as incompatible with our narrower Callable alias. The
    # narrow alias is what we want for tests and middleware composition,
    # so cast once at the seam.
    app: ASGIApp = cast(ASGIApp, mcp.sse_app())
    token = settings.mcp_auth_token
    if token is not None:
        secret = token.get_secret_value()
        if secret:
            log.info("mcp_auth_enabled")
            return BearerAuthASGI(app, secret)
    log.info("mcp_auth_disabled")
    return app


def main() -> None:
    setup_tracing("sec-recon-mcp-server")
    _register_tools()
    log.info(
        "mcp_server_starting",
        host=settings.mcp_server_host,
        port=settings.mcp_server_port,
        transport="sse",
        auth=settings.mcp_auth_token is not None,
    )
    app = build_app()
    config = uvicorn.Config(
        app,
        host=settings.mcp_server_host,
        port=settings.mcp_server_port,
        log_level=settings.log_level.lower(),
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
