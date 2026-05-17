"""MCP server entry point.

This module owns the FastMCP instance. Tool modules import `mcp` from here
and register handlers via @mcp.tool. main() triggers tool registration via
side-effect imports, then starts the SSE HTTP transport.
"""

import structlog
from mcp.server.fastmcp import FastMCP

from sec_recon_agent.config import settings

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
    from sec_recon_agent.mcp_server.tools import cve  # noqa: F401
    from sec_recon_agent.mcp_server.tools import cve_search  # noqa: F401
    from sec_recon_agent.mcp_server.tools import nmap  # noqa: F401

    # Populated as tools land:
    # from sec_recon_agent.mcp_server.tools import exploits    # noqa: F401


def main() -> None:
    _register_tools()
    log.info(
        "mcp_server_starting",
        host=settings.mcp_server_host,
        port=settings.mcp_server_port,
        transport="sse",
    )
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
