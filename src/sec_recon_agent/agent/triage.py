"""Pydantic AI triage agent.

Wires the four MCP tools (cve_lookup, cve_semantic_search, exploit_check,
nmap_parse_xml) into a single agent that emits a typed TriageReport.

The MCP transport is HTTP+SSE; SSE is inferred from the `/sse` URL suffix.
The agent connects to the sec-recon MCP server (default :8001). Caller is
responsible for entering `agent.run_toolsets()` before invoking
`agent.run(...)`, or using `agent.iter(...)` which manages it implicitly.
"""

import os

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset

from sec_recon_agent.agent.prompts import SYSTEM_PROMPT
from sec_recon_agent.agent.schema import TriageReport
from sec_recon_agent.config import settings


def build_agent() -> Agent[None, TriageReport]:
    """Construct the triage agent wired to the local MCP server.

    pydantic-settings populates Settings from .env, but Pydantic AI reads
    ANTHROPIC_API_KEY directly from os.environ. Push it once on build so
    callers don't need to manage that themselves.
    """
    if settings.anthropic_api_key and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = settings.anthropic_api_key.get_secret_value()

    toolset = MCPToolset(f"{settings.mcp_server_url}/sse")

    return Agent(
        model=f"{settings.llm_provider}:{settings.llm_model}",
        output_type=TriageReport,
        toolsets=[toolset],
        system_prompt=SYSTEM_PROMPT,
    )
