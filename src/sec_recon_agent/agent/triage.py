"""Pydantic AI triage agent.

Wires the seven MCP tools (cve_lookup, cve_semantic_search, exploit_check,
kev_check, epss_score, nmap_parse_xml, attack_mapping) into a single
agent that emits a typed TriageReport.

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


def export_anthropic_api_key_to_env() -> None:
    """Move ANTHROPIC_API_KEY from pydantic-settings into os.environ.

    Pydantic AI's Anthropic provider reads the key from os.environ rather
    than from our Settings object. We push it once at process startup
    (called from `api/stream.py::main` and `mcp_server/server.py::main`)
    so SecretStr leaks the secret only at the latest moment possible.
    Do NOT call this from request handlers.
    """
    if settings.anthropic_api_key and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = settings.anthropic_api_key.get_secret_value()


# Allowlist of LLM model identifiers the API will honor when a per-request
# override is supplied via TriageRequest.model. Keeping it explicit prevents
# (a) accidentally pointing the agent at an unintended provider or sandbox
# model via a body param, and (b) the comparison eval suite from being
# weaponized as a probe for arbitrary model strings.
ALLOWED_MODELS: frozenset[str] = frozenset(
    {
        "claude-haiku-4-5-20251001",
        "claude-sonnet-4-6",
        "claude-opus-4-7",
    },
)

# Short aliases the eval CLI can pass in place of the full identifier.
MODEL_ALIASES: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-6",
    "opus": "claude-opus-4-7",
}


def resolve_model(override: str | None) -> str:
    """Return the model identifier to use for one triage call.

    `override` may be:
      - None: use settings.llm_model (the default for the deployment);
      - a short alias (haiku / sonnet / opus): expand via MODEL_ALIASES;
      - a full identifier: must appear in ALLOWED_MODELS.

    Any other value raises ValueError; the API surface translates that
    into HTTP 400.
    """
    if override is None:
        return settings.llm_model
    candidate = MODEL_ALIASES.get(override, override)
    if candidate not in ALLOWED_MODELS:
        raise ValueError(
            f"model {override!r} is not on the allowlist; "
            f"choose one of {sorted(ALLOWED_MODELS)}",
        )
    return candidate


def build_agent(model_override: str | None = None) -> Agent[None, TriageReport]:
    """Construct the triage agent wired to the local MCP server.

    The Anthropic API key must already be in os.environ when this is
    invoked (see `export_anthropic_api_key_to_env`). Building the agent
    inside a request handler is fine; exporting the secret per request
    is not.

    `model_override` lets one request bypass `settings.llm_model` (the
    deployment default) in favor of a specific Anthropic model. The
    override goes through `resolve_model` which enforces an allowlist.
    """
    model = resolve_model(model_override)
    toolset = MCPToolset(f"{settings.mcp_server_url}/sse")

    return Agent(
        model=f"{settings.llm_provider}:{model}",
        output_type=TriageReport,
        toolsets=[toolset],
        system_prompt=SYSTEM_PROMPT,
    )
