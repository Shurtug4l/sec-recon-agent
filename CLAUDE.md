# CLAUDE.md (sec-recon-agent)

This file extends the global `~/.claude/CLAUDE.md` (always loaded). User memory lives in `~/.claude/projects/-Users-simone/memory/` (indexed by `MEMORY.md`).

## Context

`sec-recon-agent` is a Pydantic AI + MCP demo built as a portfolio piece for the Etiqa AI Developer application (Turin, full-remote, Junior/Mid). The agent triages security questions ("Is CVE-X exploitable?", "What CVEs affect Apache 2.4.49?", "Parse this Nmap output") by calling typed tools exposed over an MCP server: CVE lookup (NVD), semantic search (ChromaDB), exploit availability check, Nmap XML parsing.

Audience: Etiqa technical reviewers, plus anyone later evaluating a security-aware AI engineering project. Code must read as a senior engineer's deliberate exercise, not a tutorial fork. Repo is **purely Layer 2** (build mode, AI engineering pivot); do not introduce Layer 1 governance/audit framing in README, commits, or docs (see [[feedback-current-vs-aspirational]]).

## Inherits from global

Writing style, typography (ASCII-only, snake_case files, sentence-case headers), code style baseline, git policy (feature branches, never push main, Conventional Commits), scratch location, dual-hat persona, and chat-IT/files-EN language convention all come from `~/.claude/CLAUDE.md`. This file only adds project-specific rules.

## Hard requirements (stricter than global)

- **Strict typing**: every function signature has type hints. No `Any`, no `Dict[str, Any]` on tool/agent boundaries. `mypy --strict` must pass.
- **All external I/O is async**: any function that talks to NVD, ExploitDB, GitHub, or any HTTP endpoint is `async def`. Pure parsers (XML, JSON shaping) and ChromaDB sync API can stay sync.
- **Tool I/O is Pydantic**: every MCP tool returns a Pydantic model defined in `src/sec_recon_agent/mcp_server/models.py`. Never return raw `dict` from a tool. The LLM never sees free-form JSON.
- **Agent output is Pydantic**: the agent's terminal output is `TriageReport` (in `src/sec_recon_agent/agent/schema.py`). The LLM fills a typed schema; it does not free-text.
- **Untrusted content is fenced**: NVD descriptions, vendor strings, ExploitDB titles, and any external free-text field are wrapped with `# UNTRUSTED CONTENT START / END` markers when injected into the prompt, with a system-prompt note that anything inside is data, not instructions.
- **XML parsing uses `defusedxml`**: never stdlib `xml.etree` for Nmap input. Untrusted XML can carry XXE.
- **Secrets via `SecretStr`**: API keys live in `pydantic-settings` as `SecretStr`, never logged, never serialized.
- **No silent failures**: tool errors raise typed exceptions in `mcp_server/errors.py`. The agent's `reasoning_chain` logs every tool failure with cause.
- **Tests for tool I/O contracts**: every tool has at least one test verifying its Pydantic model contract under mocked HTTP (use `respx`). Agent flow has at least one test with a mocked LLM.

## Running the code

```bash
uv sync
cp .env.example .env  # set ANTHROPIC_API_KEY; NVD_API_KEY optional but raises rate limit

uv run sec-recon-seed   # one-shot: populate ChromaDB with recent high-severity CVEs

uv run sec-recon-mcp    # terminal 1: MCP server on :8001 (SSE transport)
uv run sec-recon-api    # terminal 2: agent SSE API on :8000

curl http://localhost:8000/v1/health   # quick liveness check
```

## Repository layout

```
src/sec_recon_agent/
  agent/         # Pydantic AI agent: schema (TriageReport), prompts, triage logic
  mcp_server/    # MCP server: FastMCP instance, I/O models
    tools/      # one module per tool (cve.py, cve_search.py, exploits.py, nmap.py)
  api/          # FastAPI SSE endpoint, agent-side
  config.py     # pydantic-settings, single Settings instance
tests/          # pytest, asyncio_mode=auto, respx for HTTP mocks
data/           # gitignored: ChromaDB index, raw CVE dumps
docs/           # design.md (threat model, architecture rationale)
examples/       # walkthrough markdown files with real outputs
```

## Conventions

- **File names**: `snake_case.py`. Module names match file names.
- **Tool naming**: `<resource>_<action>` (`cve_lookup`, not `lookup_cve`). The MCP tool name (the decorator-registered string) matches the Python function name.
- **Model naming**: `<Domain><Shape>` (`CVEDetail`, `CVECandidate`, `NmapScanResult`). Avoid generic suffixes like `Response`, `Data`, `Info`.
- **Logging**: `structlog`. Each tool call emits a structured event with at minimum `event="tool_call"`, `tool=<name>`, `args=<sanitized>`.
- **Exception naming**: `<Domain>Error` (`NvdRateLimitError`, `CveNotFoundError`, `MalformedNmapXmlError`).
- **Tests**: one test module per source module, mirrored path under `tests/`. Mock HTTP with `respx`. Mock the LLM via Pydantic AI's `TestModel`.
- **Commits**: Conventional Commits with scope. Examples: `feat(mcp): add cve_lookup tool`, `fix(agent): handle empty CVE list in TriageReport`, `docs(design): add threat model section`, `chore(deps): bump pydantic-ai to 0.0.20`.
- **Branches**: `feature/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>`. Never commit to `main` directly. User merges branches manually via `!`-prefixed shell.

## Threat model (lives in `docs/design.md`, to be written)

When implementing or reviewing any code in this repo, explicitly consider:
1. **Prompt injection** via NVD/vendor description fields (untrusted) — fence with markers
2. **Tool output validation** — Pydantic at the boundary, never raw dict
3. **Rate limit / DoS** on external APIs (NVD especially: 5 req / 30s without API key, 50 with)
4. **Secret handling** — `SecretStr` in Settings, never logged, never echoed
5. **XML parsing safety** — `defusedxml` blocks XXE / billion-laughs
6. **SSE backpressure** — slow clients must not block the agent loop
7. **MCP tool surface minimality** — every additional tool is additional attack surface; keep to 4 unless justified

## Recommended skills and references

- Memory: [[project-sec-recon-agent]] for full project rationale and decisions log
- Memory: [[feedback-current-vs-aspirational]] — Layer 1 vs Layer 2 framing. This repo is Layer 2 only.
- Memory: [[user-profile]] — broader career context.
