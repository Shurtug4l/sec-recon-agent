# sec-recon-agent

Type-safe security triage built on Pydantic AI and a custom Model Context Protocol server.

The agent answers vulnerability questions ("Is CVE-X exploitable?", "What CVEs affect Apache 2.4.49?", "Triage this Nmap output") by calling typed tools exposed over MCP:

- `cve_lookup` — async NVD API client, rate-limited, returns a structured `CVEDetail`
- `cve_semantic_search` — vector retrieval over a local ChromaDB index of recent high-severity CVEs
- `exploit_check` — public-exploit availability (ExploitDB + GitHub PoC search)
- `nmap_parse_xml` — pure parser, structured port/service extraction

The agent never produces free-text guessing. Its only output is a `TriageReport` Pydantic model: severity, exploit availability, recommended action, and the full reasoning chain.

## Why this exists

Most LLM "security assistants" hallucinate CVEs and exploit details. This one is a deliberate exercise in:

- **Strict typing on the model boundary**: every tool I/O is a Pydantic model. The LLM never sees raw JSON, only structured contracts
- **MCP as the integration layer**: tools live in a separate process, callable from any MCP-compatible client (Claude Desktop, a custom client, this agent)
- **Streaming UX**: tool calls and intermediate reasoning are streamed via Server-Sent Events
- **Security-aware AI engineering**: untrusted tool content (CVE descriptions from third parties) is fenced in the prompt; the agent has no out-of-band tools beyond the declared MCP surface

## Architecture

```
client --SSE--> agent API (FastAPI :8000)
                    │
                    │ Pydantic AI tool calls
                    ▼
                MCP client --HTTP--> MCP server (:8001)
                                          │
                                          ├── NVD API (cve_lookup)
                                          ├── ChromaDB (semantic search)
                                          ├── ExploitDB + GitHub (exploit_check)
                                          └── XML parser (nmap_parse)
```

## Stack

Python 3.12+ · Pydantic AI · MCP (Anthropic SDK) · FastAPI (SSE) · ChromaDB (ONNX MiniLM embedder) · httpx · structlog · uv

## Running

### With Docker (recommended)

```bash
cp .env.example .env       # set ANTHROPIC_API_KEY (NVD_API_KEY and GITHUB_TOKEN optional)
make build                 # multi-stage uv build, non-root runtime
make seed                  # one-shot: pull recent CVEs into ChromaDB
make up                    # start MCP server + agent API + frontend
make ui                    # opens http://localhost:3000 in the browser
make triage Q="Apache 2.4.49 on port 80. Risk?"   # or use the UI
make logs                  # tail logs
make down                  # stop, keep the data volume
```

Three services bound to `127.0.0.1`:
- `:3000` — Next.js frontend (React 19, Tailwind, Catppuccin theme, dark/light toggle, history sidebar)
- `:8000` — agent API (FastAPI + SSE)
- `:8001` — MCP server (FastMCP)

All run as non-root users (`secrecon` uid 1000 for the backend, `node` uid 1000 for the frontend) with `no-new-privileges`; backend containers are `read_only: true`.

### With observability (Jaeger sidecar)

```bash
make obs-up                # starts MCP + API + jaeger; spans go to OTLP
open http://localhost:16686  # Jaeger UI
make obs-down              # stops the observability stack
```

Without the profile, spans go to stdout (zero infrastructure). Every tool call emits a span with attributes (`tool.name`, `cve.id`, `tool.success`, `cve.cvss_v3_score`, `hosts.count`, ...). User query text and untrusted vendor content are deliberately NOT recorded as attributes — tests in `tests/test_observability.py` enforce this invariant.

### Without Docker

```bash
uv sync
cp .env.example .env       # add ANTHROPIC_API_KEY (and optionally NVD_API_KEY)

uv run sec-recon-seed      # seed ChromaDB (~30 days lookback, several thousand CVEs)

uv run sec-recon-mcp       # terminal 1: MCP server on :8001
uv run sec-recon-api       # terminal 2: agent API on :8000

curl -N -X POST http://localhost:8000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"query": "Apache 2.4.49 on port 80. Risk?"}'
```

## Status

All four MCP tools, the Pydantic AI agent, and the FastAPI SSE surface have landed. Container stack (Docker + compose), OpenTelemetry tracing, Jaeger sidecar profile, and a Next.js 15 + React 19 + Tailwind frontend are in place. Test suite: 88 passed (35 contract + 45 property/adversarial + 8 observability). See:

- `docs/design.md` — architecture decisions, threat model, and the security review findings applied to the code.
- `examples/triage_walkthrough.md` — three real sessions against the live agent (specific CVE, product description, Nmap XML), captured 2026-05-18.

## License

MIT.
