# sec-recon-agent design

A short engineering brief for the next reviewer. Covers: what the system is, how it is wired, the non-trivial design choices and why other options were rejected, the threat model with the controls actually applied in code, and what is deliberately out of scope.

## What this is

A security triage agent. Given a CVE ID, a product description, or Nmap XML output, it returns a typed `TriageReport` (severity, exploit availability, recommended action, full reasoning chain) by calling four MCP tools and synthesizing the result with an LLM.

Built as a portfolio piece, not a production deployment. The design choices are documented here precisely because a reviewer's first question is usually "why this way and not the obvious other way."

## System architecture

```
Browser
   |
   | HTTP                          (only same-origin; no CORS opened on backend)
   v
+------------------------------+
|  Frontend (Next.js 15)       |  :3000
|  React 19 + Tailwind         |
|  /api/triage  ──── proxy ────┐
+------------------------------+│
                                │  HTTP+SSE
                                v
                       +------------------------------+
                       |  Agent API (FastAPI)         |  :8000
                       |  Pydantic AI agent           |
                       |  POST /v1/triage  (SSE)      |
                       |  GET  /v1/health             |
                       +-------------+----------------+
                                     |  MCPToolset (HTTP+SSE)
                                     v
                       +------------------------------+
                       |  MCP Server (FastMCP)        |  :8001
                       |  7 typed tools               |
                       +---+---+---+---+--------------+
                           |   |   |   |
                NVD CVE 2.0|   |   |   |defusedxml (nmap_parse_xml)
                           |   |   |   |
                  ChromaDB |   |   |   |Exploit-DB CSV + GitHub Search
              (cve_search) |   |   |   |(exploit_check, parallel fan-out)
                           |   |   |   |
                           |   |   |   |CISA KEV catalog (kev_check, 24h disk cache)
                           |   |   |
                           |   |   |FIRST EPSS API (epss_score, single-shot)
                           |   |
                           |   |MITRE ATT&CK (attack_mapping, bundled JSON)
                           |
                           +-- cve_lookup (httpx, rate-limited, retry)
```

Four processes, deliberately. The frontend, the agent API, and the MCP server are independent containers; each restarts without taking the others down. The browser only ever sees `:3000` — the agent API has no CORS opened and stays single-tenant; the Next.js `/api/triage` route forwards the SSE stream byte-for-byte upstream. The MCP transport between agent and MCP server is HTTP+SSE, the same protocol the agent exposes to its own clients, so the dataflow is symmetric.

## Component breakdown

**`src/sec_recon_agent/mcp_server/`** — owns the FastMCP instance, the typed I/O models for tools, the shared NVD client (rate limiter, retry, header builder), the cross-cutting `security.py` primitive, and the seven tool modules (`cve.py`, `cve_search.py`, `exploits.py`, `kev.py`, `epss.py`, `nmap.py`, `attack.py`). `errors.py` defines the exception hierarchy; `nvd_client.py` centralizes the sliding-window rate limiter so `cve_lookup` and the `cve_search` seed pipeline share one rate budget.

**`src/sec_recon_agent/agent/`** — the Pydantic AI agent definition (`triage.py`), its output schema (`schema.py`: `TriageReport`, `CVEReference`, `Severity`, `Confidence`), and the system prompt (`prompts.py`, in its own module so it can be versioned and reviewed independently from the agent wiring). The agent uses `MCPToolset` (Pydantic AI's current MCP API; replaces the deprecated `MCPServerSSE`) to discover and call tools.

**`src/sec_recon_agent/api/`** — the FastAPI surface (`stream.py`): `POST /v1/triage` streaming SSE events, `GET /v1/health`. The `main()` entry point also runs `setup_tracing()` and `export_anthropic_api_key_to_env()` exactly once at process startup.

**`src/sec_recon_agent/config.py`** — a single `Settings` instance loaded from `.env` via pydantic-settings. API keys are `SecretStr | None` so logs and tracebacks do not leak them. The Anthropic key is pushed to `os.environ` exactly once at startup (Pydantic AI's Anthropic provider reads from the env), not per request.

**`src/sec_recon_agent/observability.py`** — `setup_tracing(service_name)` is idempotent and configures the OTel tracer provider. Default exporter is `ConsoleSpanExporter`; `OTLPSpanExporter` is lazy-imported only if `OTEL_EXPORTER_OTLP_ENDPOINT` is set. `HTTPXClientInstrumentor` is enabled here so every outbound NVD / GitHub / ExploitDB call gets a span (and propagates W3C `traceparent` for cross-process tracing).

**`frontend/`** — a Next.js 15 App Router application on React 19. The browser is the primary interface; `/api/triage` proxies the SSE stream from the FastAPI backend without ever exposing CORS. See [`docs/frontend.md`](frontend.md) for the component map.

## Decisions log

**Why the Anthropic official `mcp` SDK over FastMCP-community.** Both work. The official SDK is canonical; using it signals respect for the spec to a reviewer who cares. Switching cost later is trivial because the tool surface is decorator-driven and the implementation is portable.

**Why HTTP+SSE transport over stdio.** Stdio is the tutorial default. HTTP+SSE is what real deployments use because the MCP server and its clients run on different hosts. Choosing HTTP+SSE forces the codebase to confront process boundaries, port binding, and connection lifecycle from day one, which is what a reviewer wants to see.

**Why ChromaDB's `DefaultEmbeddingFunction` (ONNX MiniLM-L6) over sentence-transformers.** Started with sentence-transformers because it is the recognizable name. Switched after `transformers 5.x` (released October 2026) broke compatibility with the all-MiniLM-L6-v2 model card. The ONNX path uses the same model weights, same tokenizer, same pooling, same normalization. Functionally identical embeddings; the only loss is the easy upgrade path to larger SBERT models or a CrossEncoder reranker, both of which can be re-introduced when the project moves past "demo" scope. Net savings: ~700 MB of torch+transformers off the install footprint.

**Why a separate `seed_index` script over indexing on first query.** Indexing 1,000+ CVE descriptions is a one-shot ~30s operation. Doing it lazily on the first user query would push that latency into the user-facing path. Running it as `uv run sec-recon-seed` keeps the runtime tool's latency predictable and surfaces NVD outages at indexing time, not at triage time.

**Why structured output (`TriageReport` Pydantic model) over free-text.** The system prompt could ask for a markdown summary and a downstream parser could pull fields out of it. That is the fragile pattern. Pydantic-typed output enforces the contract at the model boundary: the LLM cannot return a "report" without a CVSS severity field. Combined with `mypy --strict` upstream, the call site can rely on the schema instead of doing defensive `getattr` everywhere.

**Why two separate uvicorn processes over a monolith.** Single-process is faster to start and slightly cheaper. The two-process layout exists because (a) the MCP server is a reusable service that any MCP client can talk to (Claude Desktop, a different agent, a CLI), not just our agent, and (b) a fault in one process does not crash the other. The cost is one extra TCP binding and one extra `uv run` command at startup. For a portfolio demo, the architectural clarity wins.

**Why Next.js 15 + React 19 for the frontend over a single-page Vite app.** The Etiqa job ad explicitly lists "React / TypeScript" as nice-to-have; using Next.js makes the same React/TS stack while adding a server-side `/api/triage` route that can proxy the SSE stream without opening CORS on the backend. Next.js standalone build mode produces a Docker image ~150 MB without a separate nginx tier. Vercel AI SDK was evaluated and dropped: it targets provider-specific completion APIs and would not add value over a thin SSE client wrapped around `fetch`.

**Why Tailwind + shadcn-style primitives over a component library (Mantine, MUI, Chakra).** shadcn's "copy not import" model keeps the dependency surface small (only Radix primitives and `class-variance-authority`) and lets the Catppuccin palette drop in via CSS variables without overriding library defaults. A heavy library would lock the design language and add ~1 MB of JS bundle for components we use sparingly. Framer-motion was tried and dropped because its 11.x TypeScript types fight TS 5.7 strict mode on `motion.button + onClick` and the polish gain did not justify the type-system contortions; entry animations now use Tailwind keyframes.

**Why the browser talks only to `/api/triage` and not to FastAPI directly.** Two reasons. (1) No CORS opened on the agent API; the backend stays single-tenant by design (no auth, no per-client rate limit). (2) The proxy is the right place to add future cross-cutting concerns (rate limit per IP, request logging for audit, auth handshake) without changing FastAPI itself. Today the proxy is a 20-line passthrough.

**Why CISA KEV as a first-class tool, not a flag inside `cve_lookup`.** KEV membership is a different kind of signal from anything NVD provides: it is the federal-government list of CVEs *known to be actively exploited in the wild* (Binding Operational Directive 22-01). Surfacing it as `kev_check` keeps the tool surface composable (the agent can call it on a CVE that came from semantic search without round-tripping through `cve_lookup` first) and isolates the catalog-refresh and host-locked-download concerns from the NVD client. The catalog is small (~2 MB) and updated daily; a 24h disk cache + in-memory index makes per-CVE lookups O(1) after the first hit.

**Why EPSS alongside KEV (not instead of it).** KEV answers "is this CVE known to be exploited right now?". EPSS answers "how likely is this CVE to be exploited in the next 30 days?". The two signals are orthogonal: a CVE can be on KEV without a high EPSS score (because EPSS is a forward-looking probabilistic model and KEV reflects observed exploitation), and a CVE can have a very high EPSS score without being on KEV (the model is calibrated against post-publication exploitation, so emerging high-risk CVEs surface in EPSS first). Both feed `recommended_action` so the agent can prioritize beyond CVSS, which has long been known to over-weight theoretical impact relative to real-world exploitation likelihood. EPSS is fetched per-CVE (no bulk pre-fetch) because the API is rate-friendly and the access pattern is sparse — there is no payoff in pre-loading the full dataset.

**Why the eval suite hits the live HTTP API, not the agent in-process.** A pytest fixture that built the agent in-process would still need a running MCP server (the tool surface is the system under test, not just the prompt) — coupling the test setup to docker-compose. Driving `POST /v1/triage` over real HTTP+SSE instead has two upsides: (1) the suite exercises the wire-level frame layout the frontend depends on, so a regression in the SSE byte format fails the eval as well as any UI smoke; (2) the same harness can be pointed at a remote staging environment with `--api-url` without code changes. The trade-off is the requirement to `make up` first; for a deliberately on-demand suite that is acceptable. Soft assertions (severity within +-1 step, >= 50% CVE recall) absorb the irreducible LLM non-determinism without hand-tuning the prompt to a single golden output.

**Why a per-CVE prioritization heuristic in the system prompt, not a deterministic post-processor.** The agent already calls KEV and EPSS as tools; encoding the priority order (KEV > ransomware > EPSS >= 0.5 > CVSS) in the system prompt rather than in `recommended_action`-generation code keeps the agent the single source of truth for the natural-language remediation guidance. A deterministic post-processor would have to either duplicate the prose generation or post-edit the agent's output. The trade-off is that the heuristic depends on the LLM following instructions; the structured `TriageReport.cves[].in_kev_catalog` field stays the contract for any downstream automation that needs deterministic behavior.

## Threat model

The agent consumes untrusted content from at least four sources. Treating each as adversarial.

### Inputs and trust boundaries

| Input | Source | Trust | Notes |
|---|---|---|---|
| User query string | API client | untrusted | length-capped at 4000 chars by `TriageRequest`; further truncated at the semantic search tool boundary |
| CVE ID parameter | API client (via LLM tool call) | untrusted but regex-constrained | `CveIdStr = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]` enforced at both Pydantic and MCP-schema layers |
| NVD CVE descriptions | NVD API | untrusted (vendor-authored) | wrapped with `<UNTRUSTED_CONTENT>` markers before reaching the LLM |
| Nmap XML scan output | API client (via LLM tool call) | untrusted | parsed exclusively with `defusedxml`; XXE / external entity refusal verified by a fixture test |
| ExploitDB CSV manifest | GitLab raw URL | semi-trusted | downloaded with size cap (20 MB) and post-redirect host validation against `gitlab.com` |
| GitHub Code Search results | GitHub API | semi-trusted | `html_url` fields only; no raw code content reaches the LLM |
| LLM model output | Anthropic API | trusted contract / adversarial content | constrained by Pydantic output schema; field validators reject malformed values |

### Controls applied

The findings below come from an independent code review; each one corresponds to a real change in `src/`.

**Prompt injection via tool output (HIGH).** Every free-text vendor-authored string returned by a tool is wrapped at the code boundary with `<UNTRUSTED_CONTENT>...</UNTRUSTED_CONTENT>` markers (see `mcp_server/security.py`). The system prompt names these markers explicitly and instructs the LLM to treat their content as data, not as instructions. This is the hard counterpart to the soft prompt-side guardrail. Applied to: `CVEDetail.description`, `CVECandidate.summary`, `NmapPort.product`, `NmapPort.version`.

Structured fields (CVE IDs, CVSS scores, severities, CWE IDs, CPE strings, URLs, hostnames) are not fenced because their Pydantic validators reject anything that does not match the expected shape. A malformed value cannot reach the LLM at all.

**XXE / XML attacks (HIGH).** `nmap_parse_xml` uses `defusedxml.ElementTree`. The combined `(ET.ParseError, DefusedXmlException)` catch surfaces any DTD, external entity, or entity-expansion attempt as a typed `MalformedNmapXmlError`. A test fixture fires a classic XXE payload at the parser and asserts it raises rather than dereferencing the entity.

**Resource exhaustion (HIGH).** Three bounds:
- ExploitDB CSV download streams in 8 KB chunks and aborts at 20 MB (current real size: ~5 MB).
- Seed-script pagination capped at 25 pages per severity (50,000 CVEs maximum per severity), so a malformed NVD `totalResults` cannot drive an unbounded fetch loop.
- `NmapHost.hostnames` and `NmapHost.ports` capped at 50 and 200 respectively, enforced by both Pydantic `max_length` and a parser-level slice.

**Rate limiter correctness (CRITICAL fixed).** The NVD client uses a sliding-window limiter (deque of recent timestamps, drop entries older than 30 s, append new). The initial implementation slept inside the asyncio lock, which serialized every concurrent NVD call behind the first one's sleep. Fixed by holding the lock only for the timestamp-check phase and sleeping outside it.

**Singleton init concurrency (HIGH fixed).** The ChromaDB collection and the ExploitDB index are module-level singletons. Both initializations are now protected by double-checked locking (`threading.Lock` for the sync ChromaDB path, `asyncio.Lock` for the async index path). Two coroutines arriving at the first call no longer race to open a `PersistentClient` on the same SQLite directory.

**SSRF on outbound HTTP (MEDIUM).** Only the ExploitDB client has `follow_redirects=True` and it now validates the post-redirect host against `gitlab.com` (or any subdomain). The GitHub client does not follow redirects. The NVD client does not follow redirects.

**Secret management (MEDIUM).** API keys (`ANTHROPIC_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`) live in `Settings` as `pydantic.SecretStr | None`. The Anthropic key is pushed to `os.environ` exactly once at process startup (in `api/stream.py::main`, via `export_anthropic_api_key_to_env`), not per request, so the plaintext lives in process state for the latest moment possible. Tracebacks and structured-log calls never reference the SecretStr directly.

**Error message leakage (HIGH fixed).** SSE `error` events used to echo `str(exc)` verbatim, leaking internal parameters (`params` dicts, filesystem paths, library internals). Replaced with an explicit allowlist (`_SAFE_TO_ECHO`) of exception types whose message is safe to surface. Everything else returns `"Internal error; check server logs."`. The exception class name is still echoed since it is a useful client-side discriminator without leaking content.

**Logging discipline.** All logs go through `structlog`. CVE IDs and tool names are logged (low-sensitivity, useful for debug). User query strings are NOT logged at info level. Secrets and API responses are never logged. `NvdRateLimitError` no longer includes raw `params` in its message.

**Untrusted-content fencing test invariant.** Unit tests assert that fenced fields start and end with the marker tokens. Renaming or removing the markers will fail tests, surfacing the change before it ships.

### Defended invariants (property and adversarial tests)

`tests/property/` carries two complementary suites that pin the contract of the security-critical primitives. Property tests state invariants over arbitrary inputs (via Hypothesis); adversarial tests fire hand-curated hostile payloads at the tool layer.

| Invariant | Where | What it pins |
|---|---|---|
| `fence_untrusted(t)` wraps any non-empty `t` with both markers | `test_invariants.py` | the boundary contract cannot drift silently |
| The original text is preserved verbatim inside the fence | `test_invariants.py` | we sanitize the BOUNDARY, not the CONTENT (the LLM still needs the data) |
| `fence_untrusted(None) == None` and `fence_untrusted("") == ""` | `test_invariants.py` | empty fencing inflates token cost without changing semantics |
| Any CVE ID matching `^CVE-\d{4}-\d{4,}$` passes Pydantic | `test_invariants.py` | the regex is canonical at every boundary |
| Any string not matching the regex is rejected | `test_invariants.py` | injection in URL params blocked at the model layer |
| `NmapPort.portid` in `[1, 65535]`, `cvss_v3_score` in `[0, 10]`, `similarity` in `[0, 1]` | `test_invariants.py` | the structured-output contract holds for any Hypothesis-generated value |

| Attack class | Tests in `test_adversarial.py` |
|---|---|
| Prompt injection in NVD descriptions | 8 payloads (system-prompt extraction, role override, jinja-like, log4shell `${jndi:...}`, fake-fence markers in the payload) — all reach the agent only inside the real outer fence, payload preserved verbatim |
| Marker forgery (payload contains the markers themselves) | 1 test — the wrapper applies once around the whole text; inner occurrences are just characters |
| XXE / XML attack variants | 4 payloads (classic file read, external DTD reference, parameter entity, billion laughs) — all raise `MalformedNmapXmlError`. Parser now uses `forbid_dtd=True` (tighter than defusedxml's default) so DTD declarations are refused, removing the entity attack surface entirely |
| Malformed CVE IDs | 14 payloads (lowercase, padding, newlines, null bytes, path traversal, SQL/URL injection attempts) — all rejected by the Pydantic Annotated regex before any HTTP call |
| Homoglyphs / Unicode tricks | 5 payloads (Cyrillic С, zero-width space, RTL override, NBSP, full-width hyphens) — rejected by the ASCII-only regex |
| Resource exhaustion | ExploitDB CSV above 20 MB cap aborts download; Nmap XML with 500 hostnames / 1000 ports per host capped at 50 / 200 in the returned model |

Counts: 11 property tests, 32 adversarial parametrizations. Together they replace what a hand-written example suite would only sample.

### Residual risks and accepted limits

These are real concerns that this codebase does not address. A reviewer should know what is deliberately out of scope.

- **No API authentication.** `POST /v1/triage` is open. Adding API-key or OAuth is straightforward (FastAPI middleware) but not in scope for a single-tenant demo. Operationally: do not expose the demo to the public internet.
- **No per-client rate limit on the API.** The NVD-side rate limiter protects the upstream, not the agent. A malicious client can drive request volume that exhausts the LLM API budget. Standard mitigations: SlowAPI / nginx limit_req. Out of scope.
- **Prompt injection is mitigated, not solved.** Marker-fencing is a strong signal but not a cryptographic boundary. A sufficiently determined injection embedded in NVD data could still degrade the agent's output quality (not exfiltrate secrets, since the agent has no out-of-band tools). The mitigation is layered: marker fencing + system prompt guardrail + structured output schema. The LLM cannot return free text outside the schema.
- **ChromaDB persistence is on local disk.** No replication, no backup. Acceptable for demo; replace with a managed vector store (or just SQLite WAL replication) for production.
- **No request log / audit trail.** The agent's reasoning chain is in the response body, not persisted. For compliance scenarios this would need to land in an append-only log.
- **No model output sandboxing.** The `TriageReport.recommended_action` field is free text. A vulnerability in a downstream renderer that auto-executes the recommendation would be exploitable. The schema constrains the shape, not the content.

## Testing strategy

Unit + contract tests, no integration suite. Specifically:

- **Tool I/O contracts.** Every tool has tests verifying its Pydantic output shape against mocked HTTP via `respx`. Failure modes (NVD 404, malformed payload, NVD 5xx retry exhaustion, XXE refusal, oversized download) are covered.
- **Cross-cutting primitives.** `fence_untrusted` has its own unit tests. The marker invariant is asserted in every tool that applies fencing.
- **Agent wiring.** Smoke tests verify the agent constructs, the system prompt declares all seven tool names verbatim (drift detector), and the untrusted-content guardrail is present.
- **API surface.** FastAPI `TestClient` covers health, request validation (missing/empty query), the SSE event sequence (`started` → `node` → `final`), and the error-event sanitization invariant.

Marked `@pytest.mark.slow` (3 tests): full seed + semantic search round-trip with real ChromaDB and the ONNX embedder. ~30 s first session run (ONNX model cache), <1 s subsequent.

End-to-end runs against a real LLM are not in the unit-test fast lane. They live in `src/sec_recon_agent/eval/` and are driven by the `sec-recon-eval` CLI (also exposed as `make eval`). The suite ships a curated golden set of 10 queries (named CVEs, fuzzy descriptions, degraded inputs) and uses soft assertions on `TriageReport`: severity within +-1 step, expected CVE recall >= 0.5, KEV / ransomware flags honored when expected. The runner speaks HTTP+SSE against the live `/v1/triage`, so it also exercises the wire-level contract the frontend depends on. Out-of-CI by design (requires a live stack and bills the LLM).

## Operational notes

The primary run path is Docker Compose:

```bash
cp .env.example .env       # set ANTHROPIC_API_KEY
make build                 # backend + frontend, multi-stage
make seed                  # one-shot: populate ChromaDB on the shared volume
make up                    # mcp-server + agent-api + frontend
make ui                    # open http://localhost:3000
make obs-up                # variant: add Jaeger sidecar; OTEL endpoint auto-wired
```

For local development without containers:

```bash
uv sync
uv run sec-recon-seed
uv run sec-recon-mcp     # terminal 1
uv run sec-recon-api     # terminal 2
cd frontend && npm install --legacy-peer-deps && npm run dev   # terminal 3
```

Environment variables of note (full list in `.env.example`):

| Variable | Required | Effect |
|---|---|---|
| `ANTHROPIC_API_KEY` | yes | Pydantic AI's Anthropic provider reads this from env |
| `NVD_API_KEY` | no | Raises NVD rate limit from 5 to 50 req / 30 s |
| `GITHUB_TOKEN` | no | Enables GitHub Code Search in `exploit_check`; without it the GitHub side returns `[]` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | Switch from console exporter to OTLP/HTTP (e.g. `http://jaeger:4318`) |
| `LLM_MODEL` | no | Default `claude-haiku-4-5-20251001` (cheapest tier, sufficient for tool calling + structured output). Override to `claude-sonnet-4-6` for richer prose or `claude-opus-4-7` for strongest reasoning at higher cost. |
| `CHROMA_PERSIST_DIR` | no | Default `./data/cve_index`; on disk |
| `NVD_RATE_LIMIT_PER_30S` | no | Override the local sliding-window cap (default 5) |

Environment variables of note:
- `ANTHROPIC_API_KEY` — required for the agent to call the model.
- `NVD_API_KEY` — optional; raises NVD rate limit from 5 req/30s to 50.
- `GITHUB_TOKEN` — optional; without it, GitHub PoC search in `exploit_check` degrades to `[]`.
- `CHROMA_PERSIST_DIR` — ChromaDB on-disk index location; defaults to `./data/cve_index`.

### Observability

OpenTelemetry tracing is enabled in both processes. `setup_tracing(service_name)` runs once at startup (see `src/sec_recon_agent/observability.py`), instruments httpx auto-magically (so every NVD / GitHub / ExploitDB call gets a span), and instruments the FastAPI app via `FastAPIInstrumentor.instrument_app()`. Each MCP tool emits one manual span around its body with attributes like `tool.name`, `cve.id`, `tool.success`, `cve.cvss_v3_score`, `hosts.count`, `query.length`.

Trace propagation between the two processes flows through W3C `traceparent` headers on the HTTP+SSE transport. The httpx instrumentation injects the header; FastAPI/Starlette accept it.

Default exporter is `ConsoleSpanExporter` (spans printed to stdout, zero infrastructure). Setting `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://jaeger:4318`) switches to OTLP/HTTP. The compose profile `observability` brings up a Jaeger sidecar (`jaegertracing/all-in-one`, UI on `:16686`, OTLP HTTP receiver on `:4318`) and the `obs-up` Makefile target wires the env var automatically.

What is **not** in span attributes (privacy / security):
- User query text (potentially adversarial; only `query.length` is recorded)
- API keys (`ANTHROPIC_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`)
- NVD descriptions or any vendor-authored free text (untrusted)
- LLM responses

Two tests in `tests/test_observability.py` enforce these invariants by firing a canary query / payload and asserting no span attribute contains the canary substring.

`structlog` continues to write structured logs to stdout in parallel; log lines are not OTel-correlated yet (that is a follow-on enrichment).
