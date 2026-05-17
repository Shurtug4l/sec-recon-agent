# sec-recon-agent design

A short engineering brief for the next reviewer. Covers: what the system is, how it is wired, the non-trivial design choices and why other options were rejected, the threat model with the controls actually applied in code, and what is deliberately out of scope.

## What this is

A security triage agent. Given a CVE ID, a product description, or Nmap XML output, it returns a typed `TriageReport` (severity, exploit availability, recommended action, full reasoning chain) by calling four MCP tools and synthesizing the result with an LLM.

Built as a portfolio piece, not a production deployment. The design choices are documented here precisely because a reviewer's first question is usually "why this way and not the obvious other way."

## System architecture

```
client -- HTTP+SSE --> agent API (FastAPI, :8000)
                            |
                            | Pydantic AI tool calls
                            v
                       MCP client -- HTTP+SSE --> MCP server (FastMCP, :8001)
                                                       |
                                                       +-- NVD CVE 2.0  (cve_lookup)
                                                       +-- ChromaDB      (cve_semantic_search)
                                                       +-- ExploitDB CSV (exploit_check)
                                                       +-- GitHub Search (exploit_check)
                                                       +-- defusedxml    (nmap_parse_xml)
```

Two processes, deliberately. The agent and the MCP server live in separate uvicorn instances bound to different ports. Either can restart without taking the other down. The MCP transport between them is HTTP+SSE, the same protocol the agent exposes to its own clients, so the dataflow is symmetric.

## Component breakdown

**`mcp_server/`** — owns the FastMCP instance, the typed I/O models for tools, the shared NVD client (rate limiter, retry, header builder), the cross-cutting `security.py` primitive, and the four tool modules.

**`agent/`** — the Pydantic AI agent definition (`triage.py`), its output schema (`schema.py`: `TriageReport`, `CVEReference`, `Severity`, `Confidence`), and the system prompt (`prompts.py`, in its own module so it can be versioned and reviewed independently from the agent wiring).

**`api/`** — the FastAPI surface (`stream.py`): `POST /v1/triage` streaming SSE events, `GET /v1/health`.

**`config.py`** — a single `Settings` instance loaded from `.env` via pydantic-settings. API keys are `SecretStr | None` so logs and tracebacks do not leak them.

## Decisions log

**Why the Anthropic official `mcp` SDK over FastMCP-community.** Both work. The official SDK is canonical; using it signals respect for the spec to a reviewer who cares. Switching cost later is trivial because the tool surface is decorator-driven and the implementation is portable.

**Why HTTP+SSE transport over stdio.** Stdio is the tutorial default. HTTP+SSE is what real deployments use because the MCP server and its clients run on different hosts. Choosing HTTP+SSE forces the codebase to confront process boundaries, port binding, and connection lifecycle from day one, which is what a reviewer wants to see.

**Why ChromaDB's `DefaultEmbeddingFunction` (ONNX MiniLM-L6) over sentence-transformers.** Started with sentence-transformers because it is the recognizable name. Switched after `transformers 5.x` (released October 2026) broke compatibility with the all-MiniLM-L6-v2 model card. The ONNX path uses the same model weights, same tokenizer, same pooling, same normalization. Functionally identical embeddings; the only loss is the easy upgrade path to larger SBERT models or a CrossEncoder reranker, both of which can be re-introduced when the project moves past "demo" scope. Net savings: ~700 MB of torch+transformers off the install footprint.

**Why a separate `seed_index` script over indexing on first query.** Indexing 1,000+ CVE descriptions is a one-shot ~30s operation. Doing it lazily on the first user query would push that latency into the user-facing path. Running it as `uv run sec-recon-seed` keeps the runtime tool's latency predictable and surfaces NVD outages at indexing time, not at triage time.

**Why structured output (`TriageReport` Pydantic model) over free-text.** The system prompt could ask for a markdown summary and a downstream parser could pull fields out of it. That is the fragile pattern. Pydantic-typed output enforces the contract at the model boundary: the LLM cannot return a "report" without a CVSS severity field. Combined with `mypy --strict` upstream, the call site can rely on the schema instead of doing defensive `getattr` everywhere.

**Why two separate uvicorn processes over a monolith.** Single-process is faster to start and slightly cheaper. The two-process layout exists because (a) the MCP server is a reusable service that any MCP client can talk to (Claude Desktop, a different agent, a CLI), not just our agent, and (b) a fault in one process does not crash the other. The cost is one extra TCP binding and one extra `uv run` command at startup. For a portfolio demo, the architectural clarity wins.

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
- **Agent wiring.** Smoke tests verify the agent constructs, the system prompt declares all four tool names verbatim (drift detector), and the untrusted-content guardrail is present.
- **API surface.** FastAPI `TestClient` covers health, request validation (missing/empty query), the SSE event sequence (`started` → `node` → `final`), and the error-event sanitization invariant.

Marked `@pytest.mark.slow` (3 tests): full seed + semantic search round-trip with real ChromaDB and the ONNX embedder. ~30 s first session run (ONNX model cache), <1 s subsequent.

End-to-end runs against a real LLM are deliberately not in the test suite. They are intended as manual smoke checks documented in `examples/`.

## Operational notes

```bash
uv sync
cp .env.example .env  # set ANTHROPIC_API_KEY at minimum

uv run sec-recon-seed     # one-shot: populate ChromaDB
uv run sec-recon-mcp      # terminal 1: MCP server on :8001
uv run sec-recon-api      # terminal 2: agent API on :8000

curl -N -X POST http://localhost:8000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"query": "Apache 2.4.49 on port 80. Risk?"}'
```

Environment variables of note:
- `ANTHROPIC_API_KEY` — required for the agent to call the model.
- `NVD_API_KEY` — optional; raises NVD rate limit from 5 req/30s to 50.
- `GITHUB_TOKEN` — optional; without it, GitHub PoC search in `exploit_check` degrades to `[]`.
- `CHROMA_PERSIST_DIR` — ChromaDB on-disk index location; defaults to `./data/cve_index`.

Observability hooks intentionally absent: no Prometheus exporter, no OpenTelemetry. `structlog` writes JSON to stdout, which is enough for a container-deployed setup to scrape from the runtime logs.
