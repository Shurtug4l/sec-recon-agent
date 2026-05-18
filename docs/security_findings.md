# Security findings — open and accepted

The Trivy workflow uploads a SARIF report to the GitHub Security tab on every successful image build and on a weekly schedule. The findings listed below are the **currently open** alerts on `main`; each one has been triaged with a documented decision.

This document covers two sources:
1. **Supply-chain findings** from Trivy / npm-audit / pip-audit (dependencies we ship in containers).
2. **Internal audit findings** from periodic multi-agent review of our own code (MCP tool surface, agent flow, governance posture).

**Posture**: open findings stay open. Dismissing a CVE that we technically own (it ships inside our container) without a fix would be optics, not security. Documenting them publicly is the more honest signal: a reviewer can see the analysis, agree or disagree, and we can revisit when an upstream fix lands. The same posture applies to internal findings: we list them with the current mitigation and the planned fix path, rather than hiding them until the fix lands.

**Refresh cadence**: Trivy weekly Monday cron via `.github/workflows/ci-docker-scan.yml`. Internal audit is run on-demand (last: 2026-05-18) by spawning specialized review subagents in parallel against the code surface.

---

## Triage matrix

### Supply chain (Trivy / npm-audit / pip-audit)

| Severity | CVE / GHSA | Package | Path | Disposition | Reason |
|---|---|---|---|---|---|
| HIGH | GHSA picomatch ReDoS | picomatch | `frontend` build chain | accept | build-time tooling, no attacker-controlled input |
| MEDIUM | postcss XSS via stringify | postcss | `frontend` build chain | accept | build-time CSS toolchain, output is static |
| MEDIUM | picomatch POSIX bracket | picomatch | `frontend` build chain | accept | build-time tooling |
| MEDIUM | ip-address parsing | ip-address | `frontend` transitive | accept | build-time tooling |
| MEDIUM | brace-expansion DoS via zero step | brace-expansion | `frontend` ESLint config parsing | accept | build-time, patterns from .eslintignore |
| LOW (x3) | rand unsoundness with custom logger | rand (Rust) | backend image ChromaDB native bridge | accept | we do not use rand with a custom logger |

### Internal audit (multi-agent review 2026-05-18)

| Severity | Finding | Surface | Disposition | Current mitigation |
|---|---|---|---|---|
| P0 | MCP transport has no auth layer | `mcp_server/server.py` (FastMCP SSE) | open, tracked | port `:8001` not in compose `ports:` map, reachable only on docker-compose internal network |
| P1 | `nmap_parse_xml` has no size cap on input | `mcp_server/tools/nmap.py` | open, tracked | defusedxml `forbid_dtd=True` blocks XXE; per-host caps in place; per-document host count unbounded |
| P1 | `attack_mapping` `cwe_ids` list is unbounded | `mcp_server/tools/attack.py` | open, tracked | span attribute truncation caps log size but not iteration cost |
| P1 | NVD reference URLs not marked untrusted in output | `mcp_server/tools/cve.py`, `tools/patch.py` | open, tracked (latent) | Pydantic `HttpUrl` validation; no downstream tool currently fetches reference URLs |
| P1 | SSE transport is legacy (Streamable HTTP is the post-2025-06-18 recommendation) | `mcp_server/server.py` | open, tracked (deprecation watch) | SDK still supports SSE; no breaking change forced yet |
| P1 | `epss_score` silently returns empty score on upstream CVE-id mismatch | `mcp_server/tools/epss.py` | open, tracked | `log.warning` is emitted; downstream agent has no signal |
| P1 | `path.write_bytes` blocks the event loop during 5-20MB cache refresh | `mcp_server/tools/exploits.py`, `tools/kev.py` | open, tracked | refresh runs at most once per cache TTL (7d Exploit-DB, 24h KEV) |
| P1 | `asyncio.gather` paired with bare `create_task` leaves orphaned tasks on failure | `mcp_server/tools/exploits.py`, `tools/kev.py` | open, tracked | `AsyncClient` context exit cancels in-flight tasks; window is narrow |

---

## Detailed triage

### Frontend npm findings (5)

All five findings live in `frontend/node_modules/` and reach the image because the Next.js build needs them at compile time. None of them are loaded at runtime by the user-facing Next.js server.

**Dependency chain** (from `npm ls`):

- **picomatch** → transitive of `eslint-import-resolver-typescript` → `tinyglobby` → `fdir` and of `tailwindcss` → `chokidar` / `micromatch`. Used during `next build` to walk source files; never at request time.
- **postcss** → transitive of `next` (own pinned version), `tailwindcss`, `autoprefixer`, `postcss-import`. Runs once at build to produce static CSS. The cited XSS (`</style>` injection in stringify output) requires attacker-controlled CSS input, which we do not have.
- **ip-address** → transitive of one of the test / lint chains. Not invoked from any runtime code path.
- **brace-expansion** → transitive of `minimatch` → ESLint and TypeScript-ESLint config-file parsing. The DoS requires a pattern like `{0..N..0}` with a zero step; our patterns come from `.eslintignore` and `tsconfig.json` (developer-controlled).

**Why we cannot bump them**: `npm audit fix --force` would downgrade `next` to 9.3.3 (the only Next version with a fixed transitive `postcss`) — a breaking change with no benefit. The same forced fix does not touch the picomatch / brace-expansion / ip-address chain because their transitive parents themselves have not bumped.

**What would change the disposition**:

- Next.js publishes a 15.x patch that bumps the transitive postcss.
- The Next.js / Tailwind / ESLint chain refreshes picomatch to a fixed version.
- We migrate the frontend off Next 15 (currently out of scope; tracked separately in the Dependabot ignore list for `next` major bumps).

### Backend Rust findings (3 × rand LOW)

Three identical findings in `app/.../bridge/Cargo.lock` inside the backend image (`python:3.14-slim` + ChromaDB Python wheel). The vulnerability is `rand::rng()` being unsound when used with a custom logger — a narrow API contract violation in the Rust `rand` crate.

The Cargo.lock comes from a pre-compiled native bridge bundled inside ChromaDB's wheel (likely the ONNX runtime bridge that backs the local embedder). We do not call `rand::rng()` directly, and the wheel does not expose a logger configuration knob to its Python callers.

**Why we cannot bump it**: the dependency tree is frozen at ChromaDB build time and shipped as a binary wheel. Bumping requires ChromaDB to publish a new wheel built against a newer `rand`, which is upstream's responsibility.

**What would change the disposition**: a new ChromaDB release that pins `rand >= <fixed-version>`. Dependabot will surface the Python-side bump when it lands.

---

## Detailed triage — internal audit findings

These come from the periodic multi-agent audit (last run 2026-05-18). Unlike supply-chain findings (which we accept and document because the fix sits upstream), internal findings are ours to fix and are tracked toward concrete PRs.

### P0 — MCP transport has no auth layer

`mcp_server/server.py` starts FastMCP with the SSE transport on `:8001` without any bearer / API-key / token check. The agent-api process enforces opt-in API-key auth (`api/stream.py`), but the MCP server — which is the more powerful surface (direct tool access, no agent guardrails) — enforces none.

**Current mitigation**: the `docker-compose.yml` does NOT publish `:8001` to the host. The port is reachable only via the compose-internal network, where the only client is `agent-api`. Anyone who re-runs the container with `-p 8001:8001` or deploys outside the compose perimeter loses this mitigation.

**Planned fix**: FastMCP-level bearer middleware accepting a shared secret from env, opt-in (default off to keep laptop dev frictionless). The CHANGELOG entry for the fixing PR will explicitly call out this mitigation gap so users on older images know to re-check their network exposure.

### P1 — Unbounded inputs on `nmap_parse_xml` and `attack_mapping`

`nmap_parse_xml` accepts `xml_content: str` with no upper bound; while `defusedxml(forbid_dtd=True)` neutralizes XXE and entity expansion, a multi-hundred-MB well-formed `<port>` tree is fully parsed in-process. Per-host caps are present, per-document host count is not.

`attack_mapping` accepts `cwe_ids: list[str]` with no length limit; the existing `cwe[:10]` truncation only affects the span attribute, not the iteration cost.

**Current mitigation**: both tools are reachable only by the agent (single trusted client), and the rate-limit middleware on `agent-api` caps request frequency from the client side. Direct MCP-transport callers would bypass that, see the P0 above for the related transport-auth gap.

**Planned fix**: `Annotated[str, Field(max_length=20_000_000)]` on `nmap_parse_xml.xml_content` + `findall("host")[:1000]` for per-document iteration; `Annotated[list[str], Field(max_length=200)]` with per-item `Field(max_length=40)` on `attack_mapping.cwe_ids`. Contract tests pinning the new caps.

### P1 — NVD reference URLs reach the agent without an "untrusted" marker (latent)

`tools/cve.py` and `tools/patch.py` return URLs extracted from NVD `references` as typed `HttpUrl` fields without an explicit "treat as data, not as instruction" marker in the output model. Today the agent prompt and the absence of a URL-fetching downstream tool both keep this dormant. If any future tool ever follows a reference URL, this becomes an SSRF-by-reference vector.

**Current mitigation**: agent system prompt treats tool output as data; no MCP tool currently dereferences a reference URL.

**Planned fix**: add a `references_untrusted: bool = True` flag to the result models and document the agent contract in the tool docstring (which is LLM-visible).

### P1 — SSE transport is on the legacy side of the MCP spec line

The MCP spec revision dated 2025-06-18 introduces Streamable HTTP as the recommended bidirectional surface; SSE is marked legacy in several SDK releases. The server still uses SSE in `mcp_server/server.py`.

**Current mitigation**: the SDK pin used here still supports SSE; no breaking change forced yet.

**Planned fix**: migrate to `transport="streamable-http"` once the SDK floor allows. Deferred until the SDK explicitly deprecates, no rush.

### P1 — `epss_score` silent fallback on upstream CVE-id mismatch

`tools/epss.py` returns an empty `EpssScore(cve_id=cve_id)` after a `log.warning` when the FIRST.org response carries a different CVE-id than the one queried. The agent has no way to distinguish "CVE not in EPSS" (legitimate empty result) from "EPSS API misbehaved" (system fault). The triage layer may treat a misbehavior as a "zero exploit probability" signal, which is wrong.

**Current mitigation**: `log.warning` emitted to structured logs; operators reviewing logs can detect the pattern.

**Planned fix**: raise a typed `MalformedEpssPayloadError`, surface as a tool-level error to the agent which can mark the triage report appropriately.

### P1 — Event-loop blocking on cache refresh write

`tools/exploits.py` and `tools/kev.py` call sync `path.write_bytes(bytes(buffer))` on 5-20MB blobs inside their async cache-refresh paths. Each refresh momentarily blocks the asyncio event loop.

**Current mitigation**: cache refresh runs at most once per TTL (7d Exploit-DB index, 24h KEV catalog), so the blocking window is rare in practice.

**Planned fix**: `await asyncio.to_thread(path.write_bytes, bytes(buffer))`.

### P1 — Orphaned tasks on `asyncio.gather` failure

`tools/exploits.py` and `tools/kev.py` pair `asyncio.create_task(...)` with `asyncio.gather`. If one task raises, the other is not cancelled and continues running until the `AsyncClient` context exits.

**Current mitigation**: the `AsyncClient` context exit cancels in-flight tasks via httpx connection teardown; the leak window is narrow.

**Planned fix**: use `asyncio.gather(coro_a, coro_b)` directly (gather already manages the tasks), or `asyncio.TaskGroup` (Python 3.11+) which cancels siblings on first failure.

---

## How to read the Security tab against this document

1. Open the [Code scanning alerts](https://github.com/Shurtug4l/sec-recon-agent/security/code-scanning) page.
2. Match each open alert against the table above.
3. If an alert is **not** in the table, it is new: assess it, decide, and update this file in the same PR that resolves (or accepts) it.
4. The Trivy workflow does not auto-dismiss alerts. The CRITICAL gate in `ci-docker-scan.yml` will fail the build outright on any CRITICAL; HIGH and below land in the Security tab as informational. The "fail on CRITICAL" line is the actual policy gate; this file is the discipline that prevents the HIGH/MEDIUM channel from becoming background noise.

---

## Out-of-scope by design

These findings will **never** be auto-dismissed even if a fix lands, because they touch code we do not invoke. Dismissing them would lose audit traceability:

- The 3 `rand` LOW findings (custom-logger unsoundness) live in a wheel we consume as a black box. A future ChromaDB upgrade may close the alert silently; this document will be updated in the same PR.

---

## Internal audit cadence and methodology

Periodic multi-agent review: spawn three specialized cold-review agents in parallel against the current `main` (`mcp-server-auditor`, `dependency-supply-chain-auditor`, `ai-governance-mapper`) plus one cross-check (`code-reviewer-strict`). Each agent operates in an isolated context and produces a prioritized P0-P3 report with file:line citations; findings are consolidated here, with mitigations and planned PRs.

The intent is **defense in depth via independent review**: the agents do not see each other's output, so a finding surfaced by three of them at once is a strong signal, and a finding surfaced by only one is still informative if the reasoning holds. The "what's solid" section in each agent report is also tracked separately (not in this document) to avoid backsliding on hardening that is already in place.

Cadence: ad-hoc, recommended every meaningful code addition to the MCP tool surface or the agent flow. Not a substitute for inline review, which catches issues before they land; the multi-agent pass is the periodic external check.

---

## Related

- [`.github/workflows/ci-docker-scan.yml`](../.github/workflows/ci-docker-scan.yml) — the scan workflow.
- [`docs/owasp_llm_top10.md::LLM05 Supply Chain`](owasp_llm_top10.md) — how supply-chain risk is layered against this project.
- [`docs/design.md::Residual risks`](design.md) — the architectural-level limitations these findings sit inside.
