# Security findings - open and accepted

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
| P0 | MCP transport has no auth layer | `mcp_server/server.py` (FastMCP SSE) | **fixed (PR1)** | opt-in `MCP_AUTH_TOKEN` bearer middleware in front of the SSE app; default off so docker-compose-internal usage is unchanged |
| P1 | `nmap_parse_xml` has no size cap on input | `mcp_server/tools/nmap.py` | **fixed (PR1)** | 20MB input cap + 1000-host iteration cap, both enforced at the tool entry |
| P1 | `attack_mapping` `cwe_ids` list is unbounded | `mcp_server/tools/attack.py` | **fixed (PR1)** | 200-entry list cap + 40-char per-entry cap; oversize input raises `InvalidCweInputError` before lookup |
| P1 | NVD reference URLs not marked untrusted in output | `mcp_server/tools/cve.py`, `tools/patch.py` | **fixed (PR1)** | docstring + Pydantic `Field(description=...)` mark `references` as untrusted on `CVEDetail` and `PatchAvailability`; agent system prompt repeats the contract |
| P1 | SSE transport is legacy (Streamable HTTP is the post-2025-06-18 recommendation) | `mcp_server/server.py` | open, tracked (deprecation watch) | SDK still supports SSE; no breaking change forced yet |
| P1 | `epss_score` silently returns empty score on upstream CVE-id mismatch | `mcp_server/tools/epss.py` | **fixed (S1)** | explicit `EpssScore.status` enum (`found` / `not_found` / `upstream_error`); a CVE-id mismatch returns `upstream_error`, surfaced in the report `signal_coverage` |
| P1 | `path.write_bytes` blocks the event loop during 5-20MB cache refresh | `mcp_server/tools/exploits.py`, `tools/kev.py` | open, tracked | refresh runs at most once per cache TTL (7d Exploit-DB, 24h KEV) |
| P1 | `asyncio.gather` paired with bare `create_task` leaves orphaned tasks on failure | `mcp_server/tools/exploits.py`, `tools/kev.py` | open, tracked | `AsyncClient` context exit cancels in-flight tasks; window is narrow |

---

## Detailed triage

### Frontend npm findings (5)

All five findings live in `frontend/node_modules/` and reach the image because the Next.js build needs them at compile time. None of them are loaded at runtime by the user-facing Next.js server.

**Dependency chain** (from `npm ls`):

- **picomatch** -> transitive of `eslint-import-resolver-typescript` -> `tinyglobby` -> `fdir` and of `tailwindcss` -> `chokidar` / `micromatch`. Used during `next build` to walk source files; never at request time.
- **postcss** -> transitive of `next` (own pinned version), `tailwindcss`, `autoprefixer`, `postcss-import`. Runs once at build to produce static CSS. The cited XSS (`</style>` injection in stringify output) requires attacker-controlled CSS input, which we do not have.
- **ip-address** -> transitive of one of the test / lint chains. Not invoked from any runtime code path.
- **brace-expansion** -> transitive of `minimatch` -> ESLint and TypeScript-ESLint config-file parsing. The DoS requires a pattern like `{0..N..0}` with a zero step; our patterns come from `.eslintignore` and `tsconfig.json` (developer-controlled).

**Why we cannot bump them**: `npm audit fix --force` would downgrade `next` to 9.3.3 (the only Next version with a fixed transitive `postcss`) - a breaking change with no benefit. The same forced fix does not touch the picomatch / brace-expansion / ip-address chain because their transitive parents themselves have not bumped.

**What would change the disposition**:

- Next.js publishes a 15.x patch that bumps the transitive postcss.
- The Next.js / Tailwind / ESLint chain refreshes picomatch to a fixed version.
- We migrate the frontend off Next 15 (currently out of scope; tracked separately in the Dependabot ignore list for `next` major bumps).

### Backend Rust findings (3 × rand LOW)

Three identical findings in `app/.../bridge/Cargo.lock` inside the backend image (`python:3.14-slim` + ChromaDB Python wheel). The vulnerability is `rand::rng()` being unsound when used with a custom logger - a narrow API contract violation in the Rust `rand` crate.

The Cargo.lock comes from a pre-compiled native bridge bundled inside ChromaDB's wheel (likely the ONNX runtime bridge that backs the local embedder). We do not call `rand::rng()` directly, and the wheel does not expose a logger configuration knob to its Python callers.

**Why we cannot bump it**: the dependency tree is frozen at ChromaDB build time and shipped as a binary wheel. Bumping requires ChromaDB to publish a new wheel built against a newer `rand`, which is upstream's responsibility.

**What would change the disposition**: a new ChromaDB release that pins `rand >= <fixed-version>`. Dependabot will surface the Python-side bump when it lands.

---

## Detailed triage - internal audit findings

These come from the periodic multi-agent audit (last run 2026-05-18). Unlike supply-chain findings (which we accept and document because the fix sits upstream), internal findings are ours to fix and are tracked toward concrete PRs.

### P0 - MCP transport has no auth layer (fixed)

`mcp_server/server.py` started FastMCP with the SSE transport on `:8001` without any bearer / API-key / token check. The agent-api process enforces opt-in API-key auth (`api/stream.py`), but the MCP server, which is the more powerful surface (direct tool access, no agent guardrails), enforced none.

**Previous mitigation**: the `docker-compose.yml` did NOT publish `:8001` to the host. The port was reachable only via the compose-internal network, where the only client is `agent-api`. Anyone who re-ran the container with `-p 8001:8001` or deployed outside the compose perimeter lost this mitigation.

**Fix landed**: opt-in `MCP_AUTH_TOKEN` env var. When set, every HTTP request to the MCP server must carry `Authorization: Bearer <token>`; comparison is constant-time. When unset (default), behavior is unchanged so docker-compose-internal usage stays frictionless. Plain ASGI middleware (`mcp_server/auth.py`); lifespan and non-HTTP scopes pass through.

### P1 - Unbounded inputs on `nmap_parse_xml` and `attack_mapping` (fixed)

`nmap_parse_xml` previously accepted `xml_content: str` with no upper bound; while `defusedxml(forbid_dtd=True)` neutralized XXE and entity expansion, a multi-hundred-MB well-formed `<port>` tree was fully parsed in-process. Per-host caps were present, per-document host count was not.

`attack_mapping` previously accepted `cwe_ids: list[str]` with no length limit; the existing `cwe[:10]` truncation only affected the span attribute, not the iteration cost.

**Previous mitigation**: both tools were reachable only by the agent (single trusted client), and the rate-limit middleware on `agent-api` capped request frequency from the client side. Direct MCP-transport callers would have bypassed that, see the P0 above for the related transport-auth gap.

**Fix landed**: `Annotated[str, Field(max_length=20_000_000)]` on `nmap_parse_xml.xml_content` + a `[:1000]` cap on the `<host>` iteration; a 20MB pre-flight check also runs at the tool entry to bound direct callers. `Annotated[list[str], Field(max_length=200)]` with per-item `Field(max_length=40)` on `attack_mapping.cwe_ids` + runtime checks that raise `InvalidCweInputError` before any lookup. Contract tests pin the new caps.

### P1 - NVD reference URLs reach the agent without an "untrusted" marker (fixed)

`tools/cve.py` and `tools/patch.py` returned URLs extracted from NVD `references` as typed `HttpUrl` fields without an explicit "treat as data, not as instruction" marker in the output model. The agent prompt and the absence of a URL-fetching downstream tool both kept this dormant; the latent risk was that any future tool following a reference URL would have inherited an SSRF-by-reference vector.

**Previous mitigation**: agent system prompt treated tool output as data; no MCP tool dereferenced a reference URL.

**Fix landed**: `CVEDetail.references` and `PatchAvailability.references` carry an `UNTRUSTED` contract in both the class docstring and the Pydantic `Field(description=...)`. Tool docstrings on `cve_lookup` and `patch_lookup` repeat the contract, and the agent system prompt has an explicit clause forbidding fact-claims based on reference content. No boolean flag is added to the data shape: the constant-True flag would have been rumor in every payload, where a documentation contract is louder.

### P1 - SSE transport is on the legacy side of the MCP spec line

The MCP spec revision dated 2025-06-18 introduces Streamable HTTP as the recommended bidirectional surface; SSE is marked legacy in several SDK releases. The server still uses SSE in `mcp_server/server.py`.

**Current mitigation**: the SDK pin used here still supports SSE; no breaking change forced yet.

**Planned fix**: migrate to `transport="streamable-http"` once the SDK floor allows. Deferred until the SDK explicitly deprecates, no rush.

### P1 - `epss_score` silent fallback on upstream CVE-id mismatch (fixed)

`tools/epss.py` used to return an empty `EpssScore(cve_id=cve_id)` after a `log.warning` when the FIRST.org response carried a different CVE-id than the one queried. The agent had no way to distinguish "CVE not in EPSS" (legitimate empty result) from "EPSS API misbehaved" (system fault), so a misbehavior could read as a "zero exploit probability" signal.

**Fix landed (S1)**: `EpssScore.status` disambiguates the three states at the tool boundary (`found` / `not_found` / `upstream_error`); a mismatched upstream CVE-id returns `status=upstream_error` (span attribute `epss.status`), and `TriageReport.signal_coverage` carries the per-feed state so the agent and the UI see the fault explicitly. Hard request failures still raise a typed `EpssError`.

### P1 - Event-loop blocking on cache refresh write

`tools/exploits.py` and `tools/kev.py` call sync `path.write_bytes(bytes(buffer))` on 5-20MB blobs inside their async cache-refresh paths. Each refresh momentarily blocks the asyncio event loop.

**Current mitigation**: cache refresh runs at most once per TTL (7d Exploit-DB index, 24h KEV catalog), so the blocking window is rare in practice.

**Planned fix**: `await asyncio.to_thread(path.write_bytes, bytes(buffer))`.

### P1 - Orphaned tasks on `asyncio.gather` failure

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

- [`.github/workflows/ci-docker-scan.yml`](../.github/workflows/ci-docker-scan.yml) - the scan workflow.
- [`docs/owasp_llm_top10.md::LLM03 Supply Chain`](owasp_llm_top10.md) - how supply-chain risk is layered against this project.
- [`docs/design.md::Residual risks`](design.md) - the architectural-level limitations these findings sit inside.
