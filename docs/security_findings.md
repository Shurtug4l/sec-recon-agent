# Security findings — open and accepted

The Trivy workflow uploads a SARIF report to the GitHub Security tab on every successful image build and on a weekly schedule. The findings listed below are the **currently open** alerts on `main`; each one has been triaged with a documented decision.

**Posture**: open findings stay open. Dismissing a CVE that we technically own (it ships inside our container) without a fix would be optics, not security. Documenting them publicly is the more honest signal: a reviewer can see the analysis, agree or disagree, and we can revisit when an upstream fix lands.

**Refresh cadence**: weekly Monday cron via `.github/workflows/ci-docker-scan.yml`. Anything new will surface in the Security tab without anyone running anything.

---

## Triage matrix

| Severity | CVE / GHSA | Package | Path | Disposition | Reason |
|---|---|---|---|---|---|
| HIGH | GHSA picomatch ReDoS | picomatch | `frontend` build chain | accept | build-time tooling, no attacker-controlled input |
| MEDIUM | postcss XSS via stringify | postcss | `frontend` build chain | accept | build-time CSS toolchain, output is static |
| MEDIUM | picomatch POSIX bracket | picomatch | `frontend` build chain | accept | build-time tooling |
| MEDIUM | ip-address parsing | ip-address | `frontend` transitive | accept | build-time tooling |
| MEDIUM | brace-expansion DoS via zero step | brace-expansion | `frontend` ESLint config parsing | accept | build-time, patterns from .eslintignore |
| LOW (x3) | rand unsoundness with custom logger | rand (Rust) | backend image ChromaDB native bridge | accept | we do not use rand with a custom logger |

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

## Related

- [`.github/workflows/ci-docker-scan.yml`](../.github/workflows/ci-docker-scan.yml) — the scan workflow.
- [`docs/owasp_llm_top10.md::LLM05 Supply Chain`](owasp_llm_top10.md) — how supply-chain risk is layered against this project.
- [`docs/design.md::Residual risks`](design.md) — the architectural-level limitations these findings sit inside.
