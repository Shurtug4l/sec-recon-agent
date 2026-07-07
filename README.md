# sec-recon-agent

[![backend](https://github.com/Shurtug4l/sec-recon-agent/actions/workflows/ci-backend.yml/badge.svg)](https://github.com/Shurtug4l/sec-recon-agent/actions/workflows/ci-backend.yml)
[![frontend](https://github.com/Shurtug4l/sec-recon-agent/actions/workflows/ci-frontend.yml/badge.svg)](https://github.com/Shurtug4l/sec-recon-agent/actions/workflows/ci-frontend.yml)
[![python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](#license)
[![scorecard](https://img.shields.io/badge/scorecard-reproducible-blue)](SCORECARD.md)
[![live demo](https://img.shields.io/badge/demo-live-22d3ee)](https://shurtug4l.github.io/sec-recon-agent/)

**An LLM vulnerability-triage agent designed the way an AI Solutions Architect would build it and an AI Security Engineer would attack it.** Every answer is grounded in live authoritative feeds, the output is a schema-bounded `TriageReport`, the prioritization verdict is deterministic (not LLM-guessed), and the untrusted-data boundary is a first-class design concern with a falsifiable red-team battery. Built on Pydantic AI + a custom Model Context Protocol (MCP) server, behind a Next.js frontend.

![sec-recon-agent: a live Log4Shell triage from query to a typed TriageReport with CISA KEV, ransomware, and EPSS signals](docs/assets/demo.gif)

**[Try the live demo](https://shurtug4l.github.io/sec-recon-agent/)** - it replays real captured triages across the full SSVC ladder right in the browser, with a reproducible [scorecard](https://shurtug4l.github.io/sec-recon-agent/scorecard/). No API key, no setup: the runs are genuine captures, not mock data.

Feed it a CVE ID, a product version, raw Nmap XML, or an SBOM (a machine-readable software inventory: CycloneDX, SPDX, or requirements.txt). The agent grounds its answer through ten typed MCP tools covering CVE lookup and semantic search, exploit and patch availability, KEV / EPSS / OSV feeds, SBOM and Nmap ingestion, and MITRE ATT&CK mapping. It returns a schema-validated `TriageReport`: severity, exploit availability, operational signals, prioritization verdict, recommended action with a concrete fixed version when one exists, and the full reasoning chain. Two design choices carry the whole project:

- **The verdict is deterministic.** Prioritization follows SSVC (Stakeholder-Specific Vulnerability Categorization, CISA's decision framework), a four-step urgency ladder: **Act / Attend / Track\* / Track**, where Track\* is Track with closer monitoring. The verdict is computed server-side from the collected signals and stamped onto the report, never produced by the LLM: same signals in, same verdict out.
- **Coverage is honest.** The signals are named and sourced: CISA KEV (the US government catalog of vulnerabilities confirmed exploited in the wild), EPSS (FIRST.org's estimated probability of exploitation within 30 days), public-exploit availability, and CVSS (the standard 0-10 severity score). Each feed is reported per triage as found, no entry, errored, or not queried - the report never papers over a feed it could not reach.

## What it is, and what it is not

Deciding whether a CVE deserves an all-hands response or a slot in next sprint is judgment work, done today across ten browser tabs: NVD for the CVSS, CISA KEV for active exploitation, FIRST EPSS for probability, Exploit-DB and GitHub for public PoCs. A general-purpose LLM goes faster and confidently hands you a CVSS that does not exist. This agent runs the entire fusion across live feeds in under two minutes and returns a deterministic verdict with a hash-chained audit of exactly how it got there. It is useful to vulnerability and AppSec engineers (a defensible, prioritized queue), SOC engineers (every report pivots CWE weakness classes into ATT&CK techniques, the language detections are written in), and teams building or vetting LLM agents (a working reference for a grounded, type-safe, adversary-aware agent).

It is deliberately **not**:

- **not a vulnerability scanner** - it does not enumerate your packages or images; feed it an SBOM (pair it with Trivy / Grype, which produce that SBOM);
- **not a findings-management platform** - no dedup / ticketing / dashboards at fleet scale (that is DefectDojo's job);
- **not a source of ground truth** - it cites NVD / KEV / EPSS / OSV and refuses to invent facts on tool failure (degraded mode);
- **not production multi-tenant SaaS** - single-tenant by design; auth and rate-limit are opt-in.

| | **sec-recon-agent** | Trivy / Grype | DefectDojo |
|---|---|---|---|
| Primary job | Reason over a vuln from mixed inputs and prioritize it | Scan images / filesystems / SBOMs for known-vuln packages | Aggregate and manage findings from many scanners |
| Output | Grounded `TriageReport` + deterministic SSVC verdict | List of vulnerable packages + fixed versions | Dashboards, dedup, workflow / tickets |
| Signal fusion | KEV + EPSS + exploit + ransomware + ATT&CK in one verdict | CVSS / severity from the advisory | whatever the wired scanners emit |
| Adversarial posture | Untrusted-data boundary + red-team battery are first-class | trusted-input tooling | trusted-input aggregation |

## Architecture

```
+--------------------------+
|  Frontend - Next.js 15   |  :3000   <- user types a query in the browser
|  React 19 + Tailwind     |
+------------+-------------+
             |  /api/triage (Next.js proxy)
             v
+--------------------------+
|  Agent API - FastAPI     |  :8000   <- SSE stream of node events + final TriageReport
|  Pydantic AI agent       |
+------------+-------------+
             |  MCPToolset (HTTP+SSE)
             v
+--------------------------+
|  MCP Server - FastMCP    |  :8001
|  10 typed tools          |
+------------+-------------+
             |
             +-- NVD CVE 2.0 API           (cve_lookup, async + rate-limited)
             +-- ChromaDB MiniLM-L6 + BM25 (cve_semantic_search, hybrid RRF-fused)
             +-- Exploit-DB CSV + GitHub   (exploit_check, parallel fan-out)
             +-- CISA KEV catalog          (kev_check, "patch now" signal + ransomware flag)
             +-- FIRST EPSS API            (epss_score, 30-day exploitation probability)
             +-- CycloneDX / SPDX / PEP 508 (sbom_ingest, no-network, deterministic)
             +-- NVD CPE configurations    (patch_lookup, fixed_in / version range extraction)
             +-- OSV.dev API               (osv_lookup, package + version -> advisories)
             +-- defusedxml                (nmap_parse_xml, XXE-safe)
             +-- MITRE ATT&CK mapping      (attack_mapping, CWE -> techniques + mitigations)
```

For one named CVE, five tools fan out in parallel; `attack_mapping` runs once at the end on the union of CWE IDs; `cve_semantic_search` runs only when the input is a fuzzy description rather than a CVE ID. Every free-text vendor field crossing a tool boundary is fenced as `<UNTRUSTED_CONTENT>` before it reaches the LLM. The full sequence diagram and the field-level trust map are in [docs/design.md](docs/design.md#triage-end-to-end); the trust boundary is the subject of [docs/case_study.md](docs/case_study.md).

## Quick start

```bash
git clone https://github.com/Shurtug4l/sec-recon-agent.git
cd sec-recon-agent
cp .env.example .env       # set ANTHROPIC_API_KEY

make build                 # multi-stage uv + node builds
make seed                  # one-shot: pull recent CRITICAL+HIGH CVEs into ChromaDB (~5-8k, 30-day window)
make up                    # start mcp-server + agent-api + frontend
make ui                    # opens http://localhost:3000
```

Three services bound to localhost only: `:3000` (Next.js frontend), `:8000` (agent API, FastAPI + SSE), `:8001` (MCP server, FastMCP). One-off query from the shell:

```bash
make triage Q="Apache 2.4.49 on port 80. Risk?"
# or: curl -N -X POST http://localhost:8000/v1/triage \
#       -H "Content-Type: application/json" -d '{"query": "Apache 2.4.49 on port 80. Risk?"}'
```

The no-Docker development path, API authentication, rate limiting, and MCP transport auth are in [docs/running.md](docs/running.md).

## The ten tools

Each tool has a typed Pydantic contract: validated input, typed result model, typed errors, size and rate caps, and untrusted-content fencing on free-text fields. Per-tool contracts with caps and retry policies are in [docs/tools.md](docs/tools.md).

| Tool | Source | Returns |
|---|---|---|
| `cve_lookup` | NVD CVE 2.0 API | `CVEDetail`: CVSS v3, severity, CWEs, affected CPEs, references |
| `cve_semantic_search` | local ChromaDB index | ranked `CVECandidate` hits for fuzzy descriptions (hybrid dense + BM25, RRF-fused) |
| `exploit_check` | Exploit-DB CSV + GitHub code search | `ExploitCheck`: public-PoC availability |
| `kev_check` | CISA KEV catalog | `KevCheck`: exploited-in-the-wild, remediation deadline, ransomware flag |
| `epss_score` | FIRST.org EPSS API | `EpssScore`: 30-day exploitation probability + percentile |
| `patch_lookup` | NVD CPE configurations | `PatchAvailability`: fixed-in versions per affected product |
| `osv_lookup` | OSV.dev API | `OsvScanResult`: advisories for a package at a specific version |
| `sbom_ingest` | local parse, no network | `SbomComponentList` from CycloneDX / SPDX / requirements.txt |
| `nmap_parse_xml` | local parse, defusedxml | `NmapScanResult`: hosts, ports, services, version banners |
| `attack_mapping` | bundled MITRE ATT&CK mapping | ATT&CK techniques + mitigations for a set of CWE IDs |

The system prompt encodes one prioritization heuristic: CISA KEV membership > known ransomware use > EPSS probability >= 0.5 (or percentile >= 0.95) > CVSS as tiebreaker. CVSS alone over-weights theoretical impact relative to real-world exploitation likelihood.

## Determinism, honesty, audit

**Deterministic SSVC.** The prioritization verdict is computed by a pure server-side function (`agent/ssvc.py`) over the collected signals and stamped onto the final report. The LLM can reason about it but cannot change it. A safety-relevant verdict should not depend on sampling temperature.

**Signal-coverage honesty.** Every report carries a per-feed coverage map: found, no entry, errored, or not queried. A triage that could not reach EPSS says so instead of silently omitting the signal, and the eval suite scores this honesty.

**Hash-chained audit trail.** Every triage appends one row to an append-only SQLite log: SHA-256 digests of query and report, aggregate counts, model, duration. Rows are sealed with `prev_event_hash` / `this_event_hash` over a canonical JSON serialization; `sec-recon-audit verify` walks the chain and exits non-zero on tamper. Digest-only by default: plain query text stays out unless explicitly enabled. Internals in [docs/design.md](docs/design.md#operational-notes).

## Eval, red team, scorecard

An end-to-end golden-set evaluation (`src/sec_recon_agent/eval/`) exercises the live HTTP API with 11 curated queries: named CVEs, fuzzy descriptions, an SBOM, degraded inputs. Assertions are soft (severity within +-1 step, expected CVE recall >= 0.5, KEV / ransomware flags honored) because the agent is probabilistic; the measured axes are the ones an engineering review actually asks about: latency p50/p95, tokens and $/triage, structured-output conformance, confidence calibration (ECE), and retrieval quality (hit-rate@k, MRR) for the semantic search index.

A red-team battery of 18 prompt-injection payloads across six categories (direct override, role-play, fake authority, marker forgery, system-prompt extraction, indirect injection via tool output) applies falsifiable resistance checks to the returned report. Every payload is tagged with the MITRE ATLAS technique it exercises, and the CLI reports per-technique resistance rates.

```bash
make up
make eval          # golden set against the live stack; bills the LLM
make redteam       # injection battery; bills the LLM
make scorecard     # regenerate SCORECARD.md from stored result JSONs
```

Both suites are deliberately out of CI: they need a live stack and bill the LLM provider. Run them before merging changes to the system prompt or the model. Results land in one stamped, reproducible [SCORECARD.md](SCORECARD.md); the scorecard baseline is measured on sonnet (the default haiku is cheaper but thrashes on multi-tool cases). Full commands, sample outputs, and the model-comparison mode are in [docs/evaluation.md](docs/evaluation.md).

## Security posture

Every HIGH finding from an independent security review is mapped to the code change that addressed it in [docs/design.md](docs/design.md#threat-model). Highlights:

- **Strict typing at the model boundary** - every tool I/O is a Pydantic model; `mypy --strict` enforced.
- **Untrusted-content fencing** - every free-text vendor field is wrapped with `<UNTRUSTED_CONTENT>` markers at the code boundary (`mcp_server/security.py`); the system prompt instructs the LLM to treat fenced content as data, never as instructions.
- **XXE-safe XML parsing** - `defusedxml` with explicit `forbid_dtd=True`, tested against classic, external-DTD, parameter-entity, and billion-laughs payloads.
- **Bounded resource consumption** - every input crossing the MCP boundary is double-capped (schema `max_length` + runtime pre-flight); outbound feeds are host-locked with size caps and post-redirect host checks.
- **Error-payload allowlist** - the SSE `error` event surfaces a generic message unless the exception type is explicitly allowlisted; internal messages never leak to the client.
- **Container hardening** - non-root users, `read_only: true` rootfs, `no-new-privileges`, ports bound to `127.0.0.1`, `tmpfs:/tmp`.
- **Trivy in CI** - both images scanned on dependency changes plus a weekly cron; CRITICAL findings block the merge, HIGH findings land as SARIF in the Security tab. Open findings are triaged with accept rationale in [docs/security_findings.md](docs/security_findings.md).
- **Opt-in API auth and per-IP rate limiting**; the MCP port takes a bearer token whenever it is published beyond the compose network - setup in [docs/running.md](docs/running.md).

## Testing

**405 tests (402 fast + 3 slow ChromaDB round-trip tests, excluded from the fast run)**, all network-mocked, no LLM billing. Coverage on the fast suite holds at ~90% with a soft 70% floor. CI matrix-tests Python 3.12 + 3.13.

```bash
make test                        # full suite (includes the 3 slow tests)
uv run pytest -m "not slow"      # fast suite, ~3.5 min (tenacity retry tests include real waits)
uv run pytest -m "not slow" --cov
uv run pytest tests/property     # property-based + adversarial corpus only
make lint                        # backend (ruff + mypy --strict) + frontend (ESLint)
```

The per-area breakdown - tool contracts, adversarial corpus, API, audit hash chain, eval metrics, red-team scorer, SSVC rules, observability privacy invariants - is in [docs/design.md](docs/design.md#testing-strategy).

## Frontend

The browser is the primary interface, in a dark-only "Slate Recon" design system. Five tabs plus a permalink route:

- **Home (`/`)** - landing: architecture pipeline, design pillars, tool grid.
- **Triage (`/triage`)** - query form with example chips, live SSE progress, the report view, and a localStorage history sidebar.
- **Dashboard (`/dashboard`)** - statistics from local history, a measured per-node latency waterfall, and a transparency tab showing the literal system prompt and tool inventory from `GET /v1/meta`.
- **Scorecard (`/scorecard`)** - the reproducible scorecard rendered in the UI.
- **Guide (`/guide`)** - one explainer card per framework the agent grounds answers in (CVE / CVSS, KEV, EPSS, ATT&CK, ATLAS, SBOM, SSVC, MCP...).
- **`/r`** - self-contained viewer for shared-report permalinks: the whole report is gzip-encoded in the URL fragment, decoded locally, never sent to a server.

Reports stream live over SSE, render the untrusted-content fence semantically (vendor text is visibly quarantined), and export to Markdown, raw JSON, or print-to-PDF. Component map and SSE wire protocol in [docs/frontend.md](docs/frontend.md).

## Stack

**Backend**: Python 3.12+, `uv`, `pydantic-ai`, `mcp` (FastMCP), FastAPI + `sse-starlette` + `slowapi`, ChromaDB (ONNX MiniLM embedder), `httpx` + `tenacity`, `defusedxml`, `pydantic-settings` (`SecretStr`), `structlog`, OpenTelemetry. **Frontend**: Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS, Radix primitives, Recharts. **Containers**: multi-stage Dockerfiles, Docker Compose, optional Jaeger profile. **Tests**: pytest, respx, Hypothesis, the OpenTelemetry SDK's `InMemorySpanExporter`.

Observability: OTel tracing in both Python processes, stdout exporter by default, `make obs-up` for a Jaeger sidecar at `:16686`, W3C `traceparent` propagated from the frontend proxy through to the MCP server. Span attributes are allowlisted; user query text and vendor content are never recorded. Details in [docs/design.md](docs/design.md#observability).

## Project layout

```
sec-recon-agent/
+- src/sec_recon_agent/
|  +- agent/          # Pydantic AI agent: prompts, TriageReport schema, deterministic SSVC (ssvc.py)
|  +- api/            # FastAPI app: POST /v1/triage (SSE), /v1/meta, /v1/health
|  +- audit/          # SHA-256 hash-chain audit log + sec-recon-audit CLI
|  +- eval/           # golden set, runner, scorer, metrics, cost, scorecard generator
|  +- redteam/        # injection payloads, scorer, CLI
|  +- mcp_server/     # FastMCP server: 10 tools + models, errors, security, auth, nvd_client
|  +- config.py, observability.py
+- frontend/          # Next.js 15 App Router, Slate Recon design system
+- tests/             # agent, api, audit, eval, mcp_server, property, redteam, observability
+- docs/              # design, case study, tools, evaluation, running, frontend, governance mappings
+- examples/          # real agent sessions captured live
+- scripts/           # demo fixture capture
+- SCORECARD.md       # reproducible metrics (make scorecard)
+- Dockerfile, docker-compose.yml, Makefile, pyproject.toml, SECURITY.md, .env.example
```

## Documentation

- [docs/design.md](docs/design.md) - the engineering brief: architecture decisions with rejected alternatives, threat model with finding-to-fix mapping, defended invariants, testing strategy, operational notes.
- [docs/tools.md](docs/tools.md) - per-tool MCP contracts: inputs, result models, caps, retry policies.
- [docs/evaluation.md](docs/evaluation.md) - eval suite and red-team battery in depth: commands, sample outputs, model comparison.
- [docs/running.md](docs/running.md) - no-Docker development, API auth + rate limiting, MCP transport auth, observability endpoints.
- [docs/frontend.md](docs/frontend.md) - frontend component map, SSE wire protocol, theming, export/share.
- [SCORECARD.md](SCORECARD.md) - one reproducible, stamped scorecard across security posture, detection, retrieval, cost / latency, calibration.
- [examples/triage_walkthrough.md](examples/triage_walkthrough.md) - real agent sessions captured against the live stack.
- [CONTRIBUTING.md](CONTRIBUTING.md) - local dev setup, pre-commit, branch protection, PR flow.
- [SECURITY.md](SECURITY.md) - responsible-disclosure policy and safe-harbor terms.

For an AI security / governance reviewer, the governance set answers three questions: what risks were considered, what an attacker would do against the agent itself, and what an AIMS-certified organization would need to point at.

- [docs/case_study.md](docs/case_study.md) - the design narrative on the untrusted-data trust boundary: threat model, why the obvious defenses fail, the four-layer design, residual risk.
- [docs/owasp_llm_top10.md](docs/owasp_llm_top10.md) - OWASP LLM Top 10 (2025) mapping with status, controls, file:line citations, and the tests defending each invariant.
- [docs/mitre_atlas.md](docs/mitre_atlas.md) - MITRE ATLAS mapping (AI-specific adversary tactics and techniques).
- [docs/iso_42001.md](docs/iso_42001.md) - ISO/IEC 42001:2023 alignment matrix with explicit out-of-scope declarations.
- [docs/mcp_self_audit.md](docs/mcp_self_audit.md) - the MCP server audited as a plugin surface against OWASP LLM07 / LLM08 and MCP anti-patterns.
- [docs/security_findings.md](docs/security_findings.md) - open Trivy / SARIF findings with triage notes and accept rationale.

## License

MIT.
