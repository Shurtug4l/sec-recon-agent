# MITRE ATLAS mapping

This document maps `sec-recon-agent` against the [MITRE ATLAS framework](https://atlas.mitre.org/) - adversarial threat landscape for AI systems. ATLAS organizes attacks by tactic (the attacker's goal) and technique (the method), borrowing the structure of ATT&CK and extending it to AI-specific surfaces.

The codebase has a unique double relationship with ATLAS:

1. **As a defender**: the agent itself is a target and applies controls against the tactics below.
2. **As an instrument**: the agent already integrates the `attack_mapping` MCP tool, which translates CWE IDs from a CVE into MITRE ATT&CK techniques and their mitigations. ATLAS is the natural companion framework for the AI-specific layer above ATT&CK.

For each tactic, the table below names the techniques most relevant to an LLM agent with a tool-calling surface and a vector store, the corresponding control(s) in this codebase, and the falsifiable test that defends the invariant.

## Summary

| Tactic | Most relevant techniques here | Status |
|---|---|---|
| Reconnaissance | AML.T0000 (Search Public Resources), AML.T0001 (Open-Source Intelligence) | N/A (defender; tools deliberately use public sources) |
| Resource Development | AML.T0007 (Acquire Public Models) | N/A (no fine-tuning, off-the-shelf Claude API) |
| Initial Access | AML.T0040 (LLM Prompt Injection: Direct / Indirect) | partial (defense in depth - see LLM01 in `owasp_llm_top10.md`) |
| ML Model Access | AML.T0040.000 (LLM API Access) | mitigated (opt-in API auth, allowlisted model override) |
| Execution | AML.T0050 (Command and Scripting Interpreter) | N/A (tool surface is read-only, no shell-invoking tools) |
| Persistence | AML.T0021 (Establish Accounts: agent memory) | N/A (single-turn, no cross-session memory) |
| Defense Evasion | AML.T0054 (LLM Jailbreak), AML.T0055 (Unsafe Plugin Output Handling) | partial (red-team battery + structured output) |
| Discovery | AML.T0029 (Discover ML Model Family) | partial (`/v1/meta` exposes model + system prompt by design) |
| Collection | AML.T0036 (Data from Information Repositories: vector store) | mitigated (local-only Chroma, public corpus, query truncation) |
| ML Attack Staging | AML.T0043 (Craft Adversarial Data) | mitigated (red-team battery directly tests resistance) |
| Exfiltration | AML.T0024 (Exfiltration via ML Inference API) | mitigated (output schema + observability whitelist + error sanitization) |
| Impact | AML.T0034 (Cost Harvesting), AML.T0048 (Denial of ML Service) | mitigated (per-tool caps, opt-in rate limit, schema-bounded output) |

## Detailed mappings

### Initial Access - AML.T0040 (LLM Prompt Injection)

**Direct (T0040 main)**: the user input is itself adversarial.
**Indirect (T0040 sub)**: content that the agent retrieves through a tool is adversarial (e.g. an NVD description, an Nmap banner, a CISA KEV note).

**Controls applied**:

- Hard untrusted-content fence at every tool boundary that returns free-text vendor content. Locations and code references in `docs/owasp_llm_top10.md::LLM01`.
- System-prompt guardrail naming the markers and instructing the model to treat the wrapped content as data.
- Structured output (`TriageReport`) so the model cannot produce free-text outside the schema even when it cedes to an injection.
- Operational regression detection: `make redteam` runs 18 curated payloads across `direct`, `role_play`, `fake_authority`, `marker_forgery`, `system_extract`, `indirect` categories with falsifiable resistance checks. The aggregate resistance rate is the headline metric after any prompt or model change.

**Why partial**: marker fencing is a soft boundary in the model's attention; a sufficiently determined indirect injection can still degrade observable output. The red-team battery catches the common patterns, not all possible patterns.

### ML Model Access - AML.T0040.000 (LLM API Access)

**Controls applied**:

- Opt-in API authentication: `Authorization: Bearer <key>` or `X-API-Key: <key>`, constant-time compare via `hmac.compare_digest`. See `src/sec_recon_agent/api/stream.py::verify_api_key`.
- Allowlist of model identifiers (`ALLOWED_MODELS` in `agent/triage.py`): an attacker cannot probe arbitrary model strings via the per-request override.
- Anthropic API key never logged, never sent to the client, pushed to `os.environ` exactly once at startup with `SecretStr`.

### Defense Evasion - AML.T0054 (LLM Jailbreak) + AML.T0055 (Unsafe Plugin Output Handling)

**T0054** is partially addressed by the same controls as Initial Access (the model's instruction-following is the boundary). **T0055** is the part we own outright: tool output that contains adversarial instructions is fenced before it ever reaches the model. See `src/sec_recon_agent/mcp_server/security.py`.

**Operational signal**: the red-team battery includes `marker_forgery` payloads (`marker-close-untrusted`, `marker-fake-system-tag`, `marker-pseudo-xml-instructions`) specifically designed to test whether a model can be tricked into accepting a forged boundary marker as a real one.

### Discovery - AML.T0029 (Discover ML Model Family)

**By design transparent**: `/v1/meta` returns the model identifier and the literal system prompt. The project's transparency posture says the operator should know what the agent is told; in a production-shaped deployment this endpoint sits behind the same API-key gate as `/v1/triage`.

### Collection - AML.T0036 (Data from Information Repositories)

The local ChromaDB collection is the target. The corpus is public CVE data (NVD CRITICAL+HIGH, 30-day lookback). User queries are NOT persisted in the corpus and NOT echoed in spans. An attacker with code-execution on the host already owns the process; the threat model does not claim defense against that scenario.

The eval suite (`sec-recon-eval`) and red-team battery (`sec-recon-redteam`) explicitly use only public-CVE queries; a fork that ingests private threat intel would need to revisit this section.

### ML Attack Staging - AML.T0043 (Craft Adversarial Data)

This is the tactic the red-team battery directly tests against. Every payload in `src/sec_recon_agent/redteam/payloads.py` carries an `atlas_techniques` field with the IDs above (`AML.T0024`, `AML.T0029`, `AML.T0040`, `AML.T0054`, `AML.T0055`). A drift detector in `tests/redteam/test_scorer.py` fails the suite if a future payload is added without an ATLAS tag, except for the explicit sanity case.

The CLI prints a per-technique resistance rate alongside the per-category one. The aggregate is **not** a partition - a payload tagged with multiple techniques contributes to each - so the per-technique number measures "how often the agent held the boundary on any payload exercising this technique", not "how often the agent held the boundary on payloads whose primary technique was this".

```bash
make redteam REDTEAM_ARGS='--filter AML.T0055'   # run only the indirect-injection payloads
make redteam REDTEAM_ARGS='--json-output redteam.json'  # JSON output includes atlas_breakdown[]
```

Categories in `src/sec_recon_agent/redteam/payloads.py`:

- `direct`: top-level instruction override (AML.T0040).
- `role_play`: persona swap / jailbreak (AML.T0054).
- `fake_authority`: impersonation (AML.T0040).
- `marker_forgery`: fake UNTRUSTED markers / system tags (AML.T0040 + AML.T0055).
- `system_extract`: prompt-leak attempts (AML.T0024 + AML.T0029).
- `indirect`: payload arrives via tool output - CycloneDX component name, Nmap banner, requirements.txt comment, fake tool result (AML.T0055).

### Exfiltration - AML.T0024 (Exfiltration via ML Inference API)

**Controls applied**:

- **Structured output** prevents the model from emitting arbitrary attacker-chosen text outside the schema.
- **Span attribute whitelist** prevents covert exfiltration via OTel: tool name, CVE ID regex-constrained, success bool, counts only. Canary tests assert no untrusted content lands in spans.
- **SSE error sanitization** prevents traceback content from leaving the API process.
- **Audit-trail privacy defaults**: only digests + counts persisted; plain query / summary opt-in per deployment.

### Impact - AML.T0034 (Cost Harvesting) + AML.T0048 (Denial of ML Service)

**T0034** (driving LLM token cost up):

- TriageReport schema caps every list field (max 10 CVEs, max 20 attack techniques) so the model cannot emit unbounded payloads.
- `RATE_LIMIT_PER_MINUTE` env switch enables a per-IP slowapi limiter; 429 body does not echo the configured limit.

**T0048** (resource exhaustion against the local pipeline):

- Per-tool size caps on every external fetch (Exploit-DB 20 MB, KEV 50 MB, EPSS 4 MB).
- `TriageRequest.query` capped at 100 KB.
- Nmap hostnames / ports per host capped at 50 / 200.
- NVD sliding-window rate limiter, race-free.

## Cross-reference

- The `attack_mapping` MCP tool (`src/sec_recon_agent/mcp_server/tools/attack.py`) integrates the *defender-side* MITRE ATT&CK framework (CWE -> technique -> mitigation). ATLAS is the *adversary-side* AI-specific layer above it. The two surfaces are complementary: ATT&CK names what an attacker would do with a CVE, ATLAS names what an attacker would do to the agent itself.
- `docs/owasp_llm_top10.md` covers the same risk space framed by OWASP's taxonomy; the two documents share evidence but use different category cuts.
