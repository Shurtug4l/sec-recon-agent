# Scorecard

Single reproducible measurement of the system across security posture, detection quality, retrieval, efficiency, and reliability. Regenerate with `make scorecard` (see [Reproduce](#reproduce)). Live metrics are populated from the eval / retrieval / red-team result JSONs; a _pending live run_ marker means that run has not been captured yet.

- **Model**: `sonnet`
- **Date**: 2026-07-07
- **Commit**: `101e6d8`
- **Token pricing**: Anthropic published rates as of 2026-06-24

## Security posture (red-team resistance)

Prompt-injection battery: **18 payloads** across 6 categories, each mapped to MITRE ATLAS techniques. Resistance = the agent held the boundary on every falsifiable check for the payload.

**Resistance: 15/18 (83%)**

| ATLAS technique | Payloads | Resisted |
|---|---:|---:|
| AML.T0024 (Exfiltration via ML Inference API) | 3 | 2/3 (67%) |
| AML.T0029 (Discover ML Model Family) | 2 | 2/2 (100%) |
| AML.T0040 (LLM Prompt Injection) | 10 | 8/10 (80%) |
| AML.T0054 (LLM Jailbreak) | 2 | 2/2 (100%) |
| AML.T0055 (Unsafe Plugin Output Handling) | 6 | 5/6 (83%) |

_A payload can exercise more than one technique, so the payload column sums past the battery size._

## Detection quality (golden set)

Golden set: **11 curated cases** (8 expect a CISA KEV hit, 1 expect a ransomware flag; KEV = CISA's Known Exploited Vulnerabilities catalog, CVEs observed exploited in the wild). Soft assertions: severity within +-1 step, expected CVE recall >= 50%, KEV / ransomware honored when asked.

- **Pass rate**: 10/11 (91%)
- **Severity within +-1 step**: 11/11
- **Mean CVE recall**: 1.00

## Retrieval quality (cve_semantic_search)

Measured by sampling the seeded ChromaDB index and querying with a truncated description; the corpus is a moving window, so numbers depend on the seed. Hybrid retrieval: dense MiniLM-L6 fused with lexical BM25 (reciprocal-rank fusion); no cross-encoder reranker (yet). Ablation vs dense-only in docs/evaluation.md.

- **Sampled**: 500 CVEs (top_k=10)
- **MRR**: 0.790
- **hit-rate@1 / @3 / @5**: 77% / 81% / 82%

_MRR = mean reciprocal rank of the expected CVE (1.0 = always ranked first); hit-rate@k = share of samples whose expected CVE appears in the top k results._

## Efficiency (cost & latency)

- **Latency p50 / p95**: 67.0s / 94.3s
- **Mean tokens (in / out)**: 69050 / 3908
- **Cost**: total $2.9234, mean $0.2658/triage

## Reliability (conformance & calibration)

- **Structured-output conformance**: 11/11 well-formed reports
- **Confidence calibration (ECE)**: 0.009 (0 = perfectly calibrated; over the scored cases)

## Prioritization (deterministic SSVC)

The SSVC verdict (Stakeholder-Specific Vulnerability Categorization, CISA's remediation-urgency methodology) is computed server-side from the collected signals, not by the LLM, so it is reproducible from the same inputs. EPSS below is FIRST.org's predicted probability of exploitation in the next 30 days. Decision rules, most-urgent first:

| Signal | Decision |
|---|---|
| known ransomware association | **Act** |
| on CISA KEV (active exploitation) | **Act** |
| public exploit AND EPSS >= 0.5 | **Act** |
| public exploit (no high-EPSS) | **Attend** |
| EPSS >= 0.5 or percentile >= 0.95 | **Attend** |
| EPSS >= 0.1 (elevated) | **Track\*** |
| High/Critical CVSS, no exploitation signal | **Track\*** |
| none of the above | **Track** |

_SSVC-informed, not the full CISA tree: the Automatable and Mission & Well-being decision points are approximated (EPSS as a likelihood proxy; deployment-specific asset criticality is out of scope for a stateless tool)._

## Reproduce

```bash
make up          # start the stack
make seed        # seed the CVE index (once)
mkdir -p data/scorecard
make eval     EVAL_ARGS='--json-output data/scorecard/eval.json --model sonnet'
make eval     EVAL_ARGS='--retrieval --retrieval-sample 500 --json-output data/scorecard/retrieval.json'
make redteam  REDTEAM_ARGS='--json-output data/scorecard/redteam.json --model sonnet'
make scorecard   # regenerate this file from whatever JSONs exist
```

The eval and red-team runs require a live stack and bill the LLM; they are out of CI by design. The deterministic coverage sections regenerate offline.
