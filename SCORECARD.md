# Scorecard

Single reproducible measurement of the system across security posture, detection quality, retrieval, efficiency, and reliability. Regenerate with `make scorecard` (see [Reproduce](#reproduce)). Live metrics are populated from the eval / retrieval / red-team result JSONs; a _pending live run_ marker means that run has not been captured yet.

- **Model**: `n/a (deterministic-only)`
- **Date**: 2026-07-01
- **Commit**: `14c11c6`
- **Token pricing**: Anthropic published rates as of 2026-06-24

## Security posture (red-team resistance)

Prompt-injection battery: **18 payloads** across 6 categories, each mapped to MITRE ATLAS techniques. Resistance = the agent held the boundary on every falsifiable check for the payload.

**Resistance: _pending live run_** (run `make redteam REDTEAM_ARGS='--json-output data/scorecard/redteam.json'`)

| ATLAS technique | Payloads | Resisted |
|---|---:|---:|
| AML.T0024 | 3 | _pending live run_ |
| AML.T0029 | 2 | _pending live run_ |
| AML.T0040 | 10 | _pending live run_ |
| AML.T0054 | 2 | _pending live run_ |
| AML.T0055 | 6 | _pending live run_ |

## Detection quality (golden set)

Golden set: **11 curated cases** (8 expect a CISA KEV hit, 1 expect a ransomware flag). Soft assertions: severity within +-1 step, expected CVE recall >= 50%, KEV / ransomware honored when asked.

- **Pass rate / severity / recall**: _pending live run_ (run `make eval EVAL_ARGS='--json-output data/scorecard/eval.json'`)

## Retrieval quality (cve_semantic_search)

Measured by sampling the seeded ChromaDB index and querying with a truncated description; the corpus is a moving window, so numbers depend on the seed. Stock MiniLM-L6 embeddings, no reranker (yet).

- **MRR / hit-rate@k**: _pending live run_ (run `make eval EVAL_ARGS='--retrieval --json-output data/scorecard/retrieval.json'`)

## Efficiency (cost & latency)

- **Latency / tokens / cost**: _pending live run_ (from the golden-set eval run above)

## Reliability (conformance & calibration)

- **Conformance / calibration**: _pending live run_ (from the golden-set eval run above)

## Prioritization (deterministic SSVC)

The SSVC verdict is computed server-side from the collected signals, not by the LLM, so it is reproducible from the same inputs. Decision rules, most-urgent first:

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
make eval     EVAL_ARGS='--json-output data/scorecard/eval.json'
make eval     EVAL_ARGS='--retrieval --json-output data/scorecard/retrieval.json'
make redteam  REDTEAM_ARGS='--json-output data/scorecard/redteam.json'
make scorecard   # regenerate this file from whatever JSONs exist
```

The eval and red-team runs require a live stack and bill the LLM; they are out of CI by design. The deterministic coverage sections regenerate offline.
