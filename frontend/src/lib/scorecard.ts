// Aggregations for the static /scorecard route. Pure functions over the
// committed sonnet-baseline snapshot in src/demo/scorecard/*.json (the same
// eval / retrieval / red-team result JSONs `make scorecard` consumes, slimmed
// to the fields the page renders - the numbers are unchanged). No network, no
// key: the page is statically exportable.
//
// The confidence -> probability mapping mirrors eval/metrics.py
// (confidence_to_probability) so the calibration bins and ECE match the
// backend scorecard exactly.

import evalRaw from "@/demo/scorecard/eval.json";
import provenanceRaw from "@/demo/scorecard/provenance.json";
import redteamRaw from "@/demo/scorecard/redteam.json";
import retrievalRaw from "@/demo/scorecard/retrieval.json";

export interface Provenance {
  model: string;
  date: string;
  commit: string;
  pricing_note: string;
  source: string;
}

interface EvalVerdict {
  case_id: string;
  passed: boolean;
  severity_ok: boolean;
  cve_recall: number;
  kev_ok: boolean;
  ransomware_ok: boolean;
  notes: string[];
}

interface EvalCase {
  id: string;
  query: string;
  model: string;
  expected_severity: string | null;
  expected_in_kev: boolean | null;
  severity: string;
  confidence: "high" | "medium" | "low";
  verdict: EvalVerdict;
  elapsed_seconds: number;
  usage: { input_tokens: number | null; output_tokens: number | null; cost_usd: number | null };
  conformant: boolean;
}

interface RedteamSnapshot {
  summary: { total: number; resisted: number; resistance_rate: number };
  atlas_breakdown: Array<{ technique: string; total: number; resisted: number; rate: number }>;
  category_breakdown: Array<{ category: string; total: number; resisted: number }>;
  misses: Array<{
    id: string;
    category: string;
    severity: string;
    atlas_techniques: string[];
    failed_checks: string[];
  }>;
}

interface RetrievalSnapshot {
  sampled: number;
  top_k: number;
  query_chars: number;
  mrr: number;
  hit_rate_at_1: number;
  hit_rate_at_3: number;
  hit_rate_at_5: number;
  p95_similarity_top1: number;
}

const evalCases = evalRaw as EvalCase[];
const redteam = redteamRaw as RedteamSnapshot;
const retrieval = retrievalRaw as RetrievalSnapshot;
export const provenance = provenanceRaw as Provenance;

// Mirrors eval/metrics.py::confidence_to_probability.
const CONFIDENCE_PROB: Record<string, number> = { high: 0.9, medium: 0.6, low: 0.3 };

// Mirrors eval/metrics.py::percentile (linear interpolation, numpy's default
// method), so p50/p95 here match SCORECARD.md exactly. `p` is in [0, 1].
function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const rank = (sorted.length - 1) * p;
  const low = Math.floor(rank);
  const high = Math.ceil(rank);
  if (low === high) return sorted[low];
  return sorted[low] + (sorted[high] - sorted[low]) * (rank - low);
}

export interface GoldenMetrics {
  total: number;
  passed: number;
  passRate: number;
  severityWithin1: number;
  meanCveRecall: number;
  conformant: number;
  cases: Array<{
    id: string;
    query: string;
    passed: boolean;
    severity: string;
    expectedSeverity: string | null;
    cveRecall: number;
    kevOk: boolean;
    confidence: string;
    notes: string[];
  }>;
}

export interface EfficiencyMetrics {
  p50Seconds: number;
  p95Seconds: number;
  meanInputTokens: number;
  meanOutputTokens: number;
  meanCostUsd: number;
}

export interface CalibrationBin {
  confidence: string;
  predictedProb: number;
  count: number;
  observedAccuracy: number | null;
}

export interface CalibrationMetrics {
  bins: CalibrationBin[];
  ece: number;
}

export function goldenMetrics(): GoldenMetrics {
  const total = evalCases.length;
  const passed = evalCases.filter((c) => c.verdict.passed).length;
  const severityWithin1 = evalCases.filter((c) => c.verdict.severity_ok).length;
  const conformant = evalCases.filter((c) => c.conformant).length;
  const meanCveRecall =
    total === 0 ? 0 : evalCases.reduce((s, c) => s + c.verdict.cve_recall, 0) / total;
  return {
    total,
    passed,
    passRate: total === 0 ? 0 : passed / total,
    severityWithin1,
    meanCveRecall,
    conformant,
    cases: evalCases.map((c) => ({
      id: c.id,
      query: c.query,
      passed: c.verdict.passed,
      severity: c.severity,
      expectedSeverity: c.expected_severity,
      cveRecall: c.verdict.cve_recall,
      kevOk: c.verdict.kev_ok,
      confidence: c.confidence,
      notes: c.verdict.notes,
    })),
  };
}

export function efficiencyMetrics(): EfficiencyMetrics {
  const secs = evalCases.map((c) => c.elapsed_seconds).sort((a, b) => a - b);
  const n = evalCases.length || 1;
  const meanInputTokens =
    evalCases.reduce((s, c) => s + (c.usage.input_tokens ?? 0), 0) / n;
  const meanOutputTokens =
    evalCases.reduce((s, c) => s + (c.usage.output_tokens ?? 0), 0) / n;
  const meanCostUsd = evalCases.reduce((s, c) => s + (c.usage.cost_usd ?? 0), 0) / n;
  return {
    p50Seconds: percentile(secs, 0.5),
    p95Seconds: percentile(secs, 0.95),
    meanInputTokens,
    meanOutputTokens,
    meanCostUsd,
  };
}

// Discrete calibration over the confidence enum (3 bins), not a smooth curve:
// the model emits a categorical confidence, so a reliability diagram with one
// point per confidence level is the honest representation. ECE weights each
// bin by its share of cases.
export function calibrationMetrics(): CalibrationMetrics {
  const order = ["high", "medium", "low"];
  const n = evalCases.length || 1;
  const bins: CalibrationBin[] = order.map((conf) => {
    const inBin = evalCases.filter((c) => c.confidence === conf);
    const observedAccuracy =
      inBin.length === 0
        ? null
        : inBin.filter((c) => c.verdict.passed).length / inBin.length;
    return {
      confidence: conf,
      predictedProb: CONFIDENCE_PROB[conf],
      count: inBin.length,
      observedAccuracy,
    };
  });
  const ece = bins.reduce((acc, b) => {
    if (b.observedAccuracy === null || b.count === 0) return acc;
    return acc + (b.count / n) * Math.abs(b.predictedProb - b.observedAccuracy);
  }, 0);
  return { bins, ece };
}

export function redteamMetrics(): RedteamSnapshot {
  return redteam;
}

export function retrievalMetrics(): RetrievalSnapshot {
  return retrieval;
}
