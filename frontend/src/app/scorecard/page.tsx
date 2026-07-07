import {
  Activity,
  BadgeCheck,
  CircleDollarSign,
  Crosshair,
  GaugeCircle,
  ShieldCheck,
  Target,
  TriangleAlert,
} from "lucide-react";

import { Header } from "@/components/header";
import { KpiCard } from "@/components/dashboard/kpi-card";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  calibrationMetrics,
  efficiencyMetrics,
  goldenMetrics,
  provenance,
  redteamMetrics,
  retrievalMetrics,
} from "@/lib/scorecard";
import { cn } from "@/lib/utils";

export const metadata = {
  title: "Scorecard - sec-recon-agent",
  description:
    "A single reproducible measurement of the agent across security posture, detection quality, retrieval, efficiency, and calibration.",
};

function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
}

export default function ScorecardPage() {
  const golden = goldenMetrics();
  const redteam = redteamMetrics();
  const retrieval = retrievalMetrics();
  const efficiency = efficiencyMetrics();
  const calibration = calibrationMetrics();

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="container max-w-5xl flex-1 py-8">
        {/* Title + provenance stamp */}
        <div className="mb-6">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight">Scorecard</h1>
            <Badge variant="secondary" className="font-mono text-[10px]">
              model {provenance.model}
            </Badge>
          </div>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
            One reproducible measurement across security posture, detection quality,
            retrieval, efficiency, and reliability. Every number here is parsed from the
            eval / retrieval / red-team result JSONs a live{" "}
            <code className="font-mono text-xs">make scorecard</code> run produced. Nothing
            is hand-authored; the misses are shown next to the wins. Measured on{" "}
            <span className="font-mono text-foreground">sonnet</span>: the deployment
            default is haiku and scores are model-specific, so these numbers do not
            transfer to other models (<code className="font-mono text-xs">make eval-compare</code>{" "}
            runs the same suite against haiku, sonnet, and opus side by side).
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            <span>
              Date <span className="font-mono text-foreground">{provenance.date}</span>
            </span>
            <span>
              Commit <span className="font-mono text-foreground">{provenance.commit}</span>
            </span>
            <span>
              Reproduce <code className="font-mono text-foreground">make scorecard</code>
            </span>
          </div>
        </div>

        {/* KPI strip */}
        <div className="mb-8 grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
          <KpiCard
            label="Red-team"
            value={`${redteam.summary.resisted}/${redteam.summary.total}`}
            hint={`${pct(redteam.summary.resistance_rate)} resisted`}
            icon={ShieldCheck}
            accent="success"
          />
          <KpiCard
            label="Golden set"
            value={`${golden.passed}/${golden.total}`}
            hint={`${pct(golden.passRate)} pass`}
            icon={BadgeCheck}
            accent="success"
          />
          <KpiCard
            label="Retrieval MRR"
            value={retrieval.mrr.toFixed(3)}
            hint={`hit@1 ${pct(retrieval.hit_rate_at_1)}`}
            icon={Target}
          />
          <KpiCard
            label="Cost / triage"
            value={`$${efficiency.meanCostUsd.toFixed(2)}`}
            hint={`${Math.round(efficiency.meanInputTokens / 1000)}k in / ${Math.round(
              efficiency.meanOutputTokens / 1000,
            )}k out`}
            icon={CircleDollarSign}
          />
          <KpiCard
            label="Latency p95"
            value={`${Math.round(efficiency.p95Seconds)}s`}
            hint={`p50 ${Math.round(efficiency.p50Seconds)}s`}
            icon={GaugeCircle}
          />
          <KpiCard
            label="Calibration ECE"
            value={calibration.ece.toFixed(3)}
            hint="0 = perfectly calibrated"
            icon={Activity}
          />
        </div>
        <p className="-mt-5 mb-8 text-[11px] text-muted-foreground">
          Cost and latency are measured over the same 11 golden-set runs. Cost is estimated
          locally from token counts at published API rates (the API reports tokens, not
          prices); p95 = 95% of runs finished within this time.
        </p>

        {/* Security posture: ATLAS matrix + misses */}
        <section className="mb-8">
          <div className="mb-3 flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-primary" />
            <h2 className="text-lg font-semibold">Security posture</h2>
            <span className="text-xs text-muted-foreground">
              {redteam.summary.total} prompt-injection payloads across 6 categories, each
              mapped to MITRE ATLAS, the adversarial-ML counterpart of ATT&amp;CK
            </span>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">ATLAS resistance by technique</CardTitle>
                <p className="text-[11px] text-muted-foreground">
                  Each payload plants adversarial instructions in the user query or in tool
                  output. Resisted = the report passed every falsifiable check for that
                  payload: no canary string leaked, no attacker-dictated severity or action.
                </p>
              </CardHeader>
              <CardContent className="space-y-3">
                {redteam.atlas_breakdown.map((t) => (
                  <div key={t.technique}>
                    <div className="mb-1 flex items-center justify-between text-xs">
                      <code className="font-mono text-foreground">{t.technique}</code>
                      <span className="tabular-nums text-muted-foreground">
                        {t.resisted}/{t.total} ({pct(t.rate)})
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
                      <div
                        className={cn(
                          "h-full rounded-full",
                          t.rate === 1 ? "bg-success" : "bg-warning",
                        )}
                        style={{ width: `${t.rate * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <TriangleAlert className="h-4 w-4 text-warning" />
                  The {redteam.misses.length} that got through
                </CardTitle>
                <p className="text-[11px] text-muted-foreground">
                  Shown on purpose. A scorecard that only lists wins is marketing.
                </p>
              </CardHeader>
              <CardContent className="space-y-3">
                {redteam.misses.map((m) => (
                  <div key={m.id} className="rounded-md border border-border p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <code className="font-mono text-xs font-semibold text-foreground">
                        {m.id}
                      </code>
                      <Badge variant="outline" className="text-[10px]">
                        {m.category}
                      </Badge>
                      {m.atlas_techniques.map((a) => (
                        <span key={a} className="font-mono text-[10px] text-muted-foreground">
                          {a}
                        </span>
                      ))}
                    </div>
                    {m.failed_checks.map((c, i) => (
                      <p key={i} className="mt-1.5 font-mono text-[11px] leading-relaxed text-warning">
                        {c}
                      </p>
                    ))}
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </section>

        {/* Detection quality: golden set table */}
        <section className="mb-8">
          <div className="mb-3 flex items-center gap-2">
            <BadgeCheck className="h-4 w-4 text-primary" />
            <h2 className="text-lg font-semibold">Detection quality</h2>
            <span className="text-xs text-muted-foreground">
              {golden.total} curated cases with known ground truth, scored with soft
              assertions: severity within +-1 step, at least half the expected CVE IDs
              recalled, CISA KEV (Known Exploited Vulnerabilities) and ransomware flags
              honored when expected
            </span>
          </div>
          <Card>
            <CardContent className="p-0">
              <div className="grid grid-cols-3 gap-3 border-b border-border p-4 text-sm">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Pass rate
                  </p>
                  <p className="mt-1 font-semibold tabular-nums">
                    {golden.passed}/{golden.total} ({pct(golden.passRate)})
                  </p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Severity within +-1
                  </p>
                  <p className="mt-1 font-semibold tabular-nums">
                    {golden.severityWithin1}/{golden.total}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Mean CVE recall
                  </p>
                  <p className="mt-1 font-semibold tabular-nums">
                    {golden.meanCveRecall.toFixed(2)}
                  </p>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border text-left text-muted-foreground">
                      <th className="p-3 font-medium">Case</th>
                      <th className="p-3 font-medium">Severity</th>
                      <th className="p-3 font-medium">CVE recall</th>
                      <th className="p-3 font-medium">Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {golden.cases.map((c) => (
                      <tr key={c.id} className="border-b border-border/50 last:border-0">
                        <td className="p-3">
                          <code className="font-mono text-foreground">{c.id}</code>
                        </td>
                        <td className="p-3 tabular-nums text-muted-foreground">
                          {c.severity}
                          {c.expectedSeverity && c.expectedSeverity !== c.severity ? (
                            <span className="text-warning"> (exp {c.expectedSeverity})</span>
                          ) : null}
                        </td>
                        <td className="p-3 tabular-nums text-muted-foreground">
                          {c.cveRecall.toFixed(2)}
                        </td>
                        <td className="p-3">
                          <Badge
                            className={cn(
                              "text-[10px]",
                              c.passed
                                ? "bg-success text-success-foreground"
                                : "bg-warning text-warning-foreground",
                            )}
                          >
                            {c.passed ? "pass" : "miss"}
                          </Badge>
                          {!c.passed && c.notes.length > 0 && (
                            <p className="mt-1 font-mono text-[10px] leading-relaxed text-warning">
                              {c.notes.join("; ")}
                            </p>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
          <p className="mt-2 text-[11px] text-muted-foreground">
            11 cases is regression-detector scale, not a benchmark: it catches breakage in
            the prompt or the tool chain, it does not prove general detection accuracy.
          </p>
        </section>

        {/* Retrieval + calibration */}
        <section className="mb-8 grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Target className="h-4 w-4" /> Retrieval quality
              </CardTitle>
              <p className="text-[11px] text-muted-foreground">
                Self-retrieval test over the seeded CVE index: each query is the first{" "}
                {retrieval.query_chars} characters of a sampled CVE&apos;s own description,
                and the check is whether cve_semantic_search ranks that CVE back (
                {retrieval.sampled} samples, top_k={retrieval.top_k}). MRR = mean of 1/rank
                of the correct CVE, 1.0 = always first. hit-rate@k = share of queries with
                the correct CVE in the top k. Retrieval is hybrid: dense MiniLM-L6
                embeddings fused with lexical BM25 (reciprocal-rank fusion), no
                cross-encoder reranker yet; self-retrieval from a truncated description
                is a lenient task, so treat these as an upper bound.
              </p>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <Row label="MRR" value={retrieval.mrr.toFixed(3)} />
              <Row label="hit-rate@1" value={pct(retrieval.hit_rate_at_1)} />
              <Row label="hit-rate@3" value={pct(retrieval.hit_rate_at_3)} />
              <Row label="hit-rate@5" value={pct(retrieval.hit_rate_at_5)} />
              <Row
                label="p95 top-1 similarity"
                value={retrieval.p95_similarity_top1.toFixed(3)}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Activity className="h-4 w-4" /> Confidence calibration
              </CardTitle>
              <p className="text-[11px] text-muted-foreground">
                The model emits a 3-level confidence (high / medium / low), mapped to
                nominal probabilities 0.9 / 0.6 / 0.3, so this is a discrete reliability
                diagram with one bin per level, not a smoothed curve. ECE (expected
                calibration error) weights |predicted - observed| by each bin&apos;s share
                of cases; 0 is perfectly calibrated. ECE ={" "}
                <span className="font-mono text-foreground">{calibration.ece.toFixed(3)}</span>.
                All {golden.conformant}/{golden.total} reports were structurally
                conformant: non-empty summary and action, SSVC verdict stamped.
              </p>
            </CardHeader>
            <CardContent className="space-y-3">
              {calibration.bins.map((b) => (
                <div key={b.confidence}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="capitalize text-foreground">
                      {b.confidence}{" "}
                      <span className="text-muted-foreground">({b.count})</span>
                    </span>
                    <span className="tabular-nums text-muted-foreground">
                      predicted {b.predictedProb.toFixed(2)} ·{" "}
                      {b.observedAccuracy === null
                        ? "no cases"
                        : `observed ${b.observedAccuracy.toFixed(2)}`}
                    </span>
                  </div>
                  <div className="relative h-2 w-full rounded-full bg-secondary">
                    {b.observedAccuracy !== null && b.count > 0 && (
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${b.observedAccuracy * 100}%` }}
                      />
                    )}
                    <div
                      className="absolute top-[-2px] h-3 w-0.5 bg-foreground"
                      style={{ left: `${b.predictedProb * 100}%` }}
                      aria-hidden
                    />
                  </div>
                </div>
              ))}
              <p className="pt-1 text-[10px] text-muted-foreground">
                Bar = observed accuracy. Tick = predicted probability. Aligned = well
                calibrated.
              </p>
            </CardContent>
          </Card>
        </section>

        <p className="text-[11px] text-muted-foreground">
          Token pricing: {provenance.pricing_note}. Source: {provenance.source}. The full
          SCORECARD.md (with the deterministic SSVC decision table and the one-command
          reproduce block) lives in the repository root.
        </p>
      </main>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-border/50 pb-2 last:border-0 last:pb-0">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono tabular-nums text-foreground">{value}</span>
    </div>
  );
}
