"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  BadgeCheck,
  CircleDollarSign,
  Crosshair,
  ShieldCheck,
  Target,
  TriangleAlert,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  calibrationMetrics,
  efficiencyMetrics,
  goldenMetrics,
  perCaseEfficiency,
  redteamMetrics,
  retrievalMetrics,
} from "@/lib/scorecard";
import { cn } from "@/lib/utils";

// The scorecard as five tabbed bands behind an always-visible KPI row: the
// KPI cards ARE the tabs (the summary row doubles as navigation), so the
// route reads in one viewport instead of the former five-section column.
// Same tab contract as the dashboard: ?tab= deep link, roving tabindex,
// arrow-key navigation.

type Band = "security" | "detection" | "retrieval" | "efficiency" | "calibration";

const BAND_KEYS: Band[] = ["security", "detection", "retrieval", "efficiency", "calibration"];

function isBand(value: string | null): value is Band {
  return value !== null && (BAND_KEYS as string[]).includes(value);
}

function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
}

export function ScorecardBands() {
  const golden = goldenMetrics();
  const redteam = redteamMetrics();
  const retrieval = retrievalMetrics();
  const efficiency = efficiencyMetrics();
  const calibration = calibrationMetrics();
  const cases = perCaseEfficiency();

  const [band, setBand] = useState<Band>("security");
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  // Deep-link: hydrate the active band from ?tab= on mount. Reading the query
  // directly (not useSearchParams) keeps the page statically prerenderable.
  useEffect(() => {
    const fromUrl = new URLSearchParams(window.location.search).get("tab");
    if (isBand(fromUrl)) setBand(fromUrl);
  }, []);

  const selectBand = useCallback((next: Band) => {
    setBand(next);
    const url = new URL(window.location.href);
    url.searchParams.set("tab", next);
    window.history.replaceState(null, "", url);
  }, []);

  function onTabKeyDown(event: React.KeyboardEvent) {
    const current = BAND_KEYS.indexOf(band);
    let nextIndex: number;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        nextIndex = (current + 1) % BAND_KEYS.length;
        break;
      case "ArrowLeft":
      case "ArrowUp":
        nextIndex = (current - 1 + BAND_KEYS.length) % BAND_KEYS.length;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = BAND_KEYS.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    selectBand(BAND_KEYS[nextIndex]);
    tabRefs.current[nextIndex]?.focus();
  }

  const tabs: Array<{
    key: Band;
    label: string;
    value: string;
    hint: string;
    icon: React.ElementType;
    accent?: "success";
  }> = [
    {
      key: "security",
      label: "Red-team",
      value: `${redteam.summary.resisted}/${redteam.summary.total}`,
      hint: `${pct(redteam.summary.resistance_rate)} resisted`,
      icon: ShieldCheck,
      accent: "success",
    },
    {
      key: "detection",
      label: "Golden set",
      value: `${golden.passed}/${golden.total}`,
      hint: `${pct(golden.passRate)} pass`,
      icon: BadgeCheck,
      accent: "success",
    },
    {
      key: "retrieval",
      label: "Retrieval MRR",
      value: retrieval.mrr.toFixed(3),
      hint: `hit@1 ${pct(retrieval.hit_rate_at_1)}`,
      icon: Target,
    },
    {
      key: "efficiency",
      label: "Cost / triage",
      value: `$${efficiency.meanCostUsd.toFixed(2)}`,
      hint: `p95 latency ${Math.round(efficiency.p95Seconds)}s`,
      icon: CircleDollarSign,
    },
    {
      key: "calibration",
      label: "Calibration ECE",
      value: calibration.ece.toFixed(3),
      hint: "0 = perfectly calibrated",
      icon: Activity,
    },
  ];

  return (
    <div>
      {/* KPI row = tab rail. Each card is a tab; the active band gets the
          signal border. */}
      <div
        role="tablist"
        aria-label="Scorecard bands"
        onKeyDown={onTabKeyDown}
        className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5"
      >
        {tabs.map(({ key, label, value, hint, icon: Icon, accent }, i) => {
          const active = band === key;
          return (
            <button
              key={key}
              ref={(el) => {
                tabRefs.current[i] = el;
              }}
              type="button"
              role="tab"
              id={`tab-${key}`}
              aria-selected={active}
              aria-controls={`panel-${key}`}
              tabIndex={active ? 0 : -1}
              onClick={() => selectBand(key)}
              className={cn(
                "rounded-lg border bg-card p-4 text-left transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
                active
                  ? "border-primary"
                  : "border-border hover:border-muted-foreground/40",
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-1">
                  <p
                    className={cn(
                      "text-xs font-medium uppercase tracking-wider",
                      active ? "text-primary" : "text-muted-foreground",
                    )}
                  >
                    {label}
                  </p>
                  <p
                    className={cn(
                      "font-display text-2xl font-semibold",
                      accent === "success" ? "text-success" : "text-foreground",
                    )}
                  >
                    {value}
                  </p>
                  <p className="text-[10px] text-muted-foreground">{hint}</p>
                </div>
                <Icon
                  className={cn(
                    "h-5 w-5 shrink-0",
                    active ? "text-primary" : "text-muted-foreground",
                  )}
                />
              </div>
            </button>
          );
        })}
      </div>

      {BAND_KEYS.map((key) => (
        <div
          key={key}
          role="tabpanel"
          id={`panel-${key}`}
          aria-labelledby={`tab-${key}`}
          tabIndex={0}
          hidden={band !== key}
          className="focus-visible:outline-none"
        >
          {band === key && key === "security" && <SecurityBand redteam={redteam} />}
          {band === key && key === "detection" && <DetectionBand golden={golden} />}
          {band === key && key === "retrieval" && <RetrievalBand retrieval={retrieval} />}
          {band === key && key === "efficiency" && (
            <EfficiencyBand efficiency={efficiency} cases={cases} />
          )}
          {band === key && key === "calibration" && (
            <CalibrationBand calibration={calibration} golden={golden} />
          )}
        </div>
      ))}
    </div>
  );
}

function BandHeader({
  icon: Icon,
  title,
  gloss,
}: {
  icon: React.ElementType;
  title: string;
  gloss: string;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-baseline gap-x-2 gap-y-1">
      <Icon className="h-4 w-4 self-center text-primary" aria-hidden />
      <h2 className="text-lg font-semibold">{title}</h2>
      <span className="text-xs text-muted-foreground">{gloss}</span>
    </div>
  );
}

// Meter row: thin fill on a lighter step of the SAME hue as track, 4px
// rounded data-end, square at the left baseline. Value always visible on the
// right; the fill is reinforcement, never the only channel.
function MeterRow({
  label,
  valueText,
  fraction,
  tone = "primary",
  annotation,
}: {
  label: React.ReactNode;
  valueText: string;
  fraction: number;
  tone?: "primary" | "success" | "warning";
  annotation?: string;
}) {
  const fillClass = { primary: "bg-primary", success: "bg-success", warning: "bg-warning" }[tone];
  const trackClass = {
    primary: "bg-primary/15",
    success: "bg-success/15",
    warning: "bg-warning/15",
  }[tone];
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2 text-xs">
        <span className="min-w-0 truncate">{label}</span>
        <span className="shrink-0 font-mono tabular-nums text-muted-foreground">{valueText}</span>
      </div>
      <div className={cn("h-2 w-full overflow-hidden rounded-[4px]", trackClass)}>
        <div
          className={cn("h-full rounded-r-[4px]", fillClass)}
          style={{ width: `${Math.max(0, Math.min(1, fraction)) * 100}%` }}
        />
      </div>
      {annotation && (
        <p className="mt-1 font-mono text-[10px] leading-relaxed text-warning">{annotation}</p>
      )}
    </div>
  );
}

function SecurityBand({ redteam }: { redteam: ReturnType<typeof redteamMetrics> }) {
  return (
    <section>
      <BandHeader
        icon={Crosshair}
        title="Security posture"
        gloss={`${redteam.summary.total} prompt-injection payloads across 6 categories, each mapped to MITRE ATLAS, the adversarial-ML counterpart of ATT&CK`}
      />
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
              <MeterRow
                key={t.technique}
                label={<code className="font-mono text-foreground">{t.technique}</code>}
                valueText={`${t.resisted}/${t.total} (${pct(t.rate)})`}
                fraction={t.rate}
                tone={t.rate === 1 ? "success" : "warning"}
                annotation={
                  t.rate < 1 ? `${t.total - t.resisted} got through, detailed alongside` : undefined
                }
              />
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
                  <code className="font-mono text-xs font-semibold text-foreground">{m.id}</code>
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
  );
}

function DetectionBand({ golden }: { golden: ReturnType<typeof goldenMetrics> }) {
  return (
    <section>
      <BandHeader
        icon={BadgeCheck}
        title="Detection quality"
        gloss={`${golden.total} curated cases with known ground truth, scored with soft assertions: severity within +-1 step, at least half the expected CVE IDs recalled, CISA KEV (Known Exploited Vulnerabilities) and ransomware flags honored when expected`}
      />
      <Card>
        <CardContent className="p-0">
          <div className="grid grid-cols-3 gap-3 border-b border-border p-4 text-sm">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Pass rate
              </p>
              <p className="mt-1 font-semibold">
                {golden.passed}/{golden.total} ({pct(golden.passRate)})
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Severity within +-1
              </p>
              <p className="mt-1 font-semibold">
                {golden.severityWithin1}/{golden.total}
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Mean CVE recall
              </p>
              <p className="mt-1 font-semibold">{golden.meanCveRecall.toFixed(2)}</p>
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
  );
}

function RetrievalBand({ retrieval }: { retrieval: ReturnType<typeof retrievalMetrics> }) {
  const missedTop5 = Math.round((1 - retrieval.hit_rate_at_5) * retrieval.sampled);
  return (
    <section>
      <BandHeader
        icon={Target}
        title="Retrieval quality"
        gloss={`self-retrieval over the seeded CVE index, ${retrieval.sampled} samples, top_k=${retrieval.top_k}`}
      />
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Ranking metrics</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              All metrics are in [0, 1]; the bars share that scale, so the hit-rate@k
              staircase reads directly.
            </p>
          </CardHeader>
          <CardContent className="space-y-3">
            <MeterRow label="MRR" valueText={retrieval.mrr.toFixed(3)} fraction={retrieval.mrr} />
            <MeterRow
              label="hit-rate@1"
              valueText={pct(retrieval.hit_rate_at_1)}
              fraction={retrieval.hit_rate_at_1}
            />
            <MeterRow
              label="hit-rate@3"
              valueText={pct(retrieval.hit_rate_at_3)}
              fraction={retrieval.hit_rate_at_3}
            />
            <MeterRow
              label="hit-rate@5"
              valueText={pct(retrieval.hit_rate_at_5)}
              fraction={retrieval.hit_rate_at_5}
              annotation={
                missedTop5 > 0
                  ? `${missedTop5} of ${retrieval.sampled} queries never rank the CVE in the top 5`
                  : undefined
              }
            />
            <MeterRow
              label="p95 top-1 similarity"
              valueText={retrieval.p95_similarity_top1.toFixed(3)}
              fraction={retrieval.p95_similarity_top1}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">How to read this</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-[11px] leading-relaxed text-muted-foreground">
            <p>
              Each query is the first {retrieval.query_chars} characters of a sampled
              CVE&apos;s own description, and the check is whether cve_semantic_search
              ranks that CVE back. MRR = mean of 1/rank of the correct CVE, 1.0 = always
              first. hit-rate@k = share of queries with the correct CVE in the top k.
            </p>
            <p>
              Retrieval is hybrid: dense MiniLM-L6 embeddings fused with lexical BM25
              (reciprocal-rank fusion), no cross-encoder reranker yet. Self-retrieval
              from a truncated description is a lenient task, so treat these numbers as
              an upper bound.
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

// Dot strip: one dot per golden run on a shared linear scale, annotated with
// the aggregate markers (p50/p95 or mean) so the percentile headline and the
// distribution it summarizes sit on the same line. Values stay reachable
// without hover via the per-case table below.
function DistributionStrip({
  points,
  markers,
  format,
}: {
  points: Array<{ id: string; value: number }>;
  markers: Array<{ label: string; value: number }>;
  format: (v: number) => string;
}) {
  const max = Math.max(...points.map((p) => p.value), ...markers.map((m) => m.value)) * 1.08;
  return (
    <div className="relative mt-6 h-12">
      {/* hairline baseline */}
      <div className="absolute left-0 right-0 top-7 h-px bg-border" aria-hidden />
      {markers.map((m) => (
        <div
          key={m.label}
          className="absolute top-1"
          style={{ left: `${(m.value / max) * 100}%` }}
          aria-hidden
        >
          <span className="absolute -translate-x-1/2 -translate-y-full whitespace-nowrap font-mono text-[10px] text-muted-foreground">
            {m.label} {format(m.value)}
          </span>
          <span className="absolute top-1 block h-6 w-px -translate-x-1/2 bg-foreground/50" />
        </div>
      ))}
      {points.map((p) => (
        <span
          key={p.id}
          className="absolute top-7 flex h-6 w-6 -translate-x-1/2 -translate-y-1/2 items-center justify-center"
          style={{ left: `${(p.value / max) * 100}%` }}
          title={`${p.id} · ${format(p.value)}`}
        >
          <span className="h-2.5 w-2.5 rounded-full bg-[hsl(var(--chart-1))] ring-2 ring-card" />
        </span>
      ))}
      <span className="absolute bottom-0 left-0 font-mono text-[10px] text-muted-foreground">
        0
      </span>
      <span className="absolute bottom-0 right-0 font-mono text-[10px] text-muted-foreground">
        {format(max)}
      </span>
    </div>
  );
}

function EfficiencyBand({
  efficiency,
  cases,
}: {
  efficiency: ReturnType<typeof efficiencyMetrics>;
  cases: ReturnType<typeof perCaseEfficiency>;
}) {
  const latencyPoints = cases.map((c) => ({ id: c.id, value: c.seconds }));
  const costPoints = cases
    .filter((c) => c.costUsd !== null)
    .map((c) => ({ id: c.id, value: c.costUsd as number }));
  return (
    <section>
      <BandHeader
        icon={CircleDollarSign}
        title="Efficiency"
        gloss="cost and latency measured over the same 11 golden-set runs; cost is estimated locally from token counts at published API rates (the API reports tokens, not prices)"
      />
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Latency per run</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              One dot per golden case, seconds from request to final report. p95 = 95%
              of runs finished within this time.
            </p>
          </CardHeader>
          <CardContent>
            <DistributionStrip
              points={latencyPoints}
              markers={[
                { label: "p50", value: efficiency.p50Seconds },
                { label: "p95", value: efficiency.p95Seconds },
              ]}
              format={(v) => `${Math.round(v)}s`}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Cost per run</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              Estimated USD per triage; mean {`$${efficiency.meanCostUsd.toFixed(2)}`} with{" "}
              {Math.round(efficiency.meanInputTokens / 1000)}k input /{" "}
              {Math.round(efficiency.meanOutputTokens / 1000)}k output tokens on average.
            </p>
          </CardHeader>
          <CardContent>
            <DistributionStrip
              points={costPoints}
              markers={[{ label: "mean", value: efficiency.meanCostUsd }]}
              format={(v) => `$${v.toFixed(2)}`}
            />
          </CardContent>
        </Card>
      </div>

      <details className="mt-4 rounded-lg border border-border bg-card">
        <summary className="cursor-pointer select-none p-3 text-xs font-medium text-muted-foreground hover:text-foreground">
          Per-case table (the values behind the dots)
        </summary>
        <div className="overflow-x-auto border-t border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="p-3 font-medium">Case</th>
                <th className="p-3 font-medium">Latency</th>
                <th className="p-3 font-medium">Cost</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.id} className="border-b border-border/50 last:border-0">
                  <td className="p-3">
                    <code className="font-mono text-foreground">{c.id}</code>
                  </td>
                  <td className="p-3 font-mono tabular-nums text-muted-foreground">
                    {c.seconds.toFixed(1)}s
                  </td>
                  <td className="p-3 font-mono tabular-nums text-muted-foreground">
                    {c.costUsd !== null ? `$${c.costUsd.toFixed(3)}` : "n/a"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}

function CalibrationBand({
  calibration,
  golden,
}: {
  calibration: ReturnType<typeof calibrationMetrics>;
  golden: ReturnType<typeof goldenMetrics>;
}) {
  return (
    <section>
      <BandHeader
        icon={Activity}
        title="Confidence calibration"
        gloss="a discrete reliability diagram with one bin per confidence level, not a smoothed curve"
      />
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Reliability by confidence level</CardTitle>
            <p className="text-[11px] text-muted-foreground">
              Bar = observed accuracy. Tick = the nominal probability the confidence
              level claims. Aligned = well calibrated; the gap is each bin&apos;s
              contribution to ECE, weighted by its share of cases.
            </p>
          </CardHeader>
          <CardContent className="space-y-4">
            {calibration.bins.map((b) => (
              <div key={b.confidence}>
                <div className="mb-1 flex items-center justify-between text-xs">
                  <span className="capitalize text-foreground">
                    {b.confidence} <span className="text-muted-foreground">({b.count})</span>
                  </span>
                  <span className="font-mono tabular-nums text-muted-foreground">
                    predicted {b.predictedProb.toFixed(2)} ·{" "}
                    {b.observedAccuracy === null
                      ? "no cases"
                      : `observed ${b.observedAccuracy.toFixed(2)}`}
                  </span>
                </div>
                <div className="relative h-2 w-full rounded-[4px] bg-primary/15">
                  {b.observedAccuracy !== null && b.count > 0 && (
                    <div
                      className="h-full rounded-r-[4px] bg-primary"
                      style={{ width: `${b.observedAccuracy * 100}%` }}
                    />
                  )}
                  <div
                    className="absolute top-[-3px] h-3.5 w-0.5 bg-foreground"
                    style={{ left: `${b.predictedProb * 100}%` }}
                    aria-hidden
                  />
                </div>
                {b.observedAccuracy !== null && b.count > 0 && (
                  <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                    gap {Math.abs(b.predictedProb - b.observedAccuracy).toFixed(2)} x weight{" "}
                    {b.count}/{golden.total}
                  </p>
                )}
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">What the number means</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-[11px] leading-relaxed text-muted-foreground">
            <p>
              The model emits a 3-level confidence (high / medium / low), mapped to
              nominal probabilities 0.9 / 0.6 / 0.3. ECE (expected calibration error)
              weights |predicted - observed| by each bin&apos;s share of cases; 0 is
              perfectly calibrated. ECE ={" "}
              <span className="font-mono text-foreground">{calibration.ece.toFixed(3)}</span>{" "}
              here, dominated by the small-sample bins (n={golden.total} is noise scale).
            </p>
            <p>
              All {golden.conformant}/{golden.total} reports were structurally
              conformant: non-empty summary and action, SSVC verdict stamped.
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
