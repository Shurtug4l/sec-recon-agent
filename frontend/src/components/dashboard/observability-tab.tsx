"use client";

import { useState } from "react";
import { Activity, AlertTriangle, Clock, ExternalLink } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { buildWaterfall, formatDuration } from "@/lib/stats";
import { cn } from "@/lib/utils";
import type { HistoryEntry, Severity } from "@/lib/types";

// Local Jaeger UI. Env-configurable; defaults to the compose sidecar port and
// is only reachable when the stack runs with the observability profile.
const JAEGER_URL = process.env.NEXT_PUBLIC_JAEGER_URL ?? "http://localhost:16686";

const severityClass: Record<Severity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

export function ObservabilityTab({ entries }: { entries: HistoryEntry[] }) {
  const [selectedId, setSelectedId] = useState<string | null>(entries[0]?.id ?? null);

  if (entries.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No runs to inspect yet.
        </CardContent>
      </Card>
    );
  }

  const selected = entries.find((e) => e.id === selectedId) ?? entries[0];
  const waterfall = buildWaterfall(selected);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[260px_1fr]">
      <Card className="lg:max-h-[calc(100vh-200px)]">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Runs ({entries.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 overflow-auto p-2">
          {entries.map((entry) => (
            <button
              key={entry.id}
              type="button"
              onClick={() => setSelectedId(entry.id)}
              className={cn(
                "w-full rounded-md p-2.5 text-left transition-colors hover:bg-accent",
                selected.id === entry.id && "bg-accent",
              )}
            >
              <p className="line-clamp-1 text-xs font-medium">{entry.query || "(empty)"}</p>
              <div className="mt-1 flex items-center gap-2">
                {entry.report ? (
                  <Badge className={cn("text-[9px] uppercase", severityClass[entry.report.severity])}>
                    {entry.report.severity}
                  </Badge>
                ) : entry.error ? (
                  <Badge variant="destructive" className="text-[9px]">error</Badge>
                ) : (
                  <Badge variant="secondary" className="text-[9px]">pending</Badge>
                )}
                {entry.durationMs !== null && (
                  <span className="text-[9px] tabular-nums text-muted-foreground">
                    {formatDuration(entry.durationMs)}
                  </span>
                )}
              </div>
            </button>
          ))}
        </CardContent>
      </Card>

      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="line-clamp-1 text-base">
              {selected.query || "(empty query)"}
            </CardTitle>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <span>{new Date(selected.startedAt).toLocaleString()}</span>
              {selected.durationMs !== null && (
                <span className="inline-flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatDuration(selected.durationMs)}
                </span>
              )}
              {selected.report && (
                <Badge className={cn("text-[10px] uppercase", severityClass[selected.report.severity])}>
                  {selected.report.severity}
                </Badge>
              )}
            </div>
          </CardHeader>
        </Card>

        {selected.error && (
          <Card className="border-destructive">
            <CardContent className="flex items-start gap-2 p-4 text-sm">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
              <span className="font-mono text-xs">{selected.error}</span>
            </CardContent>
          </Card>
        )}

        {selected.report &&
          (waterfall.length > 0 ? (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Activity className="h-4 w-4" /> Node waterfall
                </CardTitle>
                <p className="text-[11px] text-muted-foreground">
                  One segment per step of the agent graph: prompt, model request, tool
                  calls, final output. Measured client-side from the arrival time of each
                  streamed <code className="font-mono">node</code> event; segment widths
                  are real elapsed time between events, not inferred.
                </p>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="relative h-8 w-full overflow-hidden rounded-md bg-muted">
                  {waterfall.map((seg, i) => (
                    <div
                      key={seg.index}
                      className={cn(
                        "absolute top-0 h-full border-r border-background",
                        i % 2 === 0 ? "bg-primary/40" : "bg-primary/60",
                      )}
                      style={{ left: `${seg.startPct}%`, width: `${Math.max(seg.widthPct, 0.5)}%` }}
                      title={`${seg.label} · ${formatDuration(seg.durationMs)}`}
                    />
                  ))}
                </div>
                <ol className="space-y-1.5 text-sm">
                  {waterfall.map((seg) => (
                    <li
                      key={seg.index}
                      className="flex items-center gap-3 rounded-md px-2 py-1.5 transition-colors hover:bg-accent"
                    >
                      <span className="select-none font-mono text-xs text-muted-foreground">
                        {(seg.index + 1).toString().padStart(2, "0")}
                      </span>
                      <span className="leading-relaxed">{seg.label}</span>
                      <span className="ml-auto font-mono text-xs tabular-nums text-muted-foreground">
                        {formatDuration(seg.durationMs)}
                      </span>
                    </li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="py-4 text-center text-xs text-muted-foreground">
                Per-node timing was not captured for this run (it predates timing capture).
                Run a new triage to see the measured waterfall.
              </CardContent>
            </Card>
          ))}

        {selected.usage && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Token usage</CardTitle>
              <p className="text-[11px] text-muted-foreground">
                Reported by the model provider for this run (via the{" "}
                <code className="font-mono">usage</code> SSE event).
              </p>
            </CardHeader>
            <CardContent className="grid grid-cols-3 gap-3">
              <UsageStat label="input tokens" value={selected.usage.input_tokens} />
              <UsageStat label="output tokens" value={selected.usage.output_tokens} />
              <UsageStat label="model requests" value={selected.usage.requests} />
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Distributed traces</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="text-muted-foreground">
              The waterfall above is the client-side view. The full server-side picture
              (per-call latency, span attributes, and the cross-process trace tree) is
              exported via OpenTelemetry to Jaeger, reachable only on a local stack started
              with the observability profile (<code className="font-mono">make obs-up</code>):
            </p>
            <a
              href={JAEGER_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
            >
              {JAEGER_URL}
              <ExternalLink className="h-3 w-3" />
            </a>
            <p className="text-[11px] text-muted-foreground">
              Local-only link; not available on a hosted demo. Override with{" "}
              <code className="font-mono">NEXT_PUBLIC_JAEGER_URL</code>.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function UsageStat({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="rounded-md border border-border p-3">
      <p className="font-mono text-lg font-semibold tabular-nums text-primary">
        {value !== null ? value.toLocaleString() : "n/a"}
      </p>
      <p className="mt-0.5 text-[11px] text-muted-foreground">{label}</p>
    </div>
  );
}
