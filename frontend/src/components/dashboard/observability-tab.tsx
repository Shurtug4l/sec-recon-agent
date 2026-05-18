"use client";

import { useState } from "react";
import { Activity, AlertTriangle, Clock, ExternalLink } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDuration, reconstructTimeline } from "@/lib/stats";
import { cn } from "@/lib/utils";
import type { HistoryEntry, Severity } from "@/lib/types";

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
  const timeline = reconstructTimeline(selected);

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

        {timeline.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Activity className="h-4 w-4" /> Reasoning timeline
              </CardTitle>
              <p className="text-[11px] text-muted-foreground">
                Step boundaries inferred from <code className="font-mono">reasoning_chain</code> length and total runtime; intermediate node events are not persisted in history.
              </p>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="relative h-8 w-full overflow-hidden rounded-md bg-muted">
                {timeline.map((step, i) => (
                  <div
                    key={step.index}
                    className={cn(
                      "absolute top-0 h-full border-r border-background",
                      i % 2 === 0 ? "bg-primary/40" : "bg-primary/60",
                    )}
                    style={{ left: `${step.startPct}%`, width: `${step.widthPct}%` }}
                    title={step.label}
                  />
                ))}
              </div>
              <ol className="space-y-1.5 text-sm">
                {timeline.map((step) => (
                  <li
                    key={step.index}
                    className="flex gap-3 rounded-md px-2 py-1.5 transition-colors hover:bg-accent"
                  >
                    <span className="select-none font-mono text-xs text-muted-foreground">
                      {(step.index + 1).toString().padStart(2, "0")}
                    </span>
                    <span className="leading-relaxed">{step.label}</span>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Distributed traces</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="text-muted-foreground">
              Per-call latency, span attributes, and the cross-process trace tree are exported
              via OpenTelemetry. When the stack runs with the observability profile, you can
              inspect them in Jaeger:
            </p>
            <a
              href="http://localhost:16686"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
            >
              http://localhost:16686
              <ExternalLink className="h-3 w-3" />
            </a>
            <p className="text-[11px] text-muted-foreground">
              Run <code className="font-mono">make obs-up</code> to start the Jaeger sidecar.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
