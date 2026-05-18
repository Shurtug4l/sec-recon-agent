"use client";

import { useMemo } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Crosshair,
  ShieldX,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  SeverityBarChart,
  ToolLegend,
  ToolsPieChart,
} from "@/components/dashboard/charts";
import { KpiCard } from "@/components/dashboard/kpi-card";
import { aggregate, formatDuration } from "@/lib/stats";
import type { HistoryEntry } from "@/lib/types";

export function StatisticsTab({ entries }: { entries: HistoryEntry[] }) {
  const stats = useMemo(() => aggregate(entries), [entries]);

  if (entries.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          Run a triage from the home page to populate the dashboard.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="Total runs" value={stats.totalRuns} icon={Activity} />
        <KpiCard
          label="Avg time"
          value={formatDuration(stats.avgDurationMs)}
          hint={`across ${stats.completedRuns} completed`}
          icon={Clock}
        />
        <KpiCard
          label="Critical"
          value={stats.criticalCount}
          hint={`${stats.highCount} high`}
          icon={ShieldX}
          accent="critical"
        />
        <KpiCard
          label="Success rate"
          value={
            stats.totalRuns > 0
              ? `${Math.round((stats.completedRuns / stats.totalRuns) * 100)}%`
              : "—"
          }
          hint={stats.errorRuns > 0 ? `${stats.errorRuns} errored` : "no errors"}
          icon={CheckCircle2}
          accent="success"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Severity distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityBarChart data={stats.bySeverity} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Tool call counts</CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-6">
            <div className="flex-1">
              <ToolsPieChart data={stats.toolCalls} />
            </div>
            <div className="w-44 shrink-0">
              <ToolLegend data={stats.toolCalls} />
            </div>
          </CardContent>
        </Card>
      </div>

      {stats.topCves.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Top CVEs by query frequency</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {stats.topCves.map((cve) => (
              <div
                key={cve.cveId}
                className="flex items-center justify-between rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent"
              >
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-primary hover:underline"
                >
                  {cve.cveId}
                </a>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  {cve.cvss !== null && (
                    <span className="tabular-nums">CVSS {cve.cvss.toFixed(1)}</span>
                  )}
                  <span className="tabular-nums">
                    {cve.count}
                    {cve.count > 1 && " refs"}
                  </span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {stats.topAttackTechniques.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Crosshair className="h-4 w-4" />
              Top ATT&CK techniques
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {stats.topAttackTechniques.map((technique) => (
              <a
                key={technique.id}
                href={technique.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <span className="font-mono text-primary">{technique.id}</span>
                  <span className="truncate">{technique.name}</span>
                </div>
                <div className="flex shrink-0 items-center gap-3 text-xs text-muted-foreground">
                  <span className="hidden truncate sm:inline">
                    {technique.tactics.slice(0, 2).join(", ")}
                  </span>
                  <span className="tabular-nums">
                    {technique.count}
                    {technique.count > 1 && " refs"}
                  </span>
                </div>
              </a>
            ))}
          </CardContent>
        </Card>
      )}

      {stats.errorRuns > 0 && (
        <Card className="border-destructive/40">
          <CardContent className="flex items-center gap-3 p-4">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <p className="text-sm">
              {stats.errorRuns} run{stats.errorRuns > 1 ? "s" : ""} ended in an error.
              Check the observability tab for the timeline.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
