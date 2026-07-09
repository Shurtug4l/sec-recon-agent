"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, ShieldAlert, ShieldCheck } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { loadAudit } from "@/lib/audit";
import type { AuditRow, AuditTrail } from "@/lib/types";
import { cn } from "@/lib/utils";

const GENESIS = "0".repeat(64);

// Reuse the severity ramp utilities (globals.css) for the severity chip so the
// audit view speaks the same color language as the report.
function severityClass(sev: string | null): string {
  switch (sev) {
    case "critical":
      return "severity-critical";
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    default:
      return "severity-info";
  }
}

// Solid fills, verbatim from the report's SsvcVerdict styling (SSVC_META in
// triage-report-view.tsx) so the ladder reads identically wherever it appears.
const SSVC_CLASS: Record<string, string> = {
  Act: "bg-destructive text-destructive-foreground",
  Attend: "bg-warning text-warning-foreground",
  "Track*": "bg-[hsl(var(--severity-low))] text-background",
  Track: "bg-secondary text-foreground",
};

const GROUNDING_CLASS: Record<string, string> = {
  grounded: "text-[hsl(var(--success))]",
  suspect: "text-warning",
  not_evaluated: "text-muted-foreground",
};

function shortTime(ts: string): string {
  // ts is ISO 8601; show date + HH:MM without a Date round-trip.
  const [date, rest] = ts.split("T");
  return `${date} ${(rest ?? "").slice(0, 5)}`;
}

function hashCell(row: AuditRow): { from: string; to: string } {
  return {
    from: row.prev_event_hash === GENESIS ? "genesis" : row.prev_event_hash.slice(0, 8),
    to: row.this_event_hash.slice(0, 8),
  };
}

export function AuditTab() {
  const [trail, setTrail] = useState<AuditTrail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    loadAudit()
      .then((data) => {
        if (!cancelled) setTrail(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load /v1/audit");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <Card className="border-destructive">
        <CardContent className="flex items-start gap-2 p-4 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
          <div>
            <p className="font-medium">Could not load the audit trail</p>
            <p className="mt-1 font-mono text-xs text-muted-foreground">{error}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!trail) {
    return (
      <div className="space-y-4" aria-busy="true">
        <span className="sr-only">Loading the audit trail</span>
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const { verification: v } = trail;
  const verified = v.ok;

  return (
    <div className="space-y-5">
      {/* Chain integrity + the disclosure contract. */}
      <Card className={cn(verified ? "border-[hsl(var(--success)/0.4)]" : "border-destructive")}>
        <CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            {verified ? (
              <ShieldCheck className="mt-0.5 h-6 w-6 shrink-0 text-[hsl(var(--success))]" />
            ) : (
              <ShieldAlert className="mt-0.5 h-6 w-6 shrink-0 text-destructive" />
            )}
            <div>
              <p className="text-sm font-semibold">
                {verified
                  ? `Hash chain verified: ${v.verified_count} / ${trail.count} rows intact`
                  : `Chain broken at ${v.broken_event_id ?? "an event"}`}
              </p>
              <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">
                Every triage seals one append-only row: SHA-256 digests of the query and report,
                aggregate signals, and a <code className="font-mono">prev_event_hash</code> {"->"}{" "}
                <code className="font-mono">this_event_hash</code> link.{" "}
                <code className="font-mono">sec-recon-audit verify</code> walks the chain and this
                view re-checks it live. Digest-only by design: the query and report text never leave
                the database, so nothing sensitive is exposed here.
              </p>
            </div>
          </div>
          <div className="shrink-0 rounded-md border border-border px-3 py-2 text-center">
            <div className="font-display text-2xl tabular-nums">{trail.count}</div>
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
              sealed rows
            </div>
          </div>
        </CardContent>
      </Card>

      {!trail.enabled ? (
        <Card>
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            Audit logging is disabled on this deployment (<code className="font-mono">
              AUDIT_LOG_ENABLED=false
            </code>). Enable it to record a tamper-evident row per triage.
          </CardContent>
        </Card>
      ) : trail.events.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            No triages recorded yet. Run one and it lands here, sealed into the chain.
          </CardContent>
        </Card>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/50 text-left">
                <th className="whitespace-nowrap px-3 py-2 font-medium">Time (UTC)</th>
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">SSVC</th>
                <th className="px-3 py-2 font-medium">Grounding</th>
                <th className="whitespace-nowrap px-3 py-2 font-medium">Signals</th>
                <th className="px-3 py-2 text-right font-medium">CVEs</th>
                <th className="px-3 py-2 font-medium">Model</th>
                <th className="px-3 py-2 text-right font-medium">Duration</th>
                <th className="px-3 py-2 font-medium">Chain (prev {"->"} this)</th>
              </tr>
            </thead>
            <tbody>
              {trail.events.map((row) => {
                const chain = hashCell(row);
                return (
                  <tr
                    key={row.event_id}
                    className="border-b border-border last:border-0 hover:bg-muted/30"
                  >
                    <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-muted-foreground">
                      {shortTime(row.ts)}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={cn(
                          "rounded px-1.5 py-0.5 text-[10px] font-medium capitalize",
                          severityClass(row.severity),
                        )}
                      >
                        {row.severity ?? "n/a"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      {row.ssvc_decision ? (
                        <span
                          className={cn(
                            "rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold",
                            SSVC_CLASS[row.ssvc_decision] ?? "bg-muted text-muted-foreground",
                          )}
                        >
                          {row.ssvc_decision}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={cn(
                          "text-[11px]",
                          GROUNDING_CLASS[row.grounding_status ?? ""] ?? "text-muted-foreground",
                        )}
                      >
                        {row.grounding_status ?? "-"}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-muted-foreground">
                      <span title="CISA KEV hits">K{row.kev_hits}</span>{" "}
                      <span title="ransomware-associated hits">R{row.ransomware_hits}</span>{" "}
                      <span title="high-EPSS hits">E{row.high_epss_hits}</span>
                    </td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums">{row.cves_count}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                      {row.model}
                    </td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums">
                      {(row.duration_ms / 1000).toFixed(1)}s
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className="font-mono text-[11px] text-muted-foreground"
                        title={`${row.prev_event_hash} -> ${row.this_event_hash}`}
                      >
                        {chain.from}
                        <span className="mx-1 text-primary">{"->"}</span>
                        {chain.to}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
