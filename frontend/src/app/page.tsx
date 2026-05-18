"use client";

import { useState } from "react";
import { AlertTriangle } from "lucide-react";

import { Header } from "@/components/header";
import { HistorySidebar } from "@/components/history-sidebar";
import { ProgressStream } from "@/components/progress-stream";
import { TriageForm } from "@/components/triage-form";
import { TriageReportView } from "@/components/triage-report-view";
import { Card, CardContent } from "@/components/ui/card";
import { useHistory } from "@/hooks/use-history";
import { useTriage } from "@/hooks/use-triage";
import type { HistoryEntry } from "@/lib/types";

export default function Home() {
  const { state, run, cancel } = useTriage();
  const { entries, hydrated, add, update } = useHistory();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selected = entries.find((e) => e.id === selectedId);
  // Active display: live state if running, else the selected history entry, else nothing.
  const displayReport = state.isRunning || state.report || state.error
    ? { report: state.report, error: state.error, nodes: state.nodes, isRunning: state.isRunning, durationMs: state.durationMs }
    : selected
    ? { report: selected.report, error: selected.error, nodes: [], isRunning: false, durationMs: selected.durationMs }
    : null;

  function handleSubmit(query: string) {
    const id = crypto.randomUUID();
    const entry: HistoryEntry = {
      id,
      query,
      report: null,
      startedAt: new Date().toISOString(),
      durationMs: null,
      error: null,
    };
    add(entry);
    setSelectedId(id);
    void run(query, (final) => {
      update(id, {
        report: final.report,
        error: final.error,
        durationMs: final.durationMs,
      });
    });
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <div className="flex flex-1">
        <HistorySidebar
          entries={entries}
          selectedId={selectedId}
          onSelect={(id) => setSelectedId(id)}
          onClear={() => {
            // Replace localStorage atomically via the hook.
            entries.forEach((e) => update(e.id, {}));
            window.localStorage.removeItem("sec-recon-history");
            window.location.reload();
          }}
        />
        <main className="flex-1">
          <div className="container max-w-3xl space-y-6 py-8">
            <section>
              <h1 className="mb-2 text-2xl font-semibold tracking-tight">Security triage</h1>
              <p className="mb-6 text-sm text-muted-foreground">
                Ask a question about a CVE, a service version, or paste Nmap XML. The agent
                grounds every answer with typed tool calls; the reasoning chain is the audit log.
              </p>
              <TriageForm
                isRunning={state.isRunning}
                onSubmit={handleSubmit}
                onCancel={cancel}
                initialQuery={selected?.query ?? ""}
              />
            </section>

            {displayReport && (
              <section className="space-y-4">
                <ProgressStream nodes={displayReport.nodes} isRunning={displayReport.isRunning} />

                {displayReport.error && !displayReport.isRunning && (
                  <Card className="border-destructive">
                    <CardContent className="flex items-start gap-3 p-4">
                      <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" />
                      <div>
                        <p className="text-sm font-medium">Triage failed</p>
                        <p className="mt-1 font-mono text-xs text-muted-foreground">
                          {displayReport.error}
                        </p>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {displayReport.report && <TriageReportView report={displayReport.report} />}

                {displayReport.durationMs !== null && !displayReport.isRunning && (
                  <p className="text-right text-[10px] text-muted-foreground">
                    Completed in {(displayReport.durationMs / 1000).toFixed(1)}s
                  </p>
                )}
              </section>
            )}

            {!displayReport && hydrated && entries.length === 0 && (
              <Card className="border-dashed">
                <CardContent className="py-12 text-center text-sm text-muted-foreground">
                  Submit a query above to start a triage run.
                </CardContent>
              </Card>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
