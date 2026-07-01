"use client";

import { AlertTriangle } from "lucide-react";

import { Header } from "@/components/header";
import { HistorySidebar } from "@/components/history-sidebar";
import { ProgressStream } from "@/components/progress-stream";
import { TriageForm } from "@/components/triage-form";
import { TriageReportView } from "@/components/triage-report-view";
import { Card, CardContent } from "@/components/ui/card";
import { useTriage } from "@/hooks/use-triage";

export default function TriagePage() {
  const {
    state,
    run,
    cancel,
    entries,
    hydrated,
    selectedId,
    selectEntry,
    clearHistory,
  } = useTriage();

  const selected = entries.find((e) => e.id === selectedId) ?? null;

  const isLiveSelection =
    state.currentEntryId !== null && state.currentEntryId === selectedId;

  const displayState = isLiveSelection
    ? {
        report: state.report,
        error: state.error,
        nodes: state.nodes,
        isRunning: state.isRunning,
        durationMs: state.durationMs,
      }
    : selected
      ? {
          report: selected.report,
          error: selected.error,
          nodes: [] as string[],
          isRunning: false,
          durationMs: selected.durationMs,
        }
      : null;

  const liveEntry =
    isLiveSelection && state.currentEntryId
      ? entries.find((e) => e.id === state.currentEntryId)
      : null;
  const displayedQuery = isLiveSelection ? liveEntry?.query : selected?.query;

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <div className="flex flex-1">
        <HistorySidebar
          entries={entries}
          selectedId={selectedId}
          onSelect={(id) => selectEntry(id)}
          onClear={clearHistory}
        />
        <main className="flex-1">
          <div className="container max-w-4xl space-y-6 py-8">
            <section>
              <h1 className="mb-2 text-2xl font-semibold tracking-tight">Security triage</h1>
              <p className="mb-6 text-sm leading-relaxed text-muted-foreground">
                One input, five entry shapes: a named CVE (
                <code className="font-mono">CVE-2021-44228</code>), a
                product/version (<code className="font-mono">Apache 2.4.49</code>),
                a fuzzy symptom description, a raw Nmap XML scan, or a
                CycloneDX / SPDX / requirements.txt SBOM. The agent grounds every
                answer with ten typed tools (NVD, CISA KEV, FIRST EPSS,
                Exploit-DB, GitHub, ATT&amp;CK, patch lookup, OSV.dev, SBOM and
                Nmap parsers) and returns a typed{" "}
                <code className="font-mono">TriageReport</code>; the reasoning
                chain is the audit log.
              </p>
              <TriageForm
                isRunning={state.isRunning}
                onSubmit={run}
                onCancel={cancel}
              />
            </section>

            {displayState && (
              <section className="space-y-4">
                <ProgressStream
                  nodes={displayState.nodes}
                  isRunning={displayState.isRunning}
                />

                {displayState.error && !displayState.isRunning && (
                  <Card className="border-destructive">
                    <CardContent className="flex items-start gap-3 p-4">
                      <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" />
                      <div>
                        <p className="text-sm font-medium">Triage failed</p>
                        <p className="mt-1 font-mono text-xs text-muted-foreground">
                          {displayState.error}
                        </p>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {displayState.report && (
                  <TriageReportView
                    report={displayState.report}
                    query={displayedQuery}
                  />
                )}

                {displayState.durationMs !== null && !displayState.isRunning && (
                  <p className="text-right text-[10px] text-muted-foreground">
                    Completed in {(displayState.durationMs / 1000).toFixed(1)}s
                  </p>
                )}
              </section>
            )}

            {!displayState && hydrated && entries.length === 0 && (
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
