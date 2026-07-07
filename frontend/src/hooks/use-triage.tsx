"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

import { useHistory } from "@/hooks/use-history";
import { streamSse } from "@/lib/sse";
import { DEMO_MODE } from "@/demo/config";
import {
  demoHistorySeed,
  historyEntryFromFixture,
  matchFixture,
} from "@/demo/fixtures";
import { replayFixture } from "@/demo/replay";
import type { HistoryEntry, NodeEvent, SseEvent, TriageReport } from "@/lib/types";

// Provider-backed agent run state.
//
// State and the in-flight AbortController live in a Context Provider
// mounted at the root layout, so the run survives navigation between
// pages. A run started on `/` keeps streaming when the user moves to
// `/dashboard`; returning to `/` shows the still-in-flight UI.
//
// History is also owned here so the run-completion path can patch the
// entry without depending on a callback bound to a possibly-unmounted
// page component.

export interface TriageRunState {
  isRunning: boolean;
  nodes: string[];
  report: TriageReport | null;
  error: string | null;
  startedAt: number | null;
  durationMs: number | null;
  currentEntryId: string | null;
}

const INITIAL: TriageRunState = {
  isRunning: false,
  nodes: [],
  report: null,
  error: null,
  startedAt: null,
  durationMs: null,
  currentEntryId: null,
};

interface TriageContextValue {
  state: TriageRunState;
  run: (query: string) => void;
  cancel: () => void;
  reset: () => void;
  entries: HistoryEntry[];
  hydrated: boolean;
  selectedId: string | null;
  selectEntry: (id: string | null) => void;
  clearHistory: () => void;
  draftQuery: string;
  setDraftQuery: (query: string) => void;
}

const TriageContext = createContext<TriageContextValue | null>(null);

export function TriageProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<TriageRunState>(INITIAL);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draftQuery, setDraftQuery] = useState<string>("");
  const abortRef = useRef<AbortController | null>(null);
  const { entries, hydrated, add, update, clear, seed } = useHistory();

  // Demo cold-open: once localStorage has hydrated and the history is empty,
  // seed the whole real-capture gallery so a first-time visitor lands on a
  // populated console instead of an empty form. No-op outside demo builds and
  // no-op when the visitor already has runs (seed guards on emptiness).
  useEffect(() => {
    if (DEMO_MODE && hydrated && entries.length === 0) {
      seed(demoHistorySeed());
    }
  }, [hydrated, entries.length, seed]);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const run = useCallback(
    (query: string) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      const startedAt = Date.now();
      const id = crypto.randomUUID();

      // Push the history entry immediately so the sidebar reflects the run.
      const entry: HistoryEntry = {
        id,
        query,
        report: null,
        startedAt: new Date(startedAt).toISOString(),
        durationMs: null,
        error: null,
        nodeEvents: null,
        usage: null,
      };
      add(entry);
      setSelectedId(id);
      setState({ ...INITIAL, isRunning: true, startedAt, currentEntryId: id });

      // Fire-and-forget. The IIFE keeps run() synchronous from the caller's
      // perspective (clicking Submit returns immediately).
      void (async () => {
        let finalReport: TriageReport | null = null;
        let finalError: string | null = null;
        // Real per-node arrival times, captured client-side as each `node`
        // event streams in. Snapshotted onto the history entry at `final` so the
        // observability view draws a measured waterfall, not a synthesized one.
        const nodeEvents: NodeEvent[] = [];
        // In a demo build there is no backend: replay the matching real capture
        // instead of streaming from the agent API. An unmatched query gets a
        // nudge toward the example gallery rather than a network error.
        const demoFixture = DEMO_MODE ? matchFixture(query) : null;
        try {
          if (DEMO_MODE && !demoFixture) {
            finalError =
              "Demo build: choose one of the example vulnerabilities below (the live agent is not reachable in the hosted demo).";
            setState((prev) => ({
              ...prev,
              error: finalError,
              isRunning: false,
              durationMs: Date.now() - startedAt,
            }));
            return;
          }

          const onEvent = (event: SseEvent) => {
            // CRITICAL: capture outer-scope variables and persist to history
            // BEFORE dispatching setState. React 18+ defers setState updater
            // execution to the render phase (asynchronous w.r.t. dispatch);
            // doing the capture inside the updater means the assignment
            // happens AFTER the surrounding await chain has already moved on
            // to the `finally` block - at which point finalReport is still
            // null and we patch the history entry with the wrong values.
            if (event.type === "node") {
              nodeEvents.push({ name: event.data.node, atMs: Date.now() - startedAt });
            } else if (event.type === "final") {
              finalReport = event.data;
              update(id, {
                report: event.data,
                error: null,
                durationMs: Date.now() - startedAt,
                nodeEvents: [...nodeEvents],
              });
            } else if (event.type === "usage") {
              // Arrives after `final`; a partial patch merges it in.
              update(id, { usage: event.data });
            } else if (event.type === "error") {
              finalError = `${event.data.type}: ${event.data.message}`;
              update(id, {
                report: null,
                error: finalError,
                durationMs: Date.now() - startedAt,
              });
            }

            // Pure setState updater - no side effects. State machine only.
            setState((prev) => {
              switch (event.type) {
                case "started":
                  return prev;
                case "node":
                  return { ...prev, nodes: [...prev.nodes, event.data.node] };
                case "final":
                  return {
                    ...prev,
                    report: event.data,
                    isRunning: false,
                    durationMs: Date.now() - startedAt,
                  };
                case "error":
                  return {
                    ...prev,
                    error: `${event.data.type}: ${event.data.message}`,
                    isRunning: false,
                    durationMs: Date.now() - startedAt,
                  };
                default:
                  return prev;
              }
            });
          };

          await (demoFixture
            ? replayFixture(demoFixture, { signal: ctrl.signal, onEvent })
            : streamSse({ url: "/api/triage", body: { query }, signal: ctrl.signal, onEvent }));

          if (demoFixture) {
            // Overwrite with the fixture's REAL measured timing; the replay
            // cadence is compressed and cosmetic, so the persisted waterfall and
            // the completion time stay honest to the original capture.
            const captured = historyEntryFromFixture(demoFixture);
            finalReport = captured.report;
            update(id, {
              report: captured.report,
              error: null,
              nodeEvents: captured.nodeEvents,
              usage: captured.usage,
              durationMs: captured.durationMs,
            });
            setState((prev) => ({ ...prev, durationMs: captured.durationMs }));
          }
        } catch (err) {
          finalError = ctrl.signal.aborted
            ? "Cancelled"
            : err instanceof Error
            ? err.message
            : "Unknown error";
          setState((prev) => ({
            ...prev,
            error: finalError,
            isRunning: false,
            durationMs: Date.now() - startedAt,
          }));
        } finally {
          // Safety net: if the onEvent path above already patched the
          // history (the success / explicit-error path), this is a no-op
          // because the entry already has the right shape. The finally
          // matters only for stream-level failures (cancel, network drop)
          // where no `final` or `error` event was emitted.
          if (finalReport === null && finalError === null) {
            update(id, {
              report: null,
              error: ctrl.signal.aborted ? "Cancelled" : "Stream ended without result",
              durationMs: Date.now() - startedAt,
            });
          } else if (finalError !== null && finalReport === null) {
            // Error captured via catch (not via SSE error event); still patch.
            update(id, {
              report: null,
              error: finalError,
              durationMs: Date.now() - startedAt,
            });
          }
        }
      })();
    },
    [add, update],
  );

  const reset = useCallback(() => {
    setState(INITIAL);
  }, []);

  const clearHistory = useCallback(() => {
    clear();
    setSelectedId(null);
    // If a run is currently in flight, leave it running - clearing the
    // history does not abort the agent. The completion will simply have
    // no entry to update.
  }, [clear]);

  const selectEntry = useCallback(
    (id: string | null) => {
      setSelectedId(id);
      if (id) {
        const entry = entries.find((e) => e.id === id);
        if (entry) setDraftQuery(entry.query);
      }
    },
    [entries],
  );

  const value: TriageContextValue = {
    state,
    run,
    cancel,
    reset,
    entries,
    hydrated,
    selectedId,
    selectEntry,
    clearHistory,
    draftQuery,
    setDraftQuery,
  };

  return <TriageContext.Provider value={value}>{children}</TriageContext.Provider>;
}

export function useTriage(): TriageContextValue {
  const ctx = useContext(TriageContext);
  if (!ctx) {
    throw new Error("useTriage must be used within a <TriageProvider>");
  }
  return ctx;
}
