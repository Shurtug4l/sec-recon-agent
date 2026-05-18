"use client";

import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
} from "react";

import { useHistory } from "@/hooks/use-history";
import { streamSse } from "@/lib/sse";
import type { HistoryEntry, TriageReport } from "@/lib/types";

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
}

const TriageContext = createContext<TriageContextValue | null>(null);

export function TriageProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<TriageRunState>(INITIAL);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const { entries, hydrated, add, update, clear } = useHistory();

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
      };
      add(entry);
      setSelectedId(id);
      setState({ ...INITIAL, isRunning: true, startedAt, currentEntryId: id });

      // Fire-and-forget. The IIFE keeps run() synchronous from the caller's
      // perspective (clicking Submit returns immediately).
      void (async () => {
        let finalReport: TriageReport | null = null;
        let finalError: string | null = null;
        try {
          await streamSse({
            url: "/api/triage",
            body: { query },
            signal: ctrl.signal,
            onEvent: (event) => {
              setState((prev) => {
                switch (event.type) {
                  case "started":
                    return prev;
                  case "node":
                    return { ...prev, nodes: [...prev.nodes, event.data.node] };
                  case "final":
                    finalReport = event.data;
                    return {
                      ...prev,
                      report: event.data,
                      isRunning: false,
                      durationMs: Date.now() - startedAt,
                    };
                  case "error":
                    finalError = `${event.data.type}: ${event.data.message}`;
                    return {
                      ...prev,
                      error: finalError,
                      isRunning: false,
                      durationMs: Date.now() - startedAt,
                    };
                  default:
                    return prev;
                }
              });
            },
          });
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
          // Persist the final outcome to the history entry. Functional
          // update inside useHistory guarantees we hit the latest list,
          // even if many runs interleaved.
          update(id, {
            report: finalReport,
            error: finalError,
            durationMs: Date.now() - startedAt,
          });
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
    // If a run is currently in flight, leave it running — clearing the
    // history does not abort the agent. The completion will simply have
    // no entry to update.
  }, [clear]);

  const value: TriageContextValue = {
    state,
    run,
    cancel,
    reset,
    entries,
    hydrated,
    selectedId,
    selectEntry: setSelectedId,
    clearHistory,
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
