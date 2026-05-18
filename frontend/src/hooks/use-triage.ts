"use client";

import { useCallback, useRef, useState } from "react";

import { streamSse } from "@/lib/sse";
import type { TriageReport } from "@/lib/types";

export interface TriageRunState {
  isRunning: boolean;
  nodes: string[];
  report: TriageReport | null;
  error: string | null;
  startedAt: number | null;
  durationMs: number | null;
}

const INITIAL: TriageRunState = {
  isRunning: false,
  nodes: [],
  report: null,
  error: null,
  startedAt: null,
  durationMs: null,
};

export function useTriage() {
  const [state, setState] = useState<TriageRunState>(INITIAL);
  const abortRef = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const run = useCallback(
    async (query: string, onCompleted?: (s: TriageRunState) => void) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      const startedAt = Date.now();

      setState({ ...INITIAL, isRunning: true, startedAt });

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
          },
        });
      } catch (err) {
        if (ctrl.signal.aborted) {
          setState((prev) => ({
            ...prev,
            error: "Cancelled",
            isRunning: false,
            durationMs: Date.now() - startedAt,
          }));
        } else {
          setState((prev) => ({
            ...prev,
            error: err instanceof Error ? err.message : "Unknown error",
            isRunning: false,
            durationMs: Date.now() - startedAt,
          }));
        }
      } finally {
        // Drain final state to the caller (history persistence).
        setState((current) => {
          onCompleted?.(current);
          return current;
        });
      }
    },
    [],
  );

  const reset = useCallback(() => setState(INITIAL), []);

  return { state, run, cancel, reset };
}
