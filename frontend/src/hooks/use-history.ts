"use client";

import { useCallback, useEffect, useState } from "react";
import type { HistoryEntry } from "@/lib/types";

// Local history of past triage runs. Persisted in localStorage (no
// server-side audit log; the project scope explicitly defers persistence,
// see docs/design.md). Cap at MAX_ENTRIES so the bucket cannot grow
// unbounded across many sessions.

const STORAGE_KEY = "sec-recon-history";
const MAX_ENTRIES = 30;

export function useHistory() {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as HistoryEntry[];
        if (Array.isArray(parsed)) setEntries(parsed);
      }
    } catch {
      // Corrupted storage; ignore and start fresh.
    }
    setHydrated(true);
  }, []);

  const persist = useCallback((next: HistoryEntry[]) => {
    setEntries(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Quota exceeded; drop silently rather than crashing the UI.
    }
  }, []);

  const add = useCallback(
    (entry: HistoryEntry) => {
      persist([entry, ...entries].slice(0, MAX_ENTRIES));
    },
    [entries, persist],
  );

  const update = useCallback(
    (id: string, patch: Partial<HistoryEntry>) => {
      persist(entries.map((e) => (e.id === id ? { ...e, ...patch } : e)));
    },
    [entries, persist],
  );

  const clear = useCallback(() => persist([]), [persist]);

  return { entries, hydrated, add, update, clear };
}
