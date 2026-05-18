"use client";

import { useCallback, useEffect, useState } from "react";
import type { HistoryEntry } from "@/lib/types";

// Local history of past triage runs. Persisted in localStorage. Capped at
// MAX_ENTRIES so the bucket cannot grow unbounded across sessions.
//
// Functional updates throughout: `add` and `update` must not close over
// the stale `entries` reference. A previous version captured entries from
// render time, which silently dropped the just-added entry when the run
// completion callback patched it (the map() couldn't find the id in the
// stale snapshot, and persist() wrote the OLD list back to localStorage).

const STORAGE_KEY = "sec-recon-history";
const MAX_ENTRIES = 30;

function writeToStorage(entries: HistoryEntry[]): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // Quota exceeded; drop silently rather than crashing the UI.
  }
}

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

  const add = useCallback((entry: HistoryEntry) => {
    setEntries((prev) => {
      const next = [entry, ...prev].slice(0, MAX_ENTRIES);
      writeToStorage(next);
      return next;
    });
  }, []);

  const update = useCallback((id: string, patch: Partial<HistoryEntry>) => {
    setEntries((prev) => {
      const next = prev.map((e) => (e.id === id ? { ...e, ...patch } : e));
      writeToStorage(next);
      return next;
    });
  }, []);

  const clear = useCallback(() => {
    setEntries([]);
    try {
      window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Best effort.
    }
  }, []);

  return { entries, hydrated, add, update, clear };
}
