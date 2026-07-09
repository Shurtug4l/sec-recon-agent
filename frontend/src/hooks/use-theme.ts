"use client";

import { useCallback, useSyncExternalStore } from "react";

export type Theme = "dark" | "light";

// <html data-theme> is the single runtime source of truth (stamped pre-paint
// by the inline script in layout.tsx). Consumers subscribe to attribute
// mutations, so the value stays correct no matter what flips it - the header
// toggle today, a palette command tomorrow.
function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributeFilter: ["data-theme"] });
  return () => observer.disconnect();
}

function readTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function useTheme(): { theme: Theme; toggleTheme: () => void } {
  // The server snapshot says "dark" (the same brand default the pre-paint
  // script falls back to); useSyncExternalStore re-reads the real attribute
  // right after hydration, so there is no SSR/client markup mismatch.
  const theme = useSyncExternalStore(subscribe, readTheme, () => "dark" as const);
  const toggleTheme = useCallback(() => {
    const next: Theme = readTheme() === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("theme", next);
    } catch {
      // Private mode / quota: the toggle still works for the session.
    }
  }, []);
  return { theme, toggleTheme };
}
