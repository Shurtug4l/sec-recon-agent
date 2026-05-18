"use client";

import { TriageProvider } from "@/hooks/use-triage";

// Client-side wrapper for the root layout: mounts the TriageProvider so
// agent run state and history live ABOVE the routes, not inside them.
// A run started on `/` survives navigation to `/dashboard`.
export function Providers({ children }: { children: React.ReactNode }) {
  return <TriageProvider>{children}</TriageProvider>;
}
