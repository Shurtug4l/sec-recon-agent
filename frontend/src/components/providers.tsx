"use client";

import { CommandPaletteProvider } from "@/components/command-palette";
import { DemoBanner } from "@/components/demo-banner";
import { TriageProvider } from "@/hooks/use-triage";

// Client-side wrapper for the root layout: mounts the TriageProvider so
// agent run state and history live ABOVE the routes, not inside them.
// A run started on `/` survives navigation to `/dashboard`.
// The command palette nests inside it: report-scoped commands read useTriage.
export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <TriageProvider>
      <CommandPaletteProvider>
        <DemoBanner />
        {children}
      </CommandPaletteProvider>
    </TriageProvider>
  );
}
