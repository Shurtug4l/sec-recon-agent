"use client";

import { CommandPaletteProvider } from "@/components/command-palette";
import { DemoBanner } from "@/components/demo-banner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { TriageProvider } from "@/hooks/use-triage";

// Client-side wrapper for the root layout: mounts the TriageProvider so
// agent run state and history live ABOVE the routes, not inside them.
// A run started on `/` survives navigation to `/dashboard`.
// The command palette nests inside it: report-scoped commands read useTriage.
// The TooltipProvider shares one delay/skip timer across every Radix tooltip
// on the page (the glass-box glosses on the report and decision trace).
export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <TriageProvider>
      <TooltipProvider delayDuration={200} skipDelayDuration={300}>
        <CommandPaletteProvider>
          <DemoBanner />
          {children}
        </CommandPaletteProvider>
      </TooltipProvider>
    </TriageProvider>
  );
}
