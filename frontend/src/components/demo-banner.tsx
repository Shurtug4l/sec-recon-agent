"use client";

import { FlaskConical } from "lucide-react";

import { DEMO_MODE, DEMO_MODEL } from "@/demo/config";

// Thin honesty strip shown only in the keyless demo build. It states plainly
// that runs are replays of real captured triages, so nobody mistakes the
// hosted demo for a live agent (and so the transparency thesis holds).
export function DemoBanner() {
  if (!DEMO_MODE) return null;
  return (
    <div className="border-b border-primary/20 bg-primary/10 px-4 py-1.5 text-center text-[11px] leading-relaxed text-foreground">
      <FlaskConical className="mr-1.5 inline h-3 w-3 text-primary" aria-hidden />
      Demo build: every run replays a <strong className="font-semibold">real captured</strong>{" "}
      triage (model <code className="font-mono">{DEMO_MODEL}</code>) — no API key, no backend.
      Clone the repo to run the live agent.
    </div>
  );
}
