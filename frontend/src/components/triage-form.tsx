"use client";

import { Send, Square } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useTriage } from "@/hooks/use-triage";
import { DEMO_MODE } from "@/demo/config";
import { DEMO_FIXTURES } from "@/demo/fixtures";
import { cn } from "@/lib/utils";

interface Props {
  isRunning: boolean;
  onSubmit: (query: string) => void;
  onCancel: () => void;
}

const SBOM_EXAMPLE = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"type": "library", "name": "log4j-core", "version": "2.14.1",
     "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    {"type": "library", "name": "spring-webmvc", "version": "5.3.20",
     "purl": "pkg:maven/org.springframework/spring-webmvc@5.3.20"},
    {"type": "library", "name": "openssl", "version": "1.0.1f",
     "purl": "pkg:generic/openssl@1.0.1f"}
  ]
}`;

const EXAMPLES: { label: string; value: string }[] = [
  {
    label: "Named CVE",
    value: "What is CVE-2021-41773? Is it exploitable in the wild?",
  },
  {
    label: "Product version",
    value: "I am running Apache HTTP Server 2.4.49 on port 80. What are the risks?",
  },
  {
    label: "Service list",
    value: "Triage these services: nginx 1.18, OpenSSH 8.0, MySQL 5.7",
  },
  {
    label: "SBOM (CycloneDX)",
    value: SBOM_EXAMPLE,
  },
];

// SSVC decision -> chip tint, so the demo gallery reads as a ladder at a glance.
const DECISION_CLASS: Record<string, string> = {
  Act: "border-destructive/50 text-destructive",
  Attend: "border-warning/50 text-warning",
  "Track*": "border-[hsl(var(--severity-low))]/50 text-[hsl(var(--severity-low))]",
  Track: "border-border text-muted-foreground",
};

export function TriageForm({ isRunning, onSubmit, onCancel }: Props) {
  const { draftQuery, setDraftQuery } = useTriage();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = draftQuery.trim();
    if (!trimmed || isRunning) return;
    onSubmit(trimmed);
  }

  function runFixture(query: string) {
    if (isRunning) return;
    setDraftQuery(query);
    onSubmit(query);
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      {DEMO_MODE && (
        <div className="rounded-lg border border-border bg-card/50 p-3">
          <p className="mb-2 text-[11px] uppercase tracking-widest text-muted-foreground">
            Example triages · click to replay a real captured run
          </p>
          <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {DEMO_FIXTURES.map((f) => (
              <button
                key={f.slug}
                type="button"
                onClick={() => runFixture(f.query)}
                disabled={isRunning}
                className="flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2 text-left transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
              >
                <span className="min-w-0">
                  <span className="block truncate text-xs font-medium text-foreground">
                    {f.title}
                  </span>
                  <span className="block truncate text-[10px] text-muted-foreground">
                    {f.cve} · {f.subtitle}
                  </span>
                </span>
                <span
                  className={cn(
                    "shrink-0 rounded-full border px-2 py-0.5 font-mono text-[10px]",
                    DECISION_CLASS[f.decision],
                  )}
                  title={`SSVC verdict of this captured run: ${f.decision}. CISA-style urgency decision, computed server-side; the ladder is explained in the report header.`}
                >
                  {f.decision}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
      <Textarea
        value={draftQuery}
        onChange={(e) => setDraftQuery(e.target.value)}
        placeholder="Ask about a CVE, a service version, paste Nmap XML, or paste a CycloneDX / SPDX / requirements.txt SBOM..."
        disabled={isRunning}
        rows={8}
        maxLength={100_000}
        className="min-h-[180px] resize-y font-mono text-sm leading-relaxed"
      />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1">
          {!DEMO_MODE &&
            EXAMPLES.map((ex) => (
              <Button
                key={ex.label}
                type="button"
                variant="ghost"
                size="sm"
                className="h-7 text-[11px] text-muted-foreground"
                onClick={() => setDraftQuery(ex.value)}
                disabled={isRunning}
              >
                {ex.label}
              </Button>
            ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-muted-foreground">{draftQuery.length.toLocaleString()}/100,000</span>
          {isRunning ? (
            <Button type="button" variant="destructive" onClick={onCancel}>
              <Square className="h-4 w-4" />
              Stop
            </Button>
          ) : (
            <Button type="submit" disabled={!draftQuery.trim()}>
              <Send className="h-4 w-4" />
              Triage
            </Button>
          )}
        </div>
      </div>
    </form>
  );
}
