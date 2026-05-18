"use client";

import { useState } from "react";
import { Send, Square } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

interface Props {
  isRunning: boolean;
  onSubmit: (query: string) => void;
  onCancel: () => void;
  initialQuery?: string;
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

export function TriageForm({ isRunning, onSubmit, onCancel, initialQuery = "" }: Props) {
  const [query, setQuery] = useState(initialQuery);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = query.trim();
    if (!trimmed || isRunning) return;
    onSubmit(trimmed);
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <Textarea
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Ask about a CVE, a service version, paste Nmap XML, or paste a CycloneDX/SPDX/requirements.txt SBOM..."
        disabled={isRunning}
        rows={3}
        maxLength={100_000}
        className="resize-none font-mono text-sm"
      />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1">
          {EXAMPLES.map((ex) => (
            <Button
              key={ex.label}
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 text-[11px] text-muted-foreground"
              onClick={() => setQuery(ex.value)}
              disabled={isRunning}
            >
              {ex.label}
            </Button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-muted-foreground">{query.length.toLocaleString()}/100,000</span>
          {isRunning ? (
            <Button type="button" variant="destructive" onClick={onCancel}>
              <Square className="h-4 w-4" />
              Stop
            </Button>
          ) : (
            <Button type="submit" disabled={!query.trim()}>
              <Send className="h-4 w-4" />
              Triage
            </Button>
          )}
        </div>
      </div>
    </form>
  );
}
