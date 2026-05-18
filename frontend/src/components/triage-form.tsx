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

const EXAMPLES = [
  "What is CVE-2021-41773? Is it exploitable in the wild?",
  "I am running Apache HTTP Server 2.4.49 on port 80. What are the risks?",
  "Triage these services: nginx 1.18, OpenSSH 8.0, MySQL 5.7",
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
        placeholder="Ask about a CVE, a service version, or paste Nmap XML..."
        disabled={isRunning}
        rows={3}
        maxLength={4000}
        className="resize-none font-mono text-sm"
      />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1">
          {EXAMPLES.map((ex) => (
            <Button
              key={ex}
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 text-[11px] text-muted-foreground"
              onClick={() => setQuery(ex)}
              disabled={isRunning}
            >
              {ex.length > 36 ? ex.slice(0, 36) + "..." : ex}
            </Button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-muted-foreground">{query.length}/4000</span>
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
