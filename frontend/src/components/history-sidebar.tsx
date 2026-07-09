"use client";

import { History, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import type { HistoryEntry, Severity } from "@/lib/types";

interface Props {
  entries: HistoryEntry[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onClear: () => void;
}

const severityClass: Record<Severity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

// Time-of-day for today's runs, date for older ones. The demo gallery seeds
// entries stamped at the capture date; rendering those as bare times would
// read as "ran today", which is not true.
function formatWhen(iso: string): string {
  const d = new Date(iso);
  return d.toDateString() === new Date().toDateString()
    ? d.toLocaleTimeString()
    : d.toLocaleDateString();
}

export function HistorySidebar({ entries, selectedId, onSelect, onClear }: Props) {
  return (
    <aside className="hidden h-[calc(100vh-3.5rem)] w-72 shrink-0 border-r border-border bg-card/30 lg:flex lg:flex-col">
      <div className="flex items-center justify-between gap-2 p-4">
        <div className="flex items-center gap-2 text-sm font-medium">
          <History className="h-4 w-4" />
          History
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={onClear}
          disabled={entries.length === 0}
          aria-label="Clear history"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
      <Separator />
      <ScrollArea className="flex-1">
        <div className="space-y-1 p-2">
          {entries.length === 0 ? (
            <p className="px-2 py-6 text-center text-xs text-muted-foreground">
              Past triage runs will appear here.
            </p>
          ) : (
            entries.map((entry) => (
              <button
                key={entry.id}
                type="button"
                aria-pressed={selectedId === entry.id}
                onClick={() => onSelect(entry.id)}
                className={cn(
                  "w-full animate-fade-in rounded-md p-3 text-left transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  selectedId === entry.id && "bg-accent",
                )}
              >
                <p className="line-clamp-2 text-sm font-medium leading-tight">
                  {entry.query || "(empty)"}
                </p>
                <div className="mt-2 flex items-center gap-2">
                  {entry.report ? (
                    <Badge
                      variant="outline"
                      className={cn("text-[10px] uppercase", severityClass[entry.report.severity])}
                    >
                      {entry.report.severity}
                    </Badge>
                  ) : entry.error ? (
                    <Badge variant="destructive" className="text-[10px] uppercase">
                      error
                    </Badge>
                  ) : (
                    <Badge variant="secondary" className="text-[10px] uppercase">
                      pending
                    </Badge>
                  )}
                  <span className="text-[10px] text-muted-foreground">
                    {formatWhen(entry.startedAt)}
                  </span>
                </div>
              </button>
            ))
          )}
        </div>
      </ScrollArea>
    </aside>
  );
}
