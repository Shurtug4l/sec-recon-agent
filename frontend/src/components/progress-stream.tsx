"use client";

import { Check, Loader2, Zap } from "lucide-react";

import { cn } from "@/lib/utils";

interface Props {
  nodes: string[];
  isRunning: boolean;
}

// Friendly labels for the Pydantic AI node class names we emit from
// api/stream.py. Unknown class names render as-is.
const FRIENDLY: Record<string, string> = {
  UserPromptNode: "Loading query",
  ModelRequestNode: "Asking the model",
  CallToolsNode: "Calling MCP tools",
  End: "Synthesizing report",
};

export function ProgressStream({ nodes, isRunning }: Props) {
  if (nodes.length === 0 && !isRunning) return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        <Zap className="h-3 w-3" /> Agent progress
      </div>
      <ol className="space-y-1">
        {nodes.map((node, i) => {
          const isLast = i === nodes.length - 1;
          const isInFlight = isRunning && isLast;
          return (
            <li
              key={`${node}-${i}`}
              className={cn(
                "flex animate-fade-in items-center gap-2 rounded-md px-3 py-1.5 text-sm",
                isInFlight ? "bg-primary/10 text-primary" : "text-muted-foreground",
              )}
            >
              {isInFlight ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Check className="h-3.5 w-3.5 text-success" />
              )}
              <span className="font-mono text-xs">{FRIENDLY[node] ?? node}</span>
            </li>
          );
        })}
        {isRunning && nodes.length === 0 && (
          <li className="flex items-center gap-2 rounded-md px-3 py-1.5 text-sm text-primary">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            <span className="font-mono text-xs">Connecting...</span>
          </li>
        )}
      </ol>
    </div>
  );
}
