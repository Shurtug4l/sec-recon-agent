"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, BookOpen, Copy, Wrench } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { loadAgentMeta } from "@/lib/agent-meta";
import type { AgentMeta } from "@/lib/types";

export function TransparencyTab() {
  const [meta, setMeta] = useState<AgentMeta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadAgentMeta()
      .then((data) => {
        if (!cancelled) setMeta(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load /v1/meta");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function copyPrompt() {
    if (!meta) return;
    navigator.clipboard.writeText(meta.system_prompt).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  }

  if (error) {
    return (
      <Card className="border-destructive">
        <CardContent className="flex items-start gap-2 p-4 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
          <div>
            <p className="font-medium">Could not load agent metadata</p>
            <p className="mt-1 font-mono text-xs text-muted-foreground">{error}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!meta) {
    return (
      <div className="space-y-6" aria-busy="true">
        <span className="sr-only">Loading agent metadata</span>
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-3 w-3/4" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-36 w-full" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-48" />
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <BookOpen className="h-4 w-4" /> System prompt
            </CardTitle>
            <Button variant="outline" size="sm" onClick={copyPrompt}>
              <Copy className="h-3 w-3" />
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <p className="text-[11px] text-muted-foreground">
            The literal string the LLM receives on every request. Read-only; if you want to
            change it, edit <code className="font-mono">src/sec_recon_agent/agent/prompts.py</code> and rebuild.
          </p>
        </CardHeader>
        <CardContent>
          <pre className="max-h-[400px] overflow-auto whitespace-pre-wrap rounded-md bg-muted/50 p-4 font-mono text-xs leading-relaxed">
            {meta.system_prompt}
          </pre>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Wrench className="h-4 w-4" /> Tool inventory
            <Badge variant="secondary" className="ml-1 font-mono text-[10px]">
              {meta.tools.length} typed
            </Badge>
          </CardTitle>
          <p className="text-[11px] text-muted-foreground">
            The {meta.tools.length} typed tools the agent can call. Their I/O contracts live in{" "}
            <code className="font-mono">src/sec_recon_agent/mcp_server/models.py</code>.
          </p>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {meta.tools.map((tool) => (
            <div key={tool.name} className="rounded-md border border-border p-3">
              <div className="flex items-center justify-between gap-2">
                <code className="font-mono text-sm font-semibold text-primary">{tool.name}</code>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
                {tool.description}
              </p>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Runtime</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Model</p>
            <p className="mt-1 font-mono">{meta.model}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Output schema</p>
            <p className="mt-1 font-mono">TriageReport</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Boundary</p>
            <Badge variant="secondary" className="mt-1 font-mono text-[10px]">
              UNTRUSTED_CONTENT fenced
            </Badge>
            <p className="mt-1 text-[10px] text-muted-foreground">
              External feed text reaches the model wrapped in UNTRUSTED_CONTENT fences:
              tool output is data, never instructions.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">What the agent CANNOT do</CardTitle>
          <p className="text-[11px] text-muted-foreground">
            Hard guarantees from the architecture, documented in <code className="font-mono">docs/design.md</code>.
          </p>
        </CardHeader>
        <CardContent>
          <ul className="space-y-1.5 text-sm">
            <li className="flex gap-2">
              <span className="select-none text-muted-foreground">·</span>
              Make HTTP calls outside the {meta.tools.length} declared tools (no shell, no arbitrary fetch).
            </li>
            <li className="flex gap-2">
              <span className="select-none text-muted-foreground">·</span>
              Return free-text output bypassing the <code className="font-mono">TriageReport</code> schema.
            </li>
            <li className="flex gap-2">
              <span className="select-none text-muted-foreground">·</span>
              See your <code className="font-mono">ANTHROPIC_API_KEY</code>: the key lives in the backend process only.
            </li>
            <li className="flex gap-2">
              <span className="select-none text-muted-foreground">·</span>
              Persist or log your query text in OpenTelemetry spans: the privacy invariant is enforced by tests.
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
