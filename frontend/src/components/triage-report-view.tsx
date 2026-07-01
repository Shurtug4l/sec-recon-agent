"use client";

import { useState } from "react";
import {
  AlertTriangle,
  Braces,
  ChevronDown,
  CircleCheck,
  CircleDashed,
  CircleSlash,
  Crosshair,
  Download,
  ExternalLink,
  Flame,
  Printer,
  Radar,
  Share2,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Skull,
  TrendingUp,
  Wrench,
  Zap,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Separator } from "@/components/ui/separator";
import { downloadJson, downloadMarkdown, reportToMarkdown } from "@/lib/markdown-export";
import { buildPermalink } from "@/lib/permalink";
import { cn } from "@/lib/utils";
import type {
  FeedStatus,
  Severity,
  SignalStatus,
  SsvcAssessment,
  SsvcDecision,
  TriageReport,
} from "@/lib/types";

const severityClass: Record<Severity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

// SSVC ladder, most- to least-urgent. Position encodes urgency; the active
// stop also carries an icon + fill + text, so the verdict never rests on color
// alone (colorblind-safe, print-safe).
const SSVC_ORDER: SsvcDecision[] = ["Act", "Attend", "Track*", "Track"];
const SSVC_META: Record<
  SsvcDecision,
  { icon: typeof Zap; blurb: string; activeClass: string }
> = {
  Act: {
    icon: Zap,
    blurb: "Remediate out-of-cycle, as fast as possible.",
    activeClass: "bg-destructive text-destructive-foreground",
  },
  Attend: {
    icon: AlertTriangle,
    blurb: "Remediate ahead of standard timelines; needs attention.",
    activeClass: "bg-warning text-warning-foreground",
  },
  "Track*": {
    icon: Radar,
    blurb: "Standard timeline, but monitor for signals that would escalate.",
    activeClass: "bg-[hsl(var(--severity-low))] text-background",
  },
  Track: {
    icon: CircleCheck,
    blurb: "No action beyond standard update timelines.",
    activeClass: "bg-secondary text-foreground ring-1 ring-inset ring-primary/30",
  },
};

// Per-feed coverage status: icon + text + hue (redundant encoding).
const COVERAGE_META: Record<
  SignalStatus,
  { icon: typeof CircleCheck; label: string; className: string }
> = {
  found: { icon: CircleCheck, label: "found", className: "text-[hsl(var(--success))]" },
  not_found: { icon: CircleSlash, label: "not found", className: "text-muted-foreground" },
  error: { icon: AlertTriangle, label: "error", className: "text-warning" },
  not_queried: { icon: CircleDashed, label: "not queried", className: "text-muted-foreground/60" },
};

const UNTRUSTED_START = "<UNTRUSTED_CONTENT>";
const UNTRUSTED_END = "</UNTRUSTED_CONTENT>";

// Strip the marker tokens for display while keeping a visual signal that
// the text is vendor-authored. The fence is a wire-level convention; in
// the UI we render it as a styled quote.
function unfence(text: string): { body: string; fenced: boolean } {
  const t = text.trim();
  if (t.startsWith(UNTRUSTED_START) && t.endsWith(UNTRUSTED_END)) {
    return {
      body: t.slice(UNTRUSTED_START.length, -UNTRUSTED_END.length).trim(),
      fenced: true,
    };
  }
  return { body: text, fenced: false };
}

export function TriageReportView({
  report,
  query,
}: {
  report: TriageReport;
  query?: string;
}) {
  const [linkState, setLinkState] = useState<"idle" | "copied" | "toolarge">("idle");

  async function handleCopyLink() {
    // Encode the whole report into a URL fragment (client-side, never sent to a
    // server) and copy it. Oversized reports fall back to the JSON export.
    const url = await buildPermalink(report, window.location.origin);
    if (!url) {
      setLinkState("toolarge");
      window.setTimeout(() => setLinkState("idle"), 2500);
      return;
    }
    await navigator.clipboard.writeText(url);
    setLinkState("copied");
    window.setTimeout(() => setLinkState("idle"), 1500);
  }

  function handleExportMarkdown() {
    const md = reportToMarkdown(report, query);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
    downloadMarkdown(`triage-${stamp}.md`, md);
  }

  function handleExportPdf() {
    // Browser print-to-PDF. The @media print stylesheet hides chrome and
    // shows only the .printable-report block (this component). The user
    // picks "Save as PDF" in the system print dialog. Native multi-page,
    // pixel-perfect, zero JS dependency.
    window.print();
  }

  function handleExportJson() {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
    // The full validated report, verbatim — the machine-readable form that
    // carries the deterministic SSVC verdict and per-feed coverage.
    downloadJson(`triage-${stamp}.json`, JSON.stringify(report, null, 2));
  }

  return (
    <div id="printable-report" className="printable-report animate-fade-in space-y-4">
      <Card className="border-2 border-primary/20">
        <CardHeader className="space-y-3">
          {report.ssvc && <SsvcVerdict ssvc={report.ssvc} />}
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={cn("text-xs uppercase tracking-wider", severityClass[report.severity])}>
              {report.severity}
            </Badge>
            <Badge variant="outline" className="text-xs uppercase tracking-wider">
              {report.confidence} confidence
            </Badge>
            <div className="ml-auto flex items-center gap-1 print:hidden">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleCopyLink}
                title="Copy a shareable link; the full report is encoded in the URL fragment, never sent to a server"
              >
                <Share2 className="h-3.5 w-3.5" />
                {linkState === "copied"
                  ? "Link copied"
                  : linkState === "toolarge"
                    ? "Too large — use JSON"
                    : "Copy link"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleExportMarkdown}
                title="Export the full report as a Markdown file"
              >
                <Download className="h-3.5 w-3.5" />
                Export .md
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleExportJson}
                title="Download the full report as JSON (includes the SSVC verdict + signal coverage)"
              >
                <Braces className="h-3.5 w-3.5" />
                Export JSON
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 gap-1 text-[11px]"
                onClick={handleExportPdf}
                title="Open the print dialog; pick 'Save as PDF'"
              >
                <Printer className="h-3.5 w-3.5" />
                Export PDF
              </Button>
            </div>
          </div>
          <p className="text-base font-medium leading-relaxed">{report.summary}</p>
        </CardHeader>
        <CardContent className="space-y-4">
          <Separator />
          <div>
            <div className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Recommended action
            </div>
            <p className="whitespace-pre-line text-sm leading-relaxed">{report.recommended_action}</p>
          </div>
        </CardContent>
      </Card>

      {report.signal_coverage?.length > 0 && (
        <SignalCoverageStrip coverage={report.signal_coverage} />
      )}

      {report.cves.length > 0 && (
        <div className="space-y-3">
          <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            CVEs ({report.cves.length})
          </div>
          {report.cves.map((cve) => {
            const { body, fenced } = unfence(cve.summary);
            return (
              <Card key={cve.cve_id} id={`cve-${cve.cve_id}`} className="scroll-mt-20 overflow-hidden">
                <CardHeader className="space-y-2 pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <a
                      href={cve.nvd_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-sm font-semibold text-primary hover:underline"
                    >
                      {cve.cve_id}
                      <ExternalLink className="ml-1 inline h-3 w-3" />
                    </a>
                    <Badge className={cn("text-[10px] uppercase", severityClass[cve.severity])}>
                      {cve.severity}
                    </Badge>
                    {cve.cvss_v3_score !== null && (
                      <Badge variant="outline" className="text-[10px]">
                        CVSS {cve.cvss_v3_score.toFixed(1)}
                      </Badge>
                    )}
                    {cve.exploits_public ? (
                      <Badge variant="destructive" className="gap-1 text-[10px]">
                        <ShieldX className="h-3 w-3" /> exploit public
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="gap-1 text-[10px]">
                        <ShieldCheck className="h-3 w-3" /> no public exploit
                      </Badge>
                    )}
                    {cve.in_kev_catalog && (
                      <Badge variant="destructive" className="gap-1 text-[10px]">
                        <Flame className="h-3 w-3" />
                        CISA KEV
                        {cve.kev_due_date ? ` · due ${cve.kev_due_date}` : ""}
                      </Badge>
                    )}
                    {cve.known_ransomware_use && (
                      <Badge variant="destructive" className="gap-1 text-[10px]">
                        <Skull className="h-3 w-3" /> ransomware
                      </Badge>
                    )}
                    {cve.epss_probability !== null && (
                      <Badge
                        variant={cve.epss_probability >= 0.5 ? "destructive" : "outline"}
                        className="gap-1 text-[10px]"
                      >
                        <TrendingUp className="h-3 w-3" />
                        EPSS {(cve.epss_probability * 100).toFixed(1)}%
                        {cve.epss_percentile !== null
                          ? ` (p${(cve.epss_percentile * 100).toFixed(0)})`
                          : ""}
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3 pt-0">
                  <div>
                    {fenced && (
                      <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                        NVD description (untrusted vendor text)
                      </div>
                    )}
                    <p className={cn("text-sm leading-relaxed", fenced && "border-l-2 border-muted pl-3 text-muted-foreground")}>
                      {body}
                    </p>
                  </div>
                  {cve.affected_products.length > 0 && (
                    <div>
                      <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                        Affected
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {cve.affected_products.map((p) => (
                          <Badge key={p} variant="secondary" className="font-mono text-[10px]">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {report.attack_techniques.length > 0 && (
        <AttackSection techniques={report.attack_techniques} />
      )}

      <ReasoningChain steps={report.reasoning_chain} />
    </div>
  );
}

function SsvcVerdict({ ssvc }: { ssvc: SsvcAssessment }) {
  const meta = SSVC_META[ssvc.decision];
  const Icon = meta.icon;
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        <ShieldAlert className="h-3.5 w-3.5" />
        SSVC verdict
        <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] normal-case tracking-normal text-muted-foreground">
          deterministic · server-computed
        </span>
      </div>
      <div
        className="grid grid-cols-4 gap-1"
        role="group"
        aria-label={`SSVC decision: ${ssvc.decision}`}
      >
        {SSVC_ORDER.map((decision) => {
          const active = decision === ssvc.decision;
          const stopMeta = SSVC_META[decision];
          const StopIcon = stopMeta.icon;
          return (
            <div
              key={decision}
              aria-current={active ? "true" : undefined}
              className={cn(
                "flex items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-semibold transition-colors",
                active ? stopMeta.activeClass : "bg-muted/40 text-muted-foreground/50",
              )}
            >
              <StopIcon className="h-3.5 w-3.5 shrink-0" />
              <span>{decision}</span>
            </div>
          );
        })}
      </div>
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
        <div className="space-y-0.5">
          <p className="text-sm leading-relaxed">{ssvc.rationale || meta.blurb}</p>
          <p className="text-[11px] text-muted-foreground">
            rule <span className="font-mono">{ssvc.rule}</span>
            {ssvc.driving_cve ? (
              <>
                {" · driven by "}
                <a
                  href={`#cve-${ssvc.driving_cve}`}
                  className="font-mono text-primary hover:underline"
                >
                  {ssvc.driving_cve}
                </a>
              </>
            ) : null}
          </p>
        </div>
      </div>
    </div>
  );
}

function SignalCoverageStrip({ coverage }: { coverage: FeedStatus[] }) {
  if (!coverage || coverage.length === 0) return null;
  return (
    <div className="rounded-lg border border-border bg-card/50 p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        <Radar className="h-3.5 w-3.5" />
        Signal coverage
        <span className="normal-case tracking-normal text-muted-foreground/70">
          what each feed actually returned
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {coverage.map((feed) => {
          const statusMeta = COVERAGE_META[feed.status] ?? COVERAGE_META.not_queried;
          const StatusIcon = statusMeta.icon;
          return (
            <span
              key={feed.feed}
              title={feed.detail ?? undefined}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2 py-1 text-[11px]"
            >
              <StatusIcon className={cn("h-3.5 w-3.5 shrink-0", statusMeta.className)} />
              <span className="font-mono">{feed.feed}</span>
              <span className="text-muted-foreground">{statusMeta.label}</span>
            </span>
          );
        })}
      </div>
    </div>
  );
}

function AttackSection({ techniques }: { techniques: TriageReport["attack_techniques"] }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        <Crosshair className="h-3 w-3" />
        MITRE ATT&CK ({techniques.length})
      </div>
      {techniques.map((technique) => (
        <Card key={technique.id} className="overflow-hidden">
          <CardHeader className="space-y-2 pb-3">
            <div className="flex flex-wrap items-center gap-2">
              <a
                href={technique.url}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-sm font-semibold text-primary hover:underline"
              >
                {technique.id}
                <ExternalLink className="ml-1 inline h-3 w-3" />
              </a>
              <span className="text-sm font-medium">{technique.name}</span>
            </div>
            <div className="flex flex-wrap items-center gap-1">
              {technique.tactics.map((tactic) => (
                <Badge key={tactic} variant="secondary" className="text-[10px]">
                  {tactic}
                </Badge>
              ))}
              {technique.related_cwes.length > 0 && (
                <span className="ml-2 text-[10px] text-muted-foreground">
                  triggered by {technique.related_cwes.join(", ")}
                </span>
              )}
            </div>
          </CardHeader>
          {technique.mitigations.length > 0 && (
            <CardContent className="pt-0">
              <div className="mb-1.5 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                <Wrench className="h-3 w-3" />
                Mitigations
              </div>
              <ul className="space-y-1 text-xs">
                {technique.mitigations.map((m) => (
                  <li key={m.id} className="flex items-start gap-2">
                    <a
                      href={m.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-primary hover:underline"
                    >
                      {m.id}
                    </a>
                    <span className="leading-snug">{m.name}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          )}
        </Card>
      ))}
    </div>
  );
}

function ReasoningChain({ steps }: { steps: string[] }) {
  const [open, setOpen] = useState(false);
  if (steps.length === 0) return null;

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <Card>
        <CollapsibleTrigger asChild>
          <button className="flex w-full items-center justify-between p-4 text-left transition-colors hover:bg-accent">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Reasoning chain
              </span>
              <Badge variant="secondary" className="text-[10px]">
                {steps.length} steps
              </Badge>
            </div>
            <ChevronDown
              className={cn(
                "h-4 w-4 text-muted-foreground transition-transform",
                open && "rotate-180",
              )}
            />
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <Separator />
          <CardContent className="pt-4">
            <ol className="space-y-2 text-sm">
              {steps.map((step, i) => (
                <li key={i} className="flex gap-3">
                  <span className="select-none font-mono text-xs text-muted-foreground">
                    {(i + 1).toString().padStart(2, "0")}
                  </span>
                  <span className="leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
