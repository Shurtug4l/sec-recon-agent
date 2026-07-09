"use client";

import { useEffect, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  ExternalLink,
  Gauge,
  Layers,
  MessageSquare,
  Share2,
} from "lucide-react";
import type { ElementType } from "react";

import { Header } from "@/components/header";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DEMO_MODE } from "@/demo/config";
import { SECTIONS } from "@/lib/guide-data";
import { cn } from "@/lib/utils";

const INPUT_TYPES: { label: string; example: string; desc: string }[] = [
  {
    label: "A CVE ID",
    example: "CVE-2021-44228",
    desc: "The full NVD record plus every operational signal (KEV, EPSS, exploits, patch) fan out in parallel.",
  },
  {
    label: "A package at a version",
    example: "log4j-core 2.14.1",
    desc: "OSV.dev advisories for that exact package and version: the inverse of a CVE lookup.",
  },
  {
    label: "A natural-language question",
    example: "Is my Spring app exposed to Spring4Shell?",
    desc: "Semantic search over a local index of recent high-severity CVEs when there is no explicit ID.",
  },
  {
    label: "An SBOM",
    example: "CycloneDX / SPDX / requirements.txt",
    desc: "Paste it to bulk-triage the most-likely-vulnerable components in one pass.",
  },
  {
    label: "Nmap XML",
    example: "nmap -oX scan.xml",
    desc: "Service banners become CVE queries; parsing is XXE-safe (defusedxml, no DTD).",
  },
];

const SSVC_LADDER: { decision: string; when: string }[] = [
  {
    decision: "Act",
    when: "Remediate now. The CVE is on CISA KEV, or associated with ransomware, or has a public exploit paired with a high EPSS probability.",
  },
  {
    decision: "Attend",
    when: "Prioritize in the fast lane of the normal cycle. A public exploit already exists, or EPSS predicts high near-term exploitation (probability >= 0.5, or percentile >= 0.95).",
  },
  {
    decision: "Track*",
    when: "Watch closely. EPSS is elevated (probability >= 0.1) but below the high band, or CVSS severity is high or critical with no exploitation signal observed yet; a pre-mortem signal, not an emergency.",
  },
  {
    decision: "Track",
    when: "Routine handling. No KEV listing, no known exploit, low exploitation probability.",
  },
];

const REPORT_PARTS: { label: string; desc: string }[] = [
  {
    label: "Signal coverage",
    desc: "A per-feed strip: found / no entry / error / not queried. Honesty about what the agent actually reached; a feed that was down is shown, never silently skipped.",
  },
  {
    label: "CVE cards",
    desc: "CVSS score and vector, CISA KEV membership and due date, EPSS probability and percentile, ransomware association, and the concrete fixed version when one exists.",
  },
  {
    label: "ATT&CK techniques",
    desc: "The underlying weakness classes (CWE) mapped to MITRE ATT&CK techniques and mitigations, so the report speaks the language of detection engineering.",
  },
  {
    label: "Reasoning waterfall",
    desc: "Every Pydantic AI node with its measured duration, plus token usage and cost for the run. The reasoning chain is the audit log, not a black box.",
  },
];

function StartTriagePanel() {
  return (
    <div className="space-y-4 text-sm leading-relaxed">
      <p className="text-foreground/90">
        Open the{" "}
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[12px]">
          Triage
        </code>{" "}
        tab and describe what to assess. The agent selects the tools from the
        shape of the input; you never wire them by hand. Five accepted inputs:
      </p>
      <div className="grid gap-2 sm:grid-cols-2">
        {INPUT_TYPES.map((it) => (
          <div key={it.label} className="rounded-md border border-border bg-card p-3">
            <div className="flex flex-wrap items-baseline gap-2">
              <span className="text-sm font-semibold">{it.label}</span>
              <code className="font-mono text-[11px] text-muted-foreground">
                {it.example}
              </code>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              {it.desc}
            </p>
          </div>
        ))}
      </div>
      {DEMO_MODE && (
        <p className="rounded-md border border-primary/30 bg-primary/5 p-3 text-xs leading-relaxed text-muted-foreground">
          In this hosted demo the Triage tab replays seven real captured runs
          (model sonnet against the live stack, captured 2026-07-02), covering
          the full SSVC ladder from Act to Track. Pick one from the example
          gallery; free-text input matches only those seven (a CVE id from the
          set works too). Replay pacing is compressed so you are not waiting
          out the real 35-135 second runs; the waterfall durations shown are
          the real measured ones. Clone the repo to run the live agent on
          arbitrary input.
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        The report streams in node by node as the agent reasons; a single-CVE
        triage typically settles in under two minutes.
      </p>
    </div>
  );
}

function ReadVerdictPanel() {
  return (
    <div className="space-y-4 text-sm leading-relaxed">
      <p className="text-foreground/90">
        The verdict is the headline of the report. SSVC (Stakeholder-Specific
        Vulnerability Categorization) is the decision framework CISA uses for
        remediation urgency, built to replace sorting by CVSS score with a
        decision over exploitation evidence and impact. Here it is computed
        server-side from the collected signals, never guessed by the model,
        and it is SSVC-informed rather than a certified implementation: a
        stateless triage tool cannot know your asset criticality, so
        ransomware association and CVSS severity stand in for the impact axis.
        Four rungs, most urgent first:
      </p>
      <ul className="space-y-2">
        {SSVC_LADDER.map((s) => (
          <li key={s.decision} className="flex gap-3">
            <code className="mt-0.5 shrink-0 rounded bg-primary/10 px-2 py-0.5 font-mono text-[12px] font-semibold text-primary">
              {s.decision}
            </code>
            <span className="text-sm leading-relaxed text-muted-foreground">
              {s.when}
            </span>
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted-foreground">
        The rationale names the driving CVE and the rule that fired, and links
        straight to that CVE&apos;s card.
      </p>
    </div>
  );
}

function ReadReportPanel() {
  return (
    <div className="space-y-3 text-sm leading-relaxed">
      {REPORT_PARTS.map((p) => (
        <div key={p.label}>
          <p className="text-sm font-semibold">{p.label}</p>
          <p className="text-sm leading-relaxed text-muted-foreground">{p.desc}</p>
        </div>
      ))}
    </div>
  );
}

function ExportSharePanel() {
  return (
    <div className="space-y-2 text-sm leading-relaxed text-foreground/90">
      <p>
        Every report exports to <span className="font-semibold">Markdown</span>{" "}
        (for a ticket or a wiki) or raw{" "}
        <span className="font-semibold">JSON</span> (the exact TriageReport,
        for downstream tooling).
      </p>
      <p>
        <span className="font-semibold">Copy link</span> encodes the whole
        report into a URL fragment, compressed client-side. The fragment never
        leaves the browser for the server, so a shared link round-trips the
        report through the read-only{" "}
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[12px]">
          /r
        </code>{" "}
        route with zero backend storage.
      </p>
    </div>
  );
}

interface GuideItem {
  id: string;
  navLabel: string;
  title: string;
  icon: ElementType;
  badge: string | null;
  render: () => React.ReactNode;
}

// Part 1 keeps its own ids (not in guide-data.ts on purpose: the palette
// surfaces the 12 glossary sections; these four are guide-internal steps).
const DRIVING: GuideItem[] = [
  {
    id: "start-triage",
    navLabel: "1 · Start a triage",
    title: "Start a triage",
    icon: MessageSquare,
    badge: null,
    render: StartTriagePanel,
  },
  {
    id: "read-verdict",
    navLabel: "2 · Read the verdict",
    title: "Read the SSVC verdict",
    icon: Gauge,
    badge: null,
    render: ReadVerdictPanel,
  },
  {
    id: "read-report",
    navLabel: "3 · Read the report",
    title: "Read the rest of the report",
    icon: Layers,
    badge: null,
    render: ReadReportPanel,
  },
  {
    id: "export-share",
    navLabel: "4 · Export & share",
    title: "Export & share",
    icon: Share2,
    badge: null,
    render: ExportSharePanel,
  },
];

const GLOSSARY: GuideItem[] = SECTIONS.map((sec) => ({
  id: sec.id,
  navLabel: sec.shortLabel,
  title: sec.title,
  icon: sec.icon,
  badge: sec.badge,
  render: function GlossaryPanel() {
    return (
      <div className="space-y-4 text-sm leading-relaxed">
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            What it is
          </p>
          <p className="text-foreground/90">{sec.what}</p>
        </div>
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            Why it appears here
          </p>
          <p className="text-foreground/90">{sec.whyHere}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            Used by
          </span>
          {sec.used.map((u) => (
            <code key={u} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
              {u}
            </code>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3 pt-2">
          <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            Refs
          </span>
          {sec.refs.map((r) => (
            <a
              key={r.href}
              href={r.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
            >
              {r.label}
              <ExternalLink className="h-3 w-3" />
            </a>
          ))}
        </div>
      </div>
    );
  },
}));

const ALL_ITEMS: GuideItem[] = [...DRIVING, ...GLOSSARY];

// Master-detail: the left rail selects, the panel renders ONE item at a time
// (app idiom over document idiom - this page was a 7,400px wall of cards).
// Selection is hash-driven so palette commands and deep links keep working:
// /guide#kev selects the KEV panel, and the rail items are real anchors.
export default function GuidePage() {
  const [activeId, setActiveId] = useState<string>(ALL_ITEMS[0].id);

  useEffect(() => {
    const apply = () => {
      const h = window.location.hash.replace(/^#/, "");
      if (h && ALL_ITEMS.some((i) => i.id === h)) setActiveId(h);
    };
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  const idx = ALL_ITEMS.findIndex((i) => i.id === activeId);
  const item = ALL_ITEMS[idx];
  const prev = idx > 0 ? ALL_ITEMS[idx - 1] : null;
  const next = idx < ALL_ITEMS.length - 1 ? ALL_ITEMS[idx + 1] : null;
  const Icon = item.icon;

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="flex-1">
        <div className="container max-w-6xl py-8">
          <div className="mb-6">
            <Badge variant="secondary" className="mb-3 font-mono text-[10px]">
              How to use it &amp; glossary
            </Badge>
            <h1 className="text-3xl font-semibold tracking-tight">Guide</h1>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              How to drive the agent, then a working glossary of the security
              frameworks and data sources under the hood. Pick a topic from
              the rail; every entry is deep-linkable.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-[230px_1fr] lg:gap-8">
            {/* Master rail: chip row below lg, left rail with group labels on lg+. */}
            <aside className="lg:sticky lg:top-24 lg:self-start">
              <nav
                aria-label="Guide topics"
                className="flex gap-1.5 overflow-x-auto pb-2 lg:flex-col lg:gap-0 lg:overflow-visible lg:pb-0"
              >
                <p className="hidden lg:mb-2 lg:block lg:text-[10px] lg:font-semibold lg:uppercase lg:tracking-widest lg:text-muted-foreground">
                  Driving the agent
                </p>
                {DRIVING.map((i) => (
                  <RailLink key={i.id} item={i} active={i.id === activeId} />
                ))}
                <p className="hidden lg:mb-2 lg:mt-5 lg:block lg:text-[10px] lg:font-semibold lg:uppercase lg:tracking-widest lg:text-muted-foreground">
                  Frameworks under the hood
                </p>
                {GLOSSARY.map((i) => (
                  <RailLink key={i.id} item={i} active={i.id === activeId} />
                ))}
              </nav>
            </aside>

            {/* Detail panel: keyed remount re-runs the fade on selection. */}
            <div key={item.id} className="min-w-0 animate-fade-in">
              <Card>
                <CardHeader>
                  <div className="flex flex-wrap items-center gap-2">
                    <Icon className="h-4 w-4 text-primary" />
                    <CardTitle className="text-base">{item.title}</CardTitle>
                    {item.badge && (
                      <Badge variant="secondary" className="font-mono text-[10px]">
                        {item.badge}
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  {item.render()}
                  <div className="rule-hairline mt-6" aria-hidden />
                  <div className="mt-4 flex items-center justify-between gap-3">
                    {prev ? (
                      <a
                        href={`#${prev.id}`}
                        className="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
                      >
                        <ArrowLeft className="h-3.5 w-3.5" />
                        {prev.title}
                      </a>
                    ) : (
                      <span />
                    )}
                    <span className="shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">
                      {idx + 1} / {ALL_ITEMS.length}
                    </span>
                    {next ? (
                      <a
                        href={`#${next.id}`}
                        className="inline-flex items-center gap-1.5 text-right text-xs font-medium text-primary transition-colors hover:underline"
                      >
                        {next.title}
                        <ArrowRight className="h-3.5 w-3.5" />
                      </a>
                    ) : (
                      <span />
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

function RailLink({ item, active }: { item: GuideItem; active: boolean }) {
  return (
    <a
      href={`#${item.id}`}
      aria-current={active ? "true" : undefined}
      className={cn(
        // Chip on mobile, borderless rail row on lg+.
        "shrink-0 whitespace-nowrap rounded-full border border-border px-3 py-1.5 text-xs transition-colors",
        "lg:block lg:rounded-none lg:border-0 lg:border-l-2 lg:px-3 lg:py-1.5",
        active
          ? "border-primary bg-primary/10 text-primary lg:border-l-primary lg:bg-transparent"
          : "text-muted-foreground hover:border-primary/40 hover:text-foreground lg:border-l-transparent lg:hover:border-l-border",
      )}
    >
      {item.navLabel}
    </a>
  );
}
