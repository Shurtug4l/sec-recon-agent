"use client";

import { useEffect, useState } from "react";
import {
  ExternalLink,
  Gauge,
  Layers,
  MessageSquare,
  Share2,
} from "lucide-react";

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

export default function GuidePage() {
  const [activeId, setActiveId] = useState<string>(SECTIONS[0].id);

  useEffect(() => {
    const handler = () => {
      const fromTop = window.scrollY + 120;
      let current = SECTIONS[0].id;
      for (const sec of SECTIONS) {
        const el = document.getElementById(sec.id);
        if (el && el.offsetTop <= fromTop) current = sec.id;
      }
      setActiveId(current);
    };
    handler();
    window.addEventListener("scroll", handler, { passive: true });
    return () => window.removeEventListener("scroll", handler);
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="flex-1">
        <div className="container max-w-6xl py-8">
          <div className="mb-8">
            <Badge variant="secondary" className="mb-3 font-mono text-[10px]">
              How to use it &amp; glossary
            </Badge>
            <h1 className="text-3xl font-semibold tracking-tight">Guide</h1>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              Two parts. First, how to drive the agent: what to type, and how to
              read the verdict it streams back. Then a working glossary of the
              security frameworks and data sources under the hood: what each one
              is, why it appears in the triage output, and where to read the
              primary source. Useful both for running a triage and for explaining
              the report to a stakeholder who has not seen MITRE before.
            </p>
          </div>

          {/* Part 1 - how to use the agent */}
          <section className="mb-14 space-y-5">
            <div className="flex items-baseline gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Part 1
              </span>
              <h2 className="text-xl font-semibold tracking-tight">Driving the agent</h2>
            </div>
            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <MessageSquare className="h-4 w-4 text-primary" />
                    <CardTitle className="text-base">1 &middot; Start a triage</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 text-sm leading-relaxed">
                  <p className="text-foreground/90">
                    Open the{" "}
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[12px]">
                      Triage
                    </code>{" "}
                    tab and describe what to assess. The agent selects the tools
                    from the shape of the input; you never wire them by hand.
                    Five accepted inputs:
                  </p>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {INPUT_TYPES.map((it) => (
                      <div
                        key={it.label}
                        className="rounded-md border border-border bg-card p-3"
                      >
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
                      In this hosted demo the Triage tab replays seven real
                      captured runs (model sonnet against the live stack,
                      captured 2026-07-02), covering the full SSVC ladder from
                      Act to Track. Pick one from the example gallery; free-text
                      input matches only those seven (a CVE id from the set
                      works too). Replay pacing is compressed so you are not
                      waiting out the real 35-135 second runs; the waterfall
                      durations shown are the real measured ones. Clone the repo
                      to run the live agent on arbitrary input.
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    The report streams in node by node as the agent reasons; a
                    single-CVE triage typically settles in under two minutes.
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <Gauge className="h-4 w-4 text-primary" />
                    <CardTitle className="text-base">
                      2 &middot; Read the SSVC verdict
                    </CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 text-sm leading-relaxed">
                  <p className="text-foreground/90">
                    The verdict is the headline of the report. SSVC
                    (Stakeholder-Specific Vulnerability Categorization) is the
                    decision framework CISA uses for remediation urgency, built
                    to replace sorting by CVSS score with a decision over
                    exploitation evidence and impact. Here it is computed
                    server-side from the collected signals, never guessed by the
                    model, and it is SSVC-informed rather than a certified
                    implementation: a stateless triage tool cannot know your
                    asset criticality, so ransomware association and CVSS
                    severity stand in for the impact axis. Four rungs, most
                    urgent first:
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
                    The rationale names the driving CVE and the rule that fired,
                    and links straight to that CVE&apos;s card.
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <Layers className="h-4 w-4 text-primary" />
                    <CardTitle className="text-base">
                      3 &middot; Read the rest of the report
                    </CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3 text-sm leading-relaxed">
                  {REPORT_PARTS.map((p) => (
                    <div key={p.label}>
                      <p className="text-sm font-semibold">{p.label}</p>
                      <p className="text-sm leading-relaxed text-muted-foreground">
                        {p.desc}
                      </p>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <Share2 className="h-4 w-4 text-primary" />
                    <CardTitle className="text-base">4 &middot; Export &amp; share</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2 text-sm leading-relaxed text-foreground/90">
                  <p>
                    Every report exports to{" "}
                    <span className="font-semibold">Markdown</span> (for a ticket
                    or a wiki) or raw <span className="font-semibold">JSON</span>{" "}
                    (the exact TriageReport, for downstream tooling).
                  </p>
                  <p>
                    <span className="font-semibold">Copy link</span> encodes the
                    whole report into a URL fragment, compressed client-side. The
                    fragment never leaves the browser for the server, so a shared
                    link round-trips the report through the read-only{" "}
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[12px]">
                      /r
                    </code>{" "}
                    route with zero backend storage.
                  </p>
                </CardContent>
              </Card>
            </div>
          </section>

          {/* Part 2 - glossary */}
          <div className="mb-6 flex items-baseline gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Part 2
            </span>
            <h2 className="text-xl font-semibold tracking-tight">
              Frameworks under the hood
            </h2>
          </div>

          <div className="grid grid-cols-1 gap-8 lg:grid-cols-[220px_1fr]">
            {/* TOC */}
            <aside className="lg:sticky lg:top-24 lg:self-start">
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                On this page
              </p>
              <nav className="space-y-1">
                {SECTIONS.map((sec) => (
                  <a
                    key={sec.id}
                    href={`#${sec.id}`}
                    className={cn(
                      "block border-l-2 px-3 py-1.5 text-xs transition-colors",
                      activeId === sec.id
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:border-border hover:text-foreground",
                    )}
                  >
                    {sec.shortLabel}
                  </a>
                ))}
              </nav>
            </aside>

            {/* Content */}
            <div className="space-y-6">
              {SECTIONS.map(({ id, title, badge, icon: Icon, what, whyHere, used, refs }) => (
                <Card key={id} id={id} className="scroll-mt-24">
                  <CardHeader>
                    <div className="flex flex-wrap items-center gap-2">
                      <Icon className="h-4 w-4 text-primary" />
                      <CardTitle className="text-base">{title}</CardTitle>
                      <Badge variant="secondary" className="font-mono text-[10px]">
                        {badge}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4 text-sm leading-relaxed">
                    <div>
                      <p className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                        What it is
                      </p>
                      <p className="text-foreground/90">{what}</p>
                    </div>
                    <div>
                      <p className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                        Why it appears here
                      </p>
                      <p className="text-foreground/90">{whyHere}</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                        Used by
                      </span>
                      {used.map((u) => (
                        <code
                          key={u}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                        >
                          {u}
                        </code>
                      ))}
                    </div>
                    <div className="flex flex-wrap items-center gap-3 pt-2">
                      <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                        Refs
                      </span>
                      {refs.map((r) => (
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
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
