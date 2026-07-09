"use client";

import Link from "next/link";
import {
  ArrowDown,
  ArrowLeftRight,
  ArrowRight,
  BookOpen,
  Boxes,
  Check,
  Crosshair,
  Database,
  FileSearch,
  Flame,
  Globe,
  Network,
  ScanSearch,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TrendingUp,
  Wrench,
  X,
} from "lucide-react";

import { Header } from "@/components/header";
import { GithubLogo } from "@/components/icons/github-logo";
import { SsvcLadderHero } from "@/components/ssvc-ladder-hero";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

// Stagger index for the hero's page-load reveal (P0 `.reveal` primitive;
// neutralized under prefers-reduced-motion).
function reveal(i: number): React.CSSProperties {
  return { "--reveal-i": i } as React.CSSProperties;
}

const TOOLS = [
  { name: "cve_lookup", icon: FileSearch, blurb: "Full NVD record (CVSS, CWE, CPE) for a known CVE." },
  { name: "cve_semantic_search", icon: ScanSearch, blurb: "Vector search over a local index of recent high-severity CVEs (~5-8k, 30-day window)." },
  { name: "exploit_check", icon: Wrench, blurb: "Exploit-DB + GitHub public PoC availability." },
  { name: "kev_check", icon: Flame, blurb: "CISA Known Exploited Vulnerabilities. Strongest patch-now signal." },
  { name: "epss_score", icon: TrendingUp, blurb: "FIRST.org 30-day exploitation probability + percentile." },
  { name: "patch_lookup", icon: ShieldCheck, blurb: "Fixed-version extraction from NVD CPE configurations." },
  { name: "osv_lookup", icon: ArrowLeftRight, blurb: "OSV.dev advisories for a package at a version. Inverse of cve_lookup." },
  { name: "sbom_ingest", icon: Database, blurb: "CycloneDX / SPDX / requirements.txt parser, in-process." },
  { name: "nmap_parse_xml", icon: Network, blurb: "defusedxml-safe Nmap scan parser, no DTD." },
  { name: "attack_mapping", icon: Sparkles, blurb: "CWE -> MITRE ATT&CK techniques + mitigations." },
];

const PILLARS = [
  {
    title: "Type-safe by construction",
    body: "Pydantic AI, the typed Python agent framework, validates every model output against a declared schema at the model boundary. The LLM never returns free text; it returns a TriageReport or it fails.",
  },
  {
    title: "Grounded, and verified grounded",
    body: "Every severity, CVSS score, exploit claim, and patch version is sourced from a typed tool call. After the run, a server-side verifier re-checks each claim against the actual tool output and stamps the report grounded or suspect. The reasoning chain is the audit log.",
  },
  {
    title: "Adversary-aware",
    body: "Untrusted content fenced before reaching the LLM. Prompt-injection regression battery with MITRE ATLAS per-payload tags.",
  },
  {
    title: "Privacy-by-default",
    body: "Query bodies hashed (SHA-256) in audit. Plain-text retention opt-in via env. Append-only SQLite WAL with hash chain.",
  },
];

const MANUAL_WAY = [
  "Five-plus sources opened per CVE: NVD, CISA KEV, EPSS, Exploit-DB, ATT&CK",
  "CVSS measures capability, not urgency, and gets reconciled by hand",
  "General-purpose LLMs invent scores, patches, and exploit claims",
  "No record of how the call was made when someone asks three months later",
];

const AGENT_WAY = [
  "One query returns one grounded, schema-bound TriageReport",
  "Deterministic SSVC verdict: Act / Attend / Track* / Track",
  "Every number sourced from a typed tool call, or flagged as missing",
  "Hash-chained, tamper-evident audit of the whole reasoning chain",
];

const AUDIENCES = [
  {
    role: "Vulnerability & AppSec engineers",
    icon: ShieldAlert,
    body: "Turn a CVE backlog into a defensible, prioritized queue. Feed a CVE, a package + version, or a whole SBOM and get one grounded verdict, not ten open browser tabs across NVD, KEV, EPSS, Exploit-DB and ATT&CK.",
  },
  {
    role: "SOC & detection engineers",
    icon: Crosshair,
    body: "Every report pivots the underlying CWE weakness classes into MITRE ATT&CK techniques and mitigations, the language that detection rules and purple-team exercises are actually written in.",
  },
  {
    role: "Teams building or vetting LLM agents",
    icon: Boxes,
    body: "A working reference for a grounded, type-safe, adversary-aware agent: schema-bounded output, a verdict computed outside the model, MCP tools as auditable contracts, and a falsifiable prompt-injection battery, all measured in a reproducible scorecard.",
  },
];

export default function Landing() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main id="main-content" tabIndex={-1} className="flex-1 focus-visible:outline-none">
        {/* Hero - split: copy + the signature moment (the SSVC ladder reading
            real captured verdicts). The pipeline diagram moved to its own
            "How it works" section below. */}
        <section className="relative overflow-hidden border-b border-border/60">
          <div
            aria-hidden
            className="blueprint-grid pointer-events-none absolute inset-0 opacity-70"
          />
          <div className="container relative max-w-6xl py-14 md:py-20">
            <div className="grid items-center gap-10 lg:grid-cols-2 lg:gap-14">
              <div>
                <div className="reveal" style={reveal(0)}>
                  <Badge variant="secondary" className="mb-4 font-mono text-[10px]">
                    Pydantic AI · MCP · 10 typed tools
                  </Badge>
                </div>
                <h1
                  className="reveal text-4xl font-semibold tracking-tight md:text-5xl"
                  style={reveal(1)}
                >
                  Security triage that
                  <br />
                  cites its sources.
                </h1>
                <p
                  className="reveal mt-6 max-w-xl text-base leading-relaxed text-muted-foreground"
                  style={reveal(2)}
                >
                  <span className="font-mono text-foreground">sec-recon-agent</span>{" "}
                  is an LLM agent that answers vulnerability questions by calling
                  a fixed surface of typed tools (NVD, CISA KEV, FIRST EPSS,
                  Exploit-DB, MITRE ATT&amp;CK, SBOM and Nmap parsers), exposed by
                  a custom MCP server (Model Context Protocol: the open standard
                  that gives LLM tools a typed, auditable contract), and returns a
                  strictly-typed{" "}
                  <code className="font-mono text-foreground">TriageReport</code>.
                  No hallucinated CVSS scores, no invented patches, no free-text
                  bypass.
                </p>
                <div className="reveal mt-8 flex flex-wrap items-center gap-3" style={reveal(3)}>
                  <Button asChild size="lg">
                    <Link href="/triage">
                      Start a triage <ArrowRight className="h-4 w-4" />
                    </Link>
                  </Button>
                  <Button asChild variant="outline" size="lg">
                    <Link href="/guide">
                      <BookOpen className="h-4 w-4" /> Read the guide
                    </Link>
                  </Button>
                  <Button asChild variant="ghost" size="lg">
                    <a
                      href="https://github.com/Shurtug4l/sec-recon-agent"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <GithubLogo className="h-4 w-4" /> Source on GitHub
                    </a>
                  </Button>
                </div>
                <div className="reveal" style={reveal(4)}>
                  <HeroStats />
                </div>
              </div>
              <div className="reveal lg:pl-2" style={reveal(2)}>
                <SsvcLadderHero />
              </div>
            </div>
          </div>
        </section>

        {/* How it works - the pipeline diagram, promoted from the hero to its
            own skimmable section. */}
        <section className="border-b border-border/60">
          <div className="container max-w-5xl py-12 md:py-16">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              How it works
            </h2>
            <p className="mt-4 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              The browser streams one triage over SSE through a same-origin
              proxy; the agent fans out across the typed tool surface and the
              verdict comes back schema-bound, audited, and grounded.
            </p>
            <div className="mx-auto max-w-3xl">
              <ArchitectureDiagram />
              <p className="mt-3 text-center text-[11px] leading-relaxed text-muted-foreground">
                Cross-process W3C <code className="font-mono">traceparent</code>{" "}
                · browser talks only to the same-origin proxy · SHA-256
                hash-chained, tamper-evident audit.
              </p>
            </div>
          </div>
        </section>

        {/* Why it matters + who it's for */}
        <section className="border-b border-border/60">
          <div className="container max-w-5xl py-12 md:py-16">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Why it matters
            </h2>
            <p className="mt-4 max-w-3xl text-2xl font-semibold leading-snug tracking-tight text-foreground md:text-3xl">
              Ten browser tabs and an educated guess, or one grounded verdict in
              about two minutes.
            </p>
            <p className="mt-5 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              Deciding whether a CVE (a publicly catalogued vulnerability)
              deserves an all-hands response or a slot in next sprint is judgment
              work, and today it is done by hand: NVD for the CVSS severity
              score, CISA KEV to see whether it is already being exploited in the
              wild, FIRST EPSS for the probability it will be soon, Exploit-DB
              and GitHub for public proof-of-concept exploits, then reconcile it
              all into one call. Per CVE. Reach for a general-purpose LLM to go
              faster and it will confidently hand you a CVSS score that does not
              exist. This agent runs that entire fusion across live authoritative
              feeds and returns a{" "}
              <span className="text-foreground">deterministic SSVC verdict</span>{" "}
              (Stakeholder-Specific Vulnerability Categorization, the CISA-backed
              prioritization framework): the decision is computed in code from
              the collected signals, never guessed by the model.
            </p>

            <div className="mt-8 grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-dashed border-border bg-card/40 p-5">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  The manual way
                </p>
                <ul className="mt-3 space-y-2.5">
                  {MANUAL_WAY.map((t) => (
                    <li
                      key={t}
                      className="flex gap-2.5 text-sm leading-relaxed text-muted-foreground"
                    >
                      <X className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground/70" />
                      <span>{t}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="rounded-lg border border-primary/40 bg-primary/[0.04] p-5">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-primary">
                  With sec-recon-agent
                </p>
                <ul className="mt-3 space-y-2.5">
                  {AGENT_WAY.map((t) => (
                    <li
                      key={t}
                      className="flex gap-2.5 text-sm leading-relaxed text-foreground/90"
                    >
                      <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                      <span>{t}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <p className="mt-6 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              It is not another scanner. Trivy and Grype tell you{" "}
              <span className="text-foreground">which</span> packages are
              vulnerable; sec-recon-agent is the reasoning layer that comes next,
              deciding which of those actually demand your morning and proving why
              in a{" "}
              <a
                href="https://github.com/Shurtug4l/sec-recon-agent/blob/main/SCORECARD.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline underline-offset-2 hover:decoration-2"
              >
                reproducible scorecard
              </a>
              .
            </p>

            <h2 className="mt-12 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Who it&apos;s for
            </h2>
            <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
              {AUDIENCES.map(({ role, body, icon: Icon }) => (
                <Card key={role}>
                  <CardContent className="space-y-3 p-5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 text-primary">
                      <Icon className="h-4 w-4" />
                    </div>
                    <h3 className="text-sm font-semibold">{role}</h3>
                    <p className="text-sm leading-relaxed text-muted-foreground">
                      {body}
                    </p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Pillars */}
        <section className="border-b border-border/60">
          <div className="container max-w-5xl py-12 md:py-16">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                Design pillars
              </h2>
              <Link
                href="/case-study"
                className="text-xs text-primary hover:underline"
              >
                Why these hold together: the case study &rarr;
              </Link>
            </div>
            <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
              {PILLARS.map((p) => (
                <Card key={p.title}>
                  <CardContent className="space-y-2 p-5">
                    <h3 className="text-sm font-semibold">{p.title}</h3>
                    <p className="text-sm leading-relaxed text-muted-foreground">
                      {p.body}
                    </p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Tool surface */}
        <section className="border-b border-border/60">
          <div className="container max-w-5xl py-12 md:py-16">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                Tool surface · 10 typed contracts
              </h2>
              <Link
                href="/dashboard?tab=transparency"
                className="text-xs text-primary hover:underline"
              >
                See live in Transparency &rarr;
              </Link>
            </div>
            <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {TOOLS.map(({ name, icon: Icon, blurb }) => (
                <div
                  key={name}
                  className="rounded-md border border-border bg-card p-4 transition-colors hover:border-primary/40"
                >
                  <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 text-primary" />
                    <code className="font-mono text-sm font-semibold">{name}</code>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                    {blurb}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

      </main>
    </div>
  );
}

// A compact "system status" strip under the hero copy. Structural facts about
// the design (always true, no drift), rendered as mono stat tiles so the hero
// reads like an instrument panel, not a splash page.
const HERO_STATS: { value: string; label: string }[] = [
  { value: "10", label: "typed tool contracts" },
  { value: "4-level", label: "deterministic SSVC verdict" },
  { value: "MITRE", label: "ATLAS red-team battery" },
  { value: "SHA-256", label: "tamper-evident audit" },
];

function HeroStats() {
  return (
    <dl className="mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-4">
      {HERO_STATS.map((stat) => (
        <div key={stat.label} className="bg-card px-3 py-3">
          <dt className="font-display text-lg font-semibold tabular-nums text-primary">
            {stat.value}
          </dt>
          <dd className="mt-0.5 text-[11px] leading-tight text-muted-foreground">
            {stat.label}
          </dd>
        </div>
      ))}
    </dl>
  );
}

type Accent = "default" | "primary" | "sky" | "emerald" | "rose";

// Pipeline-stage accents, driven off the unified tokens (primary + the
// colorblind-safe categorical --chart-* ramp) instead of raw Tailwind
// sky/emerald/rose literals. Keys are kept stable; the hues map to the chart
// ramp so the diagram stays consistent with the dashboard.
const ACCENT_CLASSES: Record<Accent, { ring: string; bg: string; iconBg: string }> = {
  default: {
    ring: "border-border",
    bg: "bg-background",
    iconBg: "bg-muted text-foreground",
  },
  primary: {
    ring: "border-primary/40",
    bg: "bg-primary/5",
    iconBg: "bg-primary/15 text-primary",
  },
  sky: {
    ring: "border-[hsl(var(--chart-1)/0.4)]",
    bg: "bg-[hsl(var(--chart-1)/0.06)]",
    iconBg: "bg-[hsl(var(--chart-1)/0.15)] text-[hsl(var(--chart-1))]",
  },
  emerald: {
    ring: "border-[hsl(var(--success)/0.4)]",
    bg: "bg-[hsl(var(--success)/0.06)]",
    iconBg: "bg-[hsl(var(--success)/0.15)] text-[hsl(var(--success))]",
  },
  rose: {
    ring: "border-[hsl(var(--chart-4)/0.4)]",
    bg: "bg-[hsl(var(--chart-4)/0.06)]",
    iconBg: "bg-[hsl(var(--chart-4)/0.15)] text-[hsl(var(--chart-4))]",
  },
};

function ArchitectureDiagram() {
  return (
    <div className="mt-6 rounded-xl border border-border bg-gradient-to-b from-card to-background p-6 shadow-sm md:p-8">
      <div className="mx-auto flex max-w-md flex-col items-stretch">
        <PipelineNode
          icon={Globe}
          title="Browser"
          port=":3000"
          sub="Next.js 15 App Router · React 19"
          accent="sky"
        />
        <PipelineEdge label="POST /api/triage · same-origin" />
        <PipelineNode
          icon={ArrowLeftRight}
          title="Next.js proxy"
          port="/api/triage"
          sub="forwards the SSE stream byte-for-byte"
        />
        <PipelineEdge label="SSE · text/event-stream" />
        <PipelineNode
          icon={Server}
          title="Agent API"
          port=":8000"
          sub="FastAPI · Pydantic AI · audit hook"
          accent="primary"
        />
        <PipelineEdge label="MCPToolset · HTTP+SSE" />
        <PipelineNode
          icon={Network}
          title="MCP Server"
          port=":8001"
          sub="FastMCP · 10 typed tools"
          accent="emerald"
        />
      </div>

      <div className="my-8 flex items-center gap-3">
        <div className="h-px flex-1 bg-border" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          External data sources · parallel fan-out
        </span>
        <div className="h-px flex-1 bg-border" />
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-3">
        <SourceChip icon={Database} name="NVD CVE 2.0" hint="cve_lookup · patch_lookup" />
        <SourceChip icon={ScanSearch} name="ChromaDB · MiniLM-L6" hint="cve_semantic_search" />
        <SourceChip icon={Wrench} name="Exploit-DB" hint="exploit_check" />
        <SourceChip icon={GithubLogo} name="GitHub Code Search" hint="exploit_check" />
        <SourceChip icon={Flame} name="CISA KEV" hint="kev_check" />
        <SourceChip icon={TrendingUp} name="FIRST EPSS" hint="epss_score" />
        <SourceChip icon={ArrowLeftRight} name="OSV.dev" hint="osv_lookup" />
        <SourceChip icon={Network} name="defusedxml · Nmap" hint="nmap_parse_xml" />
        <SourceChip icon={Database} name="CycloneDX / SPDX" hint="sbom_ingest" />
        <SourceChip icon={Sparkles} name="MITRE ATT&CK JSON" hint="attack_mapping" />
      </div>
    </div>
  );
}

function PipelineNode({
  icon: Icon,
  title,
  port,
  sub,
  accent = "default",
}: {
  icon: React.ElementType;
  title: string;
  port: string;
  sub: string;
  accent?: Accent;
}) {
  const a = ACCENT_CLASSES[accent];
  return (
    <div
      className={cn(
        "w-full rounded-lg border p-3 shadow-sm transition-shadow hover:shadow-md",
        a.ring,
        a.bg,
      )}
    >
      <div className="flex items-center gap-3">
        <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-md ring-1 ring-inset ring-border/60", a.iconBg)}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-sm font-semibold">{title}</span>
            <code className="font-mono text-[11px] text-muted-foreground">{port}</code>
          </div>
          <p className="truncate text-[11px] text-muted-foreground">{sub}</p>
        </div>
      </div>
    </div>
  );
}

function PipelineEdge({ label }: { label: string }) {
  return (
    <div className="my-1 flex flex-col items-center gap-1">
      <div className="h-3 w-px bg-border" />
      <code className="rounded-full border border-border bg-card px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
        {label}
      </code>
      <div className="relative h-3 w-px bg-border">
        <ArrowDown className="absolute left-1/2 top-full -translate-x-1/2 -translate-y-1/2 h-3 w-3 text-border" strokeWidth={3} />
      </div>
    </div>
  );
}

function SourceChip({
  icon: Icon,
  name,
  hint,
}: {
  icon: React.ElementType;
  name: string;
  hint: string;
}) {
  return (
    <div className="group flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 transition-colors hover:border-primary/40">
      <Icon className="h-3.5 w-3.5 shrink-0 text-primary" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-xs font-medium">{name}</p>
        <p className="truncate font-mono text-[10px] text-muted-foreground">{hint}</p>
      </div>
    </div>
  );
}
