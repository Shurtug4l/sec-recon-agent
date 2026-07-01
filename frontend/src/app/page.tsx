"use client";

import Link from "next/link";
import {
  ArrowDown,
  ArrowLeftRight,
  ArrowRight,
  BookOpen,
  BarChart3,
  Database,
  Eye,
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
} from "lucide-react";

import { Header } from "@/components/header";
import { GithubLogo } from "@/components/icons/github-logo";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const TOOLS = [
  { name: "cve_lookup", icon: FileSearch, blurb: "Full NVD record (CVSS, CWE, CPE) for a known CVE." },
  { name: "cve_semantic_search", icon: ScanSearch, blurb: "Vector search over ~20k recent high-severity CVEs." },
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
    body: "Pydantic AI enforces the output schema. The LLM never returns free text; it returns a TriageReport or it fails.",
  },
  {
    title: "Grounded, never invented",
    body: "Every severity, CVSS score, exploit claim, and patch version is sourced from a typed tool call. The reasoning chain is the audit log.",
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

export default function Landing() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="flex-1">
        {/* Hero — split: copy + a real signature (the live pipeline diagram) */}
        <section className="relative overflow-hidden border-b border-border/60">
          <div
            aria-hidden
            className="blueprint-grid pointer-events-none absolute inset-0 opacity-70"
          />
          <div className="container relative max-w-6xl py-14 md:py-20">
            <div className="grid items-center gap-10 lg:grid-cols-2 lg:gap-14">
              <div>
                <Badge variant="secondary" className="mb-4 font-mono text-[10px]">
                  Pydantic AI · MCP · 10 typed tools
                </Badge>
                <h1 className="text-4xl font-semibold tracking-tight md:text-5xl">
                  Security triage that
                  <br />
                  cites its sources.
                </h1>
                <p className="mt-6 max-w-xl text-base leading-relaxed text-muted-foreground">
                  <span className="font-mono text-foreground">sec-recon-agent</span>{" "}
                  answers vulnerability questions by calling a fixed surface of
                  typed tools (NVD, CISA KEV, FIRST EPSS, Exploit-DB, MITRE
                  ATT&amp;CK, SBOM and Nmap parsers) and returns a strictly-typed{" "}
                  <code className="font-mono text-foreground">TriageReport</code>.
                  No hallucinated CVSS, no invented patches, no free-text bypass.
                </p>
                <div className="mt-8 flex flex-wrap items-center gap-3">
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
                <HeroStats />
              </div>
              <div className="lg:pl-2">
                <ArchitectureDiagram />
                <p className="mt-3 text-center text-[11px] leading-relaxed text-muted-foreground">
                  Cross-process W3C <code className="font-mono">traceparent</code>{" "}
                  · browser talks only to the same-origin proxy · SHA-256
                  hash-chained, tamper-evident audit.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Pillars */}
        <section className="border-b border-border/60">
          <div className="container max-w-5xl py-12 md:py-16">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Design pillars
            </h2>
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
                href="/dashboard"
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

        {/* Quick nav to sections */}
        <section>
          <div className="container max-w-5xl py-12 md:py-16">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Where to go next
            </h2>
            <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <NavCard
                href="/triage"
                icon={ShieldAlert}
                title="Triage"
                blurb="Run a query against the live agent. CVE, version, SBOM, Nmap."
              />
              <NavCard
                href="/dashboard"
                icon={BarChart3}
                title="Dashboard"
                blurb="Statistics, observability timeline, transparency on tools and prompt."
              />
              <NavCard
                href="/guide"
                icon={BookOpen}
                title="Guide"
                blurb="What is MITRE ATT&CK, ATLAS, CISA KEV, EPSS, CVSS, SBOM. Glossary + references."
              />
            </div>
            <div className="mt-8 flex flex-wrap items-center gap-3 rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
              <Eye className="h-4 w-4 shrink-0 text-primary" />
              <span>
                Transparency lives at{" "}
                <Link href="/dashboard" className="text-primary hover:underline">
                  /dashboard
                </Link>
                : system prompt, tool inventory, and the architectural guarantees
                that bound what the agent can do.
              </span>
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
  { value: "4-stop", label: "deterministic SSVC verdict" },
  { value: "MITRE", label: "ATLAS red-team battery" },
  { value: "SHA-256", label: "tamper-evident audit" },
];

function HeroStats() {
  return (
    <dl className="mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-4">
      {HERO_STATS.map((stat) => (
        <div key={stat.label} className="bg-card px-3 py-3">
          <dt className="font-mono text-lg font-semibold tabular-nums text-primary">
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

function NavCard({
  href,
  icon: Icon,
  title,
  blurb,
}: {
  href: string;
  icon: React.ElementType;
  title: string;
  blurb: string;
}) {
  return (
    <Link
      href={href}
      className="group rounded-md border border-border bg-card p-5 transition-all hover:border-primary/60 hover:shadow-sm"
    >
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-primary" />
        <span className="text-sm font-semibold">{title}</span>
        <ArrowRight className="ml-auto h-3.5 w-3.5 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
      </div>
      <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
        {blurb}
      </p>
    </Link>
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
