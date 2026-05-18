"use client";

import Link from "next/link";
import {
  ArrowRight,
  BookOpen,
  BarChart3,
  Database,
  Eye,
  FileSearch,
  Flame,
  Network,
  ScanSearch,
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

const TOOLS = [
  { name: "cve_lookup", icon: FileSearch, blurb: "Full NVD record (CVSS, CWE, CPE) for a known CVE." },
  { name: "cve_semantic_search", icon: ScanSearch, blurb: "Vector search over ~20k recent high-severity CVEs." },
  { name: "exploit_check", icon: Wrench, blurb: "Exploit-DB + GitHub public PoC availability." },
  { name: "kev_check", icon: Flame, blurb: "CISA Known Exploited Vulnerabilities. Strongest patch-now signal." },
  { name: "epss_score", icon: TrendingUp, blurb: "FIRST.org 30-day exploitation probability + percentile." },
  { name: "patch_lookup", icon: ShieldCheck, blurb: "Fixed-version extraction from NVD CPE configurations." },
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
        {/* Hero */}
        <section className="border-b border-border/60">
          <div className="container max-w-5xl py-16 md:py-24">
            <Badge variant="secondary" className="mb-4 font-mono text-[10px]">
              Pydantic AI · MCP · 9 typed tools
            </Badge>
            <h1 className="text-4xl font-semibold tracking-tight md:text-5xl">
              Security triage that
              <br />
              cites its sources.
            </h1>
            <p className="mt-6 max-w-2xl text-base leading-relaxed text-muted-foreground">
              <span className="font-mono text-foreground">sec-recon-agent</span>{" "}
              answers vulnerability questions by calling a fixed surface of typed
              tools (NVD, CISA KEV, FIRST EPSS, Exploit-DB, MITRE ATT&amp;CK, SBOM
              and Nmap parsers) and returns a strictly-typed{" "}
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
                Tool surface · 9 typed contracts
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

        {/* Architecture sketch */}
        <section className="border-b border-border/60">
          <div className="container max-w-5xl py-12 md:py-16">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              How it fits together
            </h2>
            <div className="mt-6 overflow-x-auto">
              <pre className="rounded-md border border-border bg-card p-4 font-mono text-xs leading-relaxed text-muted-foreground">
{`Browser :3000  --POST /api/triage-->  Next.js proxy  --SSE-->  Agent API :8000
                                                                     |
                                                          Pydantic AI agent
                                                                     |
                                                       MCPToolset (HTTP+SSE)
                                                                     v
                                                        MCP Server :8001
                                                        9 typed tools
                                                                     |
                              +-- NVD CVE 2.0 ---------------+--------+
                              +-- ChromaDB (ONNX MiniLM-L6) -+
                              +-- Exploit-DB + GitHub -------+
                              +-- CISA KEV ------------------+
                              +-- FIRST EPSS ----------------+
                              +-- defusedxml (Nmap, no-DTD) -+
                              +-- ATT&CK bundled JSON -------+`}
              </pre>
            </div>
            <p className="mt-4 text-xs text-muted-foreground">
              Cross-process W3C <code className="font-mono">traceparent</code>{" "}
              propagation. Browser only talks to the Next.js same-origin proxy.
              Audit trail in SQLite WAL with SHA-256 hash chain (append-only
              triggers; tamper-evident).
            </p>
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
