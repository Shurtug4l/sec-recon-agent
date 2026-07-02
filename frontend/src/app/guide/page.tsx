"use client";

import { useEffect, useState } from "react";
import {
  BookOpen,
  Crosshair,
  ExternalLink,
  Flame,
  Gauge,
  Gavel,
  Layers,
  Library,
  MessageSquare,
  Network,
  Package,
  Share2,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";

import { Header } from "@/components/header";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface Section {
  id: string;
  title: string;
  shortLabel: string;
  badge: string;
  icon: React.ElementType;
  what: string;
  whyHere: string;
  used: string[];
  refs: { label: string; href: string }[];
}

const SECTIONS: Section[] = [
  {
    id: "cve-nvd",
    title: "CVE, NVD, CVSS and CWE",
    shortLabel: "CVE / NVD",
    badge: "Vulnerability ID + scoring",
    icon: ShieldAlert,
    what:
      "A CVE (Common Vulnerabilities and Exposures) is a globally unique identifier for a single, publicly disclosed vulnerability, assigned by a CVE Numbering Authority (CNA). The NVD (NIST National Vulnerability Database) enriches each CVE record with CVSS (Common Vulnerability Scoring System) v3 base scores in the range 0.0-10.0, mapped to severity bands (low / medium / high / critical), one or more CWE (Common Weakness Enumeration) identifiers describing the underlying weakness class, and CPE (Common Platform Enumeration) match expressions that pinpoint affected products and versions. CVSS is a deterministic vector of base metrics (attack vector, complexity, privileges, user interaction, scope, CIA impact), not a probability of exploitation.",
    whyHere:
      "cve_lookup pulls the full NVD 2.0 record. patch_lookup extracts fixed-version info from CPE versionEndExcluding ranges. attack_mapping turns the returned CWE IDs into ATT&CK techniques. CVSS is reported but the agent does not treat it as exploit likelihood — that is EPSS's job.",
    used: ["cve_lookup", "cve_semantic_search", "patch_lookup", "attack_mapping"],
    refs: [
      { label: "NVD home", href: "https://nvd.nist.gov/" },
      { label: "CVSS v3.1 spec", href: "https://www.first.org/cvss/v3.1/specification-document" },
      { label: "CWE list", href: "https://cwe.mitre.org/data/index.html" },
    ],
  },
  {
    id: "kev",
    title: "CISA KEV — Known Exploited Vulnerabilities",
    shortLabel: "CISA KEV",
    badge: "Patch-now signal",
    icon: Flame,
    what:
      "The CISA KEV catalog is a curated, evidence-based list maintained by the US Cybersecurity and Infrastructure Security Agency of CVEs that have been observed exploited in the wild. Federal civilian agencies are mandated by Binding Operational Directive 22-01 to remediate KEV-listed vulnerabilities by a specific due date. Each entry includes the vendor, product, vulnerability name, the due date, an optional notes field, and (since 2023) a `knownRansomwareCampaignUse` flag.",
    whyHere:
      "kev_check is the strongest 'patch now' signal in the triage. Unlike CVSS (capability) or EPSS (prediction), KEV is observed reality. When a CVE is on KEV, the recommended_action escalates regardless of CVSS, and the ransomware flag surfaces explicitly in the report.",
    used: ["kev_check"],
    refs: [
      { label: "KEV catalog", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "BOD 22-01", href: "https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities" },
    ],
  },
  {
    id: "epss",
    title: "FIRST EPSS — Exploit Prediction Scoring System",
    shortLabel: "EPSS",
    badge: "Forward-looking probability",
    icon: TrendingUp,
    what:
      "EPSS, maintained by FIRST.org, is a daily-updated machine-learning model that estimates the probability that a CVE will be exploited in the next 30 days, plus a percentile rank against the rest of the CVE space. Inputs include CVE metadata, public-exploit availability, vendor product data, and dark-web/threat-intel signals. The model is open and the methodology is published; the raw scores are free via API.",
    whyHere:
      "epss_score complements KEV: KEV is binary and lagging (it requires observed exploitation), EPSS is continuous and forward-looking. A high EPSS without KEV listing is a 'pre-mortem' signal for prioritization. The agent reports both, and the dashboard counts CVEs with EPSS >= 0.5 as 'High EPSS'.",
    used: ["epss_score"],
    refs: [
      { label: "EPSS home", href: "https://www.first.org/epss/" },
      { label: "Model paper", href: "https://arxiv.org/abs/2302.14172" },
    ],
  },
  {
    id: "attack",
    title: "MITRE ATT&CK",
    shortLabel: "MITRE ATT&CK",
    badge: "Adversary TTPs",
    icon: Crosshair,
    what:
      "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics (the 'why' of an attack step — e.g. Initial Access, Execution, Persistence), techniques (the 'how' — e.g. Phishing, Exploitation of Remote Services), sub-techniques, and procedures, sourced from observed real-world incidents. Each technique has a stable ID (e.g. T1190, T1059) and ships with detection guidance, data sources, and mapped mitigations.",
    whyHere:
      "attack_mapping turns the CWE IDs surfaced by cve_lookup into ATT&CK techniques + mitigations. This pivots the report from defect-class (CWE) to attacker-behavior (ATT&CK), which is the language SOC and red-team teams actually use to plan detections and exercises.",
    used: ["attack_mapping"],
    refs: [
      { label: "ATT&CK Enterprise", href: "https://attack.mitre.org/matrices/enterprise/" },
      { label: "Mitigations", href: "https://attack.mitre.org/mitigations/enterprise/" },
    ],
  },
  {
    id: "atlas",
    title: "MITRE ATLAS — AI threat matrix",
    shortLabel: "MITRE ATLAS",
    badge: "Adversary TTPs for AI",
    icon: Library,
    what:
      "MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the ATT&CK-equivalent matrix for AI/ML systems. Tactics include AI Model Access, ML Attack Staging, Exfiltration via AI Inference API, Persistence, and Impact. Techniques cover LLM Prompt Injection (direct and indirect), LLM Jailbreak, LLM Plugin Compromise, Unsafe Plugin Output Handling, Exfiltration via Inference API, Denial of AI Service, Cost Harvesting, External Harms. ATLAS is the canonical taxonomy for talking about LLM-specific attacks in the same shape SOC teams already understand.",
    whyHere:
      "The red-team battery (sec-recon-redteam) tags every prompt-injection payload with one or more ATLAS technique IDs. The drift detector reports per-technique resistance rates so a regression on Exfiltration via Inference API surfaces by stable identifier rather than by free-text. The repository's authoritative mapping (with the specific T-IDs that this codebase tracks) lives in docs/mitre_atlas.md; MITRE periodically renumbers techniques, so consult that file for the version actually exercised by tests.",
    used: ["sec-recon-redteam (CLI)"],
    refs: [
      { label: "ATLAS matrix", href: "https://atlas.mitre.org/matrices/ATLAS" },
      { label: "Case studies", href: "https://atlas.mitre.org/studies" },
    ],
  },
  {
    id: "sbom",
    title: "SBOM — CycloneDX, SPDX, PEP 508",
    shortLabel: "SBOM",
    badge: "Software inventory",
    icon: Package,
    what:
      "A Software Bill of Materials enumerates every component (library, container, OS package) in a piece of software, with version and an optional package URL (purl) for canonical identification. CycloneDX is the OWASP standard (JSON or XML; this codebase consumes the 1.x JSON shape only). SPDX 2.x JSON is the Linux Foundation / ISO/IEC 5962:2021 standard. The Python requirements.txt heuristic here accepts a strict subset of PEP 508 (lines of the form name==version or name>=version). US Executive Order 14028 and several EU directives push SBOM as a mandatory artifact for software supply-chain transparency.",
    whyHere:
      "sbom_ingest parses any of the three formats in-process (no network), returning a normalized component list (name, version, purl, type). The agent then runs cve_semantic_search and cve_lookup against the most-likely-vulnerable components, batching tool calls. This is the bulk-triage entry point: paste an SBOM, get a prioritized risk list.",
    used: ["sbom_ingest", "cve_semantic_search", "cve_lookup"],
    refs: [
      { label: "CycloneDX spec", href: "https://cyclonedx.org/specification/overview/" },
      { label: "SPDX spec", href: "https://spdx.dev/" },
      { label: "purl spec", href: "https://github.com/package-url/purl-spec" },
    ],
  },
  {
    id: "nmap",
    title: "Nmap XML output",
    shortLabel: "Nmap XML",
    badge: "Network scan ingestion",
    icon: Network,
    what:
      "Nmap's `-oX` flag produces a structured XML report of a network scan: hosts, open ports, detected services, version banners (when -sV is used), OS fingerprints, script results. The XML format is stable and is the canonical ingestion shape for downstream tools.",
    whyHere:
      "nmap_parse_xml uses defusedxml with forbid_dtd=True to neutralize XXE before parsing. The structured output (host, port, service, product, version) is fed back to cve_semantic_search to surface CVEs matching the discovered service banners. Untrusted strings (banners can be attacker-controlled) are fenced as UNTRUSTED_CONTENT before reaching the LLM.",
    used: ["nmap_parse_xml", "cve_semantic_search"],
    refs: [
      { label: "Nmap XML reference", href: "https://nmap.org/book/output-formats-xml-output.html" },
      { label: "defusedxml", href: "https://github.com/tiran/defusedxml" },
    ],
  },
  {
    id: "owasp",
    title: "OWASP LLM Top 10",
    shortLabel: "OWASP LLM",
    badge: "LLM application risks",
    icon: ShieldCheck,
    what:
      "The OWASP Top 10 for Large Language Model Applications is a curated list of the most critical risks in production LLM systems. The 2025 edition covers LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector & Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.",
    whyHere:
      "The mapping is documented in docs/owasp_llm_top10.md with file:line citations to the actual mitigations in the codebase. The system prompt has an explicit untrusted-content fence (LLM01), the audit trail does not persist plaintext queries unless opt-in (LLM02), and the output schema enforces structure to prevent prompt-injection effects from leaking into downstream consumers (LLM05).",
    used: ["TriageReport schema", "untrusted-content fence", "audit privacy"],
    refs: [
      { label: "OWASP LLM Top 10 (2025)", href: "https://genai.owasp.org/llm-top-10/" },
    ],
  },
  {
    id: "iso42001",
    title: "ISO/IEC 42001:2023",
    shortLabel: "ISO 42001",
    badge: "AI management system",
    icon: Gavel,
    what:
      "ISO/IEC 42001:2023 is the first international standard for an AI Management System (AIMS): a Plan-Do-Check-Act framework analogous to ISO 27001 but specific to AI. Annex A enumerates 38 controls across leadership, planning, support, operation, performance evaluation, and improvement — explicitly covering responsibilities, data quality, transparency, system impact, and lifecycle management. It is the certifiable spine for EU AI Act risk management for high-risk systems.",
    whyHere:
      "docs/iso_42001.md maps the relevant Annex A controls to where they are implemented or explicitly out of scope. The TriageReport schema, the audit trail, the red-team battery, and the published threat-model documents satisfy the transparency, traceability, and risk-control clauses for a small portfolio-scale AIMS.",
    used: ["docs/iso_42001.md", "audit trail", "red-team battery"],
    refs: [
      { label: "ISO 42001 overview", href: "https://www.iso.org/standard/81230.html" },
    ],
  },
  {
    id: "pydantic-ai",
    title: "Pydantic AI",
    shortLabel: "Pydantic AI",
    badge: "Typed LLM agent framework",
    icon: BookOpen,
    what:
      "Pydantic AI is a Python framework for building agentic systems where the LLM output is constrained by a Pydantic model. Tools are typed Python functions, the model is selected per agent, and the iteration is exposed as an async stream of nodes (UserPromptNode, ModelRequestNode, CallToolsNode, End). The framework enforces schema validation at the model boundary: an output that does not match the declared schema raises before reaching the caller.",
    whyHere:
      "The agent is a Pydantic AI agent with TriageReport as the output type. The SSE stream emits one node event per Pydantic AI node, so the UI can render the reasoning step-by-step. Tool calls are typed by MCP contracts (see below); the LLM cannot invent arguments.",
    used: ["agent boundary"],
    refs: [
      { label: "Pydantic AI docs", href: "https://ai.pydantic.dev/" },
    ],
  },
  {
    id: "mcp",
    title: "MCP — Model Context Protocol",
    shortLabel: "MCP",
    badge: "Tool transport protocol",
    icon: Network,
    what:
      "MCP (Model Context Protocol) is Anthropic's open protocol for connecting LLMs to external tools and data sources. A MCP server exposes typed tools (name + JSON schema + handler), resources (read-only data), and prompts. Transports include stdio (local subprocess) and HTTP+SSE (remote). The protocol decouples the LLM agent from the tool implementation and gives tool I/O its own contract surface, separate from the LLM prompt.",
    whyHere:
      "The 10 tools live in a separate MCP server process (FastMCP, HTTP+SSE on :8001). The agent connects via MCPToolset. This means the tools can be reused by any MCP-aware client (Claude Desktop, future agents), and the tool surface is auditable as a stable contract independent of the prompt.",
    used: ["mcp-server :8001", "MCPToolset"],
    refs: [
      { label: "MCP spec", href: "https://modelcontextprotocol.io/" },
      { label: "Anthropic announcement", href: "https://www.anthropic.com/news/model-context-protocol" },
    ],
  },
];

const INPUT_TYPES: { label: string; example: string; desc: string }[] = [
  {
    label: "A CVE ID",
    example: "CVE-2021-44228",
    desc: "The full NVD record plus every operational signal (KEV, EPSS, exploits, patch) fan out in parallel.",
  },
  {
    label: "A package at a version",
    example: "log4j-core 2.14.1",
    desc: "OSV.dev advisories for that exact package and version — the inverse lookup.",
  },
  {
    label: "A natural-language question",
    example: "Is my Spring app exposed to Spring4Shell?",
    desc: "Semantic search over ~20k recent high-severity CVEs when there is no explicit ID.",
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
    when: "Prioritize in the fast lane of the normal cycle. A public exploit already exists, or EPSS is elevated.",
  },
  {
    decision: "Track*",
    when: "Watch closely. High severity but no confirmed exploitation yet; a pre-mortem signal, not an emergency.",
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

          {/* Part 1 — how to use the agent */}
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
                    The verdict is the headline of the report. It is computed
                    server-side from the operational signals, not guessed by the
                    model, and answers a single question: how urgently does this
                    need action? Four rungs, most urgent first:
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

          {/* Part 2 — glossary */}
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
