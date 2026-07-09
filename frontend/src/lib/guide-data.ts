// Guide glossary data, extracted from app/guide/page.tsx so the command
// palette can surface sections and external references without importing
// the page component. Single source of truth for both consumers.

import type { ElementType } from "react";
import {
  BookOpen,
  Crosshair,
  Flame,
  Gavel,
  Library,
  Network,
  Package,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";

export interface Section {
  id: string;
  title: string;
  shortLabel: string;
  badge: string;
  icon: ElementType;
  what: string;
  whyHere: string;
  used: string[];
  refs: { label: string; href: string }[];
}

export const SECTIONS: Section[] = [
  {
    id: "cve-nvd",
    title: "CVE, NVD, CVSS and CWE",
    shortLabel: "CVE / NVD",
    badge: "Vulnerability ID + scoring",
    icon: ShieldAlert,
    what:
      "A CVE (Common Vulnerabilities and Exposures) is a globally unique identifier for a single, publicly disclosed vulnerability, assigned by a CVE Numbering Authority (CNA). The NVD (NIST National Vulnerability Database) enriches each CVE record with CVSS (Common Vulnerability Scoring System) v3 base scores in the range 0.0-10.0, mapped to severity bands (low / medium / high / critical), one or more CWE (Common Weakness Enumeration) identifiers describing the underlying weakness class, and CPE (Common Platform Enumeration) match expressions that pinpoint affected products and versions. CVSS is a deterministic vector of base metrics (attack vector, complexity, privileges, user interaction, scope, CIA impact), not a probability of exploitation.",
    whyHere:
      "cve_lookup pulls the full NVD 2.0 record. patch_lookup extracts fixed-version info from CPE versionEndExcluding ranges. attack_mapping turns the returned CWE IDs into ATT&CK techniques. CVSS is reported but the agent does not treat it as exploit likelihood; that is EPSS's job.",
    used: ["cve_lookup", "cve_semantic_search", "patch_lookup", "attack_mapping"],
    refs: [
      { label: "NVD home", href: "https://nvd.nist.gov/" },
      { label: "CVSS v3.1 spec", href: "https://www.first.org/cvss/v3.1/specification-document" },
      { label: "CWE list", href: "https://cwe.mitre.org/data/index.html" },
    ],
  },
  {
    id: "kev",
    title: "CISA KEV: Known Exploited Vulnerabilities",
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
    title: "FIRST EPSS: Exploit Prediction Scoring System",
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
    id: "osv",
    title: "OSV.dev: package-level advisories",
    shortLabel: "OSV.dev",
    badge: "Package + version lookup",
    icon: Package,
    what:
      "OSV.dev is Google's open vulnerability database keyed by package and version rather than by product. It aggregates CVE records, GitHub Security Advisories (GHSA), and ecosystem-native advisories (PyPI, npm, Go, Maven, crates.io, NuGet, RubyGems) into one schema with precise introduced / fixed version ranges. Where NVD answers 'what is CVE-2021-44228?', OSV answers 'is this package at this version affected by anything?'.",
    whyHere:
      "osv_lookup is the inverse of cve_lookup: given a dependency at an exact version it queries OSV.dev and returns each applicable advisory with its CVE / GHSA aliases, upstream severity, and the version boundary where the fix landed. It is the fastest path from a dependency pin ('requests 2.5.0') to a grounded verdict.",
    used: ["osv_lookup"],
    refs: [
      { label: "OSV.dev", href: "https://osv.dev/" },
      { label: "OSV schema", href: "https://ossf.github.io/osv-schema/" },
    ],
  },
  {
    id: "attack",
    title: "MITRE ATT&CK",
    shortLabel: "MITRE ATT&CK",
    badge: "Adversary TTPs",
    icon: Crosshair,
    what:
      "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics (the 'why' of an attack step: Initial Access, Execution, Persistence), techniques (the 'how': Phishing, Exploitation of Remote Services), sub-techniques, and procedures, sourced from observed real-world incidents. Each technique has a stable ID (e.g. T1190, T1059) and ships with detection guidance, data sources, and mapped mitigations.",
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
    title: "MITRE ATLAS: AI threat matrix",
    shortLabel: "MITRE ATLAS",
    badge: "Adversary TTPs for AI",
    icon: Library,
    what:
      "MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the ATT&CK-equivalent matrix for AI/ML systems: the same tactic-and-technique structure, extended to AI-specific attack surfaces. Tactics include ML Model Access, ML Attack Staging, Exfiltration, and Impact. Techniques cover LLM Prompt Injection (direct and indirect), LLM Jailbreak, Unsafe Plugin Output Handling, Exfiltration via ML Inference API, Cost Harvesting, and Denial of ML Service. ATLAS is the canonical taxonomy for talking about LLM-specific attacks in the same shape SOC teams already understand.",
    whyHere:
      "The red-team battery (sec-recon-redteam) tags every prompt-injection payload with one or more ATLAS technique IDs. The drift detector reports per-technique resistance rates so a regression on Exfiltration via ML Inference API surfaces by stable identifier rather than by free-text. The repository's authoritative mapping (with the specific T-IDs that this codebase tracks) lives in docs/mitre_atlas.md; MITRE periodically renumbers techniques, so consult that file for the version actually exercised by tests.",
    used: ["sec-recon-redteam (CLI)"],
    refs: [
      { label: "ATLAS matrix", href: "https://atlas.mitre.org/matrices/ATLAS" },
      { label: "Case studies", href: "https://atlas.mitre.org/studies" },
    ],
  },
  {
    id: "sbom",
    title: "SBOM: CycloneDX, SPDX, PEP 508",
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
      "The mapping is documented in docs/owasp_llm_top10.md with file:line citations to the actual mitigations in the codebase. The system prompt has an explicit untrusted-content fence (LLM01), the audit trail does not persist plaintext queries unless opt-in (LLM02), and the output schema enforces structure to prevent prompt-injection effects from leaking into downstream consumers (LLM05). A post-run grounding verifier re-checks every tool-derived claim against the actual tool output and stamps the report grounded or suspect (LLM09 Misinformation), and Unbounded Consumption (LLM10) is bounded by a per-request round cap plus opt-in denial-of-wallet spend ceiling, kill-switch, and egress allowlist.",
    used: ["TriageReport schema", "untrusted-content fence", "grounding verifier", "denial-of-wallet + kill-switch"],
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
      "ISO/IEC 42001:2023 is the first international standard for an AI Management System (AIMS): a Plan-Do-Check-Act framework analogous to ISO 27001 but specific to AI. Annex A enumerates 38 controls across leadership, planning, support, operation, performance evaluation, and improvement, explicitly covering responsibilities, data quality, transparency, system impact, and lifecycle management. It is certifiable, and it is the closest existing management-system scaffold for EU AI Act risk-management obligations; it is not an AI Act harmonized standard.",
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
    title: "MCP: Model Context Protocol",
    shortLabel: "MCP",
    badge: "Tool transport protocol",
    icon: Network,
    what:
      "MCP (Model Context Protocol) is Anthropic's open protocol for connecting LLMs to external tools and data sources. An MCP server exposes typed tools (name + JSON schema + handler), resources (read-only data), and prompts. Transports include stdio (local subprocess) and HTTP+SSE (remote). The protocol decouples the LLM agent from the tool implementation and gives tool I/O its own contract surface, separate from the LLM prompt.",
    whyHere:
      "The 10 tools live in a separate MCP server process (FastMCP, HTTP+SSE on :8001). The agent connects via MCPToolset. This means the tools can be reused by any MCP-aware client (Claude Desktop, future agents), and the tool surface is auditable as a stable contract independent of the prompt.",
    used: ["mcp-server :8001", "MCPToolset"],
    refs: [
      { label: "MCP spec", href: "https://modelcontextprotocol.io/" },
      { label: "Anthropic announcement", href: "https://www.anthropic.com/news/model-context-protocol" },
    ],
  },
];
