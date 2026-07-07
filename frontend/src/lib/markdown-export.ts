/**
 * Render a TriageReport as a Markdown document. Used by the
 * "Export as Markdown" button on the report view. Pure function, no
 * side effects - the file/download trigger lives in the component.
 *
 * The output mirrors the on-screen layout: header + summary +
 * recommended action + per-CVE details + ATT&CK techniques +
 * reasoning chain. Free-text fields are passed through verbatim
 * (they were already fenced at the tool boundary on the backend
 * before reaching the model).
 */

import type {
  TriageReport,
  CVEReference,
  AttackTechnique,
  SsvcAssessment,
  FeedStatus,
} from "./types";

const UNTRUSTED_START = "<UNTRUSTED_CONTENT>";
const UNTRUSTED_END = "</UNTRUSTED_CONTENT>";

function stripFence(text: string): string {
  const t = text.trim();
  if (t.startsWith(UNTRUSTED_START) && t.endsWith(UNTRUSTED_END)) {
    return t.slice(UNTRUSTED_START.length, -UNTRUSTED_END.length).trim();
  }
  return text;
}

function formatYesNo(value: boolean | null | undefined): string {
  if (value === true) return "yes";
  if (value === false) return "no";
  return "unknown";
}

function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return "n/a";
  return `${(value * 100).toFixed(1)}%`;
}

function renderCve(cve: CVEReference): string {
  const lines: string[] = [];
  lines.push(`### ${cve.cve_id}`);
  lines.push("");
  lines.push(`- **Severity**: ${cve.severity}`);
  if (cve.cvss_v3_score !== null) {
    lines.push(`- **CVSS v3**: ${cve.cvss_v3_score.toFixed(1)}`);
  }
  lines.push(`- **Public exploit**: ${formatYesNo(cve.exploits_public)}`);
  if (cve.in_kev_catalog) {
    const due = cve.kev_due_date ? ` (CISA due ${cve.kev_due_date})` : "";
    lines.push(`- **CISA KEV**: yes${due}`);
  } else {
    lines.push(`- **CISA KEV**: no`);
  }
  if (cve.known_ransomware_use !== null) {
    lines.push(`- **Known ransomware use**: ${formatYesNo(cve.known_ransomware_use)}`);
  }
  if (cve.epss_probability !== null) {
    const pct = cve.epss_percentile !== null ? ` (p${(cve.epss_percentile * 100).toFixed(0)})` : "";
    lines.push(`- **EPSS**: ${formatPercent(cve.epss_probability)}${pct}`);
  }
  if (cve.affected_products.length > 0) {
    lines.push(`- **Affected**: ${cve.affected_products.join(", ")}`);
  }
  lines.push(`- **NVD**: ${cve.nvd_url}`);
  lines.push("");
  lines.push("> " + stripFence(cve.summary).replace(/\n/g, "\n> "));
  lines.push("");
  return lines.join("\n");
}

function renderTechnique(t: AttackTechnique): string {
  const lines: string[] = [];
  const tactics = t.tactics.length > 0 ? ` _(tactics: ${t.tactics.join(", ")})_` : "";
  lines.push(`### ${t.id} - ${t.name}${tactics}`);
  lines.push("");
  lines.push(`- **Reference**: ${t.url}`);
  if (t.related_cwes.length > 0) {
    lines.push(`- **Triggered by**: ${t.related_cwes.join(", ")}`);
  }
  if (t.mitigations.length > 0) {
    lines.push(`- **Mitigations**:`);
    for (const m of t.mitigations) {
      lines.push(`  - ${m.id} - ${m.name} (${m.url})`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

function renderSsvc(ssvc: SsvcAssessment): string {
  const lines: string[] = [];
  lines.push("## SSVC verdict");
  lines.push("");
  lines.push("_Deterministic prioritization, computed server-side from the collected signals (not the LLM)._");
  lines.push("");
  lines.push(`- **Decision**: ${ssvc.decision}`);
  lines.push(`- **Rule**: \`${ssvc.rule}\``);
  if (ssvc.driving_cve) {
    lines.push(`- **Driving CVE**: ${ssvc.driving_cve}`);
  }
  lines.push("");
  lines.push(ssvc.rationale);
  lines.push("");
  return lines.join("\n");
}

function renderCoverage(coverage: FeedStatus[]): string {
  const lines: string[] = [];
  lines.push(`## Signal coverage (${coverage.length} feeds)`);
  lines.push("");
  lines.push("| Feed | Status | Detail |");
  lines.push("|---|---|---|");
  for (const f of coverage) {
    lines.push(`| ${f.feed} | ${f.status} | ${f.detail ?? ""} |`);
  }
  lines.push("");
  return lines.join("\n");
}

export function reportToMarkdown(report: TriageReport, query?: string): string {
  const now = new Date().toISOString().replace(/T.*/, "");
  const lines: string[] = [];

  lines.push("# Triage report");
  lines.push("");
  lines.push(`- **Severity**: ${report.severity}`);
  lines.push(`- **Confidence**: ${report.confidence}`);
  lines.push(`- **Generated**: ${now}`);
  if (query) {
    const oneLineQuery = query.length > 200 ? query.slice(0, 200) + "..." : query;
    lines.push(`- **Query**: \`${oneLineQuery.replace(/`/g, "\\`")}\``);
  }
  lines.push("");

  if (report.ssvc) {
    lines.push(renderSsvc(report.ssvc));
  }

  lines.push("## Summary");
  lines.push("");
  lines.push(stripFence(report.summary));
  lines.push("");

  lines.push("## Recommended action");
  lines.push("");
  lines.push(stripFence(report.recommended_action));
  lines.push("");

  if (report.signal_coverage?.length > 0) {
    lines.push(renderCoverage(report.signal_coverage));
  }

  if (report.cves.length > 0) {
    lines.push(`## CVEs (${report.cves.length})`);
    lines.push("");
    for (const cve of report.cves) {
      lines.push(renderCve(cve));
    }
  }

  if (report.attack_techniques.length > 0) {
    lines.push(`## MITRE ATT&CK techniques (${report.attack_techniques.length})`);
    lines.push("");
    for (const t of report.attack_techniques) {
      lines.push(renderTechnique(t));
    }
  }

  if (report.reasoning_chain.length > 0) {
    lines.push(`## Reasoning chain (${report.reasoning_chain.length} steps)`);
    lines.push("");
    report.reasoning_chain.forEach((step, i) => {
      lines.push(`${i + 1}. ${step}`);
    });
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push("_Generated by sec-recon-agent._");
  lines.push("");

  return lines.join("\n");
}

/**
 * Trigger a browser download of the markdown payload. Lives next to
 * `reportToMarkdown` so the component only imports one symbol; the
 * DOM-y bits stay out of the component body.
 */
export function downloadMarkdown(filename: string, contents: string): void {
  triggerDownload(filename, contents, "text/markdown;charset=utf-8");
}

/**
 * Trigger a browser download of the report as raw JSON - the full validated
 * shape, including the SSVC verdict and per-feed coverage.
 */
export function downloadJson(filename: string, contents: string): void {
  triggerDownload(filename, contents, "application/json;charset=utf-8");
}

function triggerDownload(filename: string, contents: string, mime: string): void {
  const blob = new Blob([contents], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Browsers handle the eventual revocation, but releasing the object
  // URL on the next tick prevents the underlying blob from staying
  // referenced until GC.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
