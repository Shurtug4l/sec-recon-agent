import type { HistoryEntry, Severity } from "./types";

// Aggregations over the local history. All pure functions so they can be
// computed inside `useMemo` and cheaply re-run when the history changes.

export interface AggregateStats {
  totalRuns: number;
  completedRuns: number;
  errorRuns: number;
  avgDurationMs: number;
  criticalCount: number;
  highCount: number;
  kevCount: number;
  ransomwareCount: number;
  highEpssCount: number;
  bySeverity: Array<{ severity: Severity; count: number }>;
  byConfidence: Array<{ confidence: string; count: number }>;
  toolCalls: Array<{ tool: string; count: number }>;
  topCves: Array<{ cveId: string; count: number; cvss: number | null }>;
  topAttackTechniques: Array<{
    id: string;
    name: string;
    tactics: string[];
    url: string;
    count: number;
  }>;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const KNOWN_TOOLS = [
  "cve_lookup",
  "cve_semantic_search",
  "exploit_check",
  "kev_check",
  "epss_score",
  "patch_lookup",
  "osv_lookup",
  "sbom_ingest",
  "nmap_parse_xml",
  "attack_mapping",
];
const HIGH_EPSS_THRESHOLD = 0.5;

export function aggregate(entries: HistoryEntry[]): AggregateStats {
  const completed = entries.filter((e) => e.report !== null);
  const errored = entries.filter((e) => e.error !== null);

  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const confidenceCounts: Record<string, number> = { high: 0, medium: 0, low: 0 };
  const toolCallCounts: Record<string, number> = {};
  for (const t of KNOWN_TOOLS) toolCallCounts[t] = 0;
  const cveCounter = new Map<string, { count: number; cvss: number | null }>();
  const attackCounter = new Map<
    string,
    { name: string; tactics: string[]; url: string; count: number }
  >();

  let durationSum = 0;
  let durationN = 0;
  let kevCount = 0;
  let ransomwareCount = 0;
  let highEpssCount = 0;

  for (const entry of completed) {
    if (!entry.report) continue;
    severityCounts[entry.report.severity]++;
    confidenceCounts[entry.report.confidence] =
      (confidenceCounts[entry.report.confidence] ?? 0) + 1;

    if (entry.durationMs !== null) {
      durationSum += entry.durationMs;
      durationN++;
    }

    for (const step of entry.report.reasoning_chain) {
      for (const tool of KNOWN_TOOLS) {
        if (step.toLowerCase().includes(tool)) {
          toolCallCounts[tool]++;
          break;
        }
      }
    }

    for (const cve of entry.report.cves) {
      const existing = cveCounter.get(cve.cve_id);
      if (existing) {
        existing.count++;
      } else {
        cveCounter.set(cve.cve_id, { count: 1, cvss: cve.cvss_v3_score });
      }
      if (cve.in_kev_catalog) kevCount++;
      if (cve.known_ransomware_use === true) ransomwareCount++;
      if (cve.epss_probability !== null && cve.epss_probability >= HIGH_EPSS_THRESHOLD) {
        highEpssCount++;
      }
    }

    for (const technique of entry.report.attack_techniques ?? []) {
      const existing = attackCounter.get(technique.id);
      if (existing) {
        existing.count++;
      } else {
        attackCounter.set(technique.id, {
          name: technique.name,
          tactics: technique.tactics,
          url: technique.url,
          count: 1,
        });
      }
    }
  }

  const bySeverity = SEVERITY_ORDER.map((s) => ({ severity: s, count: severityCounts[s] }));
  const byConfidence = ["high", "medium", "low"].map((c) => ({
    confidence: c,
    count: confidenceCounts[c] ?? 0,
  }));
  const toolCalls = KNOWN_TOOLS.map((t) => ({ tool: t, count: toolCallCounts[t] }));
  const topCves = [...cveCounter.entries()]
    .map(([cveId, v]) => ({ cveId, count: v.count, cvss: v.cvss }))
    .sort((a, b) => b.count - a.count || (b.cvss ?? 0) - (a.cvss ?? 0))
    .slice(0, 10);

  const topAttackTechniques = [...attackCounter.entries()]
    .map(([id, v]) => ({ id, name: v.name, tactics: v.tactics, url: v.url, count: v.count }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
    .slice(0, 10);

  return {
    totalRuns: entries.length,
    completedRuns: completed.length,
    errorRuns: errored.length,
    avgDurationMs: durationN > 0 ? durationSum / durationN : 0,
    criticalCount: severityCounts.critical,
    highCount: severityCounts.high,
    kevCount,
    ransomwareCount,
    highEpssCount,
    bySeverity,
    byConfidence,
    toolCalls,
    topCves,
    topAttackTechniques,
  };
}

// A real waterfall for a single run, built from the per-node arrival times
// captured client-side while the run streamed (HistoryEntry.nodeEvents). Each
// segment is the measured gap between two consecutive node events; widths are
// proportional to actual elapsed time, not synthesized. Returns [] when the
// run predates timing capture (older history) so the UI can say so honestly
// instead of inventing a timeline.
export interface WaterfallSegment {
  index: number;
  label: string;
  node: string;
  startMs: number;
  durationMs: number;
  startPct: number;
  widthPct: number;
}

const NODE_LABELS: Record<string, string> = {
  UserPromptNode: "prompt",
  ModelRequestNode: "model request",
  CallToolsNode: "tool calls",
  End: "final output",
};

export function humanizeNode(name: string): string {
  if (NODE_LABELS[name]) return NODE_LABELS[name];
  // Fall back to de-camel-casing an unknown node class name.
  return name
    .replace(/Node$/, "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase();
}

export function buildWaterfall(entry: HistoryEntry): WaterfallSegment[] {
  const events = entry.nodeEvents;
  if (!events || events.length === 0 || entry.durationMs === null) return [];
  const total = entry.durationMs || 1;
  return events.map((ev, i) => {
    const start = i === 0 ? 0 : events[i - 1].atMs;
    const duration = Math.max(0, ev.atMs - start);
    return {
      index: i,
      label: humanizeNode(ev.name),
      node: ev.name,
      startMs: start,
      durationMs: duration,
      startPct: (start / total) * 100,
      widthPct: (duration / total) * 100,
    };
  });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}
