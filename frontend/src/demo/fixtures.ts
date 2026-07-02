import type { HistoryEntry, NodeEvent, TokenUsage, TriageReport } from "@/lib/types";

import apacheMina from "./fixtures/apache-mina.json";
import heartbleed from "./fixtures/heartbleed.json";
import libexpat from "./fixtures/libexpat.json";
import log4shell from "./fixtures/log4shell.json";
import regresshion from "./fixtures/regresshion.json";
import requestsVerify from "./fixtures/requests-verify.json";
import xzBackdoor from "./fixtures/xz-backdoor.json";

// One captured SSE frame, exactly as it came off the wire, plus its measured
// arrival offset from run start.
export interface RawSseFrame {
  event: "started" | "node" | "final" | "usage" | "error";
  data: unknown;
  at_ms: number;
}

// The persisted fixture shape (src/demo/fixtures/*.json). Real captures from the
// live stack; see scripts/capture-fixtures.mjs and the session notes. `frames`
// is the byte-faithful event sequence; the top-level fields are gallery
// metadata + the deterministic verdict, denormalized for convenience.
export interface DemoFixture {
  slug: string;
  cve: string;
  title: string;
  subtitle: string;
  query: string;
  model: string;
  capturedAt: string;
  decision: "Act" | "Attend" | "Track*" | "Track";
  durationMs: number;
  frames: RawSseFrame[];
}

// Gallery order: most- to least-urgent so the SSVC ladder reads top to bottom.
export const DEMO_FIXTURES: DemoFixture[] = [
  log4shell,
  heartbleed,
  regresshion,
  xzBackdoor,
  apacheMina,
  libexpat,
  requestsVerify,
] as unknown as DemoFixture[];

const BY_CVE = new Map(DEMO_FIXTURES.map((f) => [f.cve.toUpperCase(), f]));
const BY_SLUG = new Map(DEMO_FIXTURES.map((f) => [f.slug, f]));

// Match a demo query back to its fixture. The example buttons submit the exact
// captured query, but a recruiter may also paste a CVE id; match on that too.
export function matchFixture(query: string): DemoFixture | null {
  const trimmed = query.trim();
  for (const f of DEMO_FIXTURES) {
    if (f.query.trim() === trimmed) return f;
  }
  const cveMatch = trimmed.toUpperCase().match(/CVE-\d{4}-\d{4,}/);
  if (cveMatch && BY_CVE.has(cveMatch[0])) return BY_CVE.get(cveMatch[0]) ?? null;
  return null;
}

export function fixtureBySlug(slug: string): DemoFixture | null {
  return BY_SLUG.get(slug) ?? null;
}

function finalReport(fixture: DemoFixture): TriageReport | null {
  const frame = fixture.frames.find((f) => f.event === "final");
  return frame ? (frame.data as TriageReport) : null;
}

function nodeEvents(fixture: DemoFixture): NodeEvent[] {
  return fixture.frames
    .filter((f) => f.event === "node")
    .map((f) => ({ name: (f.data as { node: string }).node, atMs: f.at_ms }));
}

function usage(fixture: DemoFixture): TokenUsage | null {
  const frame = fixture.frames.find((f) => f.event === "usage");
  return frame ? (frame.data as TokenUsage) : null;
}

// A completed HistoryEntry carrying the fixture's REAL measured timing (not the
// compressed replay cadence), so the observability waterfall is honest. The id
// is deterministic per slug so re-seeding a cold-open history never duplicates.
export function historyEntryFromFixture(fixture: DemoFixture): HistoryEntry {
  return {
    id: `demo-${fixture.slug}`,
    query: fixture.query,
    report: finalReport(fixture),
    startedAt: `${fixture.capturedAt}T00:00:00.000Z`,
    durationMs: fixture.durationMs,
    error: null,
    nodeEvents: nodeEvents(fixture),
    usage: usage(fixture),
  };
}

// The cold-open seed: the whole gallery, most-urgent first.
export function demoHistorySeed(): HistoryEntry[] {
  return DEMO_FIXTURES.map(historyEntryFromFixture);
}
