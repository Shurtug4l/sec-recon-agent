// Decoder for shared-report permalinks. The fragment is attacker-controlled:
// anyone can mint a link with any bytes, so this module treats it as untrusted
// input all the way down. Every limit below fails closed to `null`, which /r
// renders as its "Could not read" state.
//
// No value imports on purpose: scripts/shared-report.test.mjs runs this file
// directly under Node, with no bundler or path aliases.

import type {
  AttackMitigation,
  AttackTechnique,
  CVEReference,
  FeedStatus,
  GroundingAssessment,
  GroundingClaim,
  SsvcAssessment,
  TriageReport,
} from "./types";

// Soft ceiling on the encoded payload, enforced when minting. Beyond this the
// URL gets unwieldy and some clients truncate.
export const PERMALINK_MAX = 16_000;
// Hard ceiling when reading: a little slack over the mint cap, so no legitimate
// link is refused and an oversized one never reaches the decoder.
export const FRAGMENT_MAX = Math.ceil(PERMALINK_MAX * 1.25);
// A few KB of gzip can expand to gigabytes, and the view renders what it gets.
export const DECOMPRESSED_MAX = 256 * 1024;
// The query rides along clipped to this, plus one truncation mark.
export const SHARED_QUERY_MAX = 4_000;

// Scheme markers so a payload is self-describing (compressed vs plain).
export const GZIP = "1";
export const PLAIN = "0";

// What a decoded permalink yields: the report plus the query that produced it
// (absent on legacy links minted before the envelope, and on reports shared
// without a query in scope).
export interface SharedReport {
  report: TriageReport;
  query?: string;
  queryTruncated?: boolean;
}

function b64UrlToBytes(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// Streams the decompression with a byte counter: `Response.text()` would buffer
// the whole output first, which is exactly what a gzip bomb wants.
async function gunzipBounded(bytes: Uint8Array): Promise<string | null> {
  // Copy into a fresh ArrayBuffer so the Blob part is unambiguously a BlobPart
  // across TS lib versions: TS 5.7+ made TypedArrays generic over their backing
  // buffer, and a bare Uint8Array (Uint8Array<ArrayBufferLike>) is not a
  // BlobPart, whereas a plain ArrayBuffer always is.
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const reader = new Blob([buffer])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"))
    .getReader();
  const decoder = new TextDecoder();
  let text = "";
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return text + decoder.decode();
    total += value.byteLength;
    if (total > DECOMPRESSED_MAX) {
      await reader.cancel();
      return null;
    }
    text += decoder.decode(value, { stream: true });
  }
}

// ---------------------------------------------------------------------------
// Validation: a hand-kept mirror of agent/schema.py, like types.ts. Absent
// fields take the same defaults Pydantic gives them, so links minted before a
// field existed still read. Each builder copies known fields only, so the view
// never receives anything this file did not look at.
// ---------------------------------------------------------------------------

// The schema leaves reasoning_chain uncapped; only the node count matters here,
// DECOMPRESSED_MAX already bounds the bytes. Matches the agent_tool_calls ceiling.
const MAX_REASONING_STEPS = 1_000;
// Pydantic's HttpUrl limit.
const MAX_URL = 2_083;

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const CONFIDENCES = ["high", "medium", "low"] as const;
const SSVC_DECISIONS = ["Act", "Attend", "Track*", "Track"] as const;
const SSVC_BASES = ["evidence", "mixed", "report"] as const;
const SIGNAL_STATUSES = ["found", "not_found", "error", "not_queried"] as const;
const GROUNDING_STATUSES = ["grounded", "suspect", "not_evaluated"] as const;
const CLAIM_STATUSES = ["supported", "unbacked", "mismatch", "unverifiable"] as const;

const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;
const MITIGATION_ID = /^M\d{4}$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

// Thrown by the builders and caught once in parseReport: one bad field rejects
// the whole report, and the nested builders stay free of null plumbing.
class Invalid extends Error {}

type Fields = Record<string, unknown>;

function fields(value: unknown): Fields {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Invalid();
  return value as Fields;
}

// Pydantic's max_length counts code points, JS .length counts UTF-16 units: an
// emoji at the cap is valid on the server and two units here.
function text(value: unknown, max: number): string {
  if (typeof value !== "string") throw new Invalid();
  if (value.length > max && [...value].length > max) throw new Invalid();
  return value;
}

// A string the schema leaves uncapped: DECOMPRESSED_MAX is the bound.
function freeText(value: unknown): string {
  if (typeof value !== "string") throw new Invalid();
  return value;
}

function textOrNull(value: unknown, max: number): string | null {
  return value === undefined || value === null ? null : text(value, max);
}

function matching(value: unknown, pattern: RegExp): string {
  if (typeof value !== "string" || value.length > 64 || !pattern.test(value)) throw new Invalid();
  return value;
}

function member<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (!allowed.includes(value as T)) throw new Invalid();
  return value as T;
}

function bool(value: unknown, fallback?: boolean): boolean {
  if (value === undefined && fallback !== undefined) return fallback;
  if (typeof value !== "boolean") throw new Invalid();
  return value;
}

function boolOrNull(value: unknown): boolean | null {
  return value === undefined || value === null ? null : bool(value);
}

function numberInRange(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) {
    throw new Invalid();
  }
  return value;
}

function numberOrNull(value: unknown, min: number, max: number): number | null {
  return value === undefined || value === null ? null : numberInRange(value, min, max);
}

function count(value: unknown): number {
  if (value === undefined) return 0;
  const n = numberInRange(value, 0, Number.MAX_SAFE_INTEGER);
  if (!Number.isInteger(n)) throw new Invalid();
  return n;
}

function list<T>(value: unknown, max: number, item: (entry: unknown) => T): T[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > max) throw new Invalid();
  return value.map(item);
}

function httpUrl(value: unknown): string {
  let url: URL;
  try {
    url = new URL(text(value, MAX_URL));
  } catch {
    throw new Invalid();
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Invalid();
  // The parsed form: URL strips the newlines a raw string could smuggle along.
  return url.href;
}

function cveReference(value: unknown): CVEReference {
  const v = fields(value);
  // The schema leaves this a bare str and the model writes it, so a stray space
  // or a prose date is a real report: drop the date, keep the report. The view
  // prints it inside the KEV badge, so only a date may land in that chrome.
  const due = textOrNull(v.kev_due_date, MAX_URL)?.trim();
  return {
    cve_id: matching(v.cve_id, CVE_ID),
    summary: text(v.summary, 1_000),
    cvss_v3_score: numberOrNull(v.cvss_v3_score, 0, 10),
    severity: member(v.severity, SEVERITIES),
    exploits_public: bool(v.exploits_public),
    affected_products: list(v.affected_products, 20, freeText),
    nvd_url: httpUrl(v.nvd_url),
    in_kev_catalog: bool(v.in_kev_catalog, false),
    kev_due_date: due && ISO_DATE.test(due) ? due : null,
    known_ransomware_use: boolOrNull(v.known_ransomware_use),
    epss_probability: numberOrNull(v.epss_probability, 0, 1),
    epss_percentile: numberOrNull(v.epss_percentile, 0, 1),
  };
}

function attackMitigation(value: unknown): AttackMitigation {
  const v = fields(value);
  return {
    id: matching(v.id, MITIGATION_ID),
    name: freeText(v.name),
    url: httpUrl(v.url),
  };
}

function attackTechnique(value: unknown): AttackTechnique {
  const v = fields(value);
  return {
    id: matching(v.id, TECHNIQUE_ID),
    name: freeText(v.name),
    tactics: list(v.tactics, 12, freeText),
    url: httpUrl(v.url),
    mitigations: list(v.mitigations, 15, attackMitigation),
    related_cwes: list(v.related_cwes, 20, freeText),
  };
}

function ssvcAssessment(value: unknown): SsvcAssessment | null {
  if (value === undefined || value === null) return null;
  const v = fields(value);
  const assessment: SsvcAssessment = {
    decision: member(v.decision, SSVC_DECISIONS),
    rule: text(v.rule, 64),
    rationale: text(v.rationale, 500),
    driving_cve:
      v.driving_cve === undefined || v.driving_cve === null ? null : matching(v.driving_cve, CVE_ID),
  };
  // Optional in the view too: captures recorded before these fields existed.
  if (v.basis !== undefined) assessment.basis = member(v.basis, SSVC_BASES);
  if (v.unverified_signals !== undefined) {
    assessment.unverified_signals = list(v.unverified_signals, 50, freeText);
  }
  return assessment;
}

function feedStatus(value: unknown): FeedStatus {
  const v = fields(value);
  return {
    feed: text(v.feed, 40),
    status: member(v.status, SIGNAL_STATUSES),
    detail: textOrNull(v.detail, 200),
  };
}

function groundingClaim(value: unknown): GroundingClaim {
  const v = fields(value);
  return {
    subject: text(v.subject, 40),
    field: text(v.field, 40),
    status: member(v.status, CLAIM_STATUSES),
    detail: textOrNull(v.detail, 200),
  };
}

function groundingAssessment(value: unknown): GroundingAssessment | null {
  if (value === undefined || value === null) return null;
  const v = fields(value);
  return {
    status: member(v.status, GROUNDING_STATUSES),
    claims_checked: count(v.claims_checked),
    supported: count(v.supported),
    unbacked: count(v.unbacked),
    mismatched: count(v.mismatched),
    unverifiable: count(v.unverifiable),
    findings: list(v.findings, 40, groundingClaim),
    truncated: bool(v.truncated, false),
  };
}

/** The validated, field-by-field copy of a report, or null if any field fails. */
export function parseReport(value: unknown): TriageReport | null {
  try {
    const v = fields(value);
    return {
      summary: text(v.summary, 500),
      severity: member(v.severity, SEVERITIES),
      confidence: member(v.confidence, CONFIDENCES),
      recommended_action: text(v.recommended_action, 500),
      cves: list(v.cves, 10, cveReference),
      attack_techniques: list(v.attack_techniques, 20, attackTechnique),
      reasoning_chain: list(v.reasoning_chain, MAX_REASONING_STEPS, freeText),
      ssvc: ssvcAssessment(v.ssvc),
      signal_coverage: list(v.signal_coverage, 16, feedStatus),
      grounding: groundingAssessment(v.grounding),
    };
  } catch (error) {
    if (error instanceof Invalid) return null;
    throw error;
  }
}

/** Decode a raw `#r=` fragment value. Null for anything but a valid report. */
export async function decodeReport(fragment: string): Promise<SharedReport | null> {
  if (fragment.length > FRAGMENT_MAX) return null;
  try {
    const encoded = decodeURIComponent(fragment);
    const scheme = encoded.slice(0, 1);
    const bytes = b64UrlToBytes(encoded.slice(1));
    let json: string | null;
    if (scheme === GZIP) json = await gunzipBounded(bytes);
    else if (scheme === PLAIN) json = new TextDecoder().decode(bytes);
    else return null;
    if (json === null) return null;

    const parsed: unknown = JSON.parse(json);
    // Envelope (P8+): { v, query?, report }. Legacy (pre-P8): a bare report.
    if (parsed && typeof parsed === "object" && "report" in parsed) {
      const env = parsed as {
        v?: unknown;
        report: unknown;
        query?: unknown;
        queryTruncated?: unknown;
      };
      if (env.v !== 1) return null;
      const report = parseReport(env.report);
      if (!report) return null;
      if (env.query === undefined) return { report, queryTruncated: env.queryTruncated === true };
      // +1: the truncation mark appended when minting.
      if (typeof env.query !== "string" || env.query.length > SHARED_QUERY_MAX + 1) return null;
      return { report, query: env.query, queryTruncated: env.queryTruncated === true };
    }
    const report = parseReport(parsed);
    return report ? { report } : null;
  } catch {
    return null;
  }
}
