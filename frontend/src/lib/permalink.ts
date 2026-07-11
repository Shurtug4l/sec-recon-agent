// Self-contained shareable reports. A completed TriageReport is serialized,
// gzip-compressed (native CompressionStream, no dependency), and base64url-
// encoded into a URL fragment. The fragment lives after '#', so it is NEVER
// sent to the server: decoding happens entirely client-side on the /r route.
// No backend, no storage, no leak.

import { DEMO_MODE } from "@/demo/config";
import type { TriageReport } from "./types";

// Scheme markers so a payload is self-describing (compressed vs plain).
const GZIP = "1";
const PLAIN = "0";

// Same env var that drives basePath in next.config.mjs, inlined at build time.
// Without it, share links minted on a sub-path host (GitHub Pages) would point
// at the domain root and 404.
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH || "";

// Demo exports build with trailingSlash (next.config.mjs), so /r is served as
// a directory; emit the canonical /r/ form there and skip the host's redirect.
const R_PATH = `${BASE_PATH}/r${DEMO_MODE ? "/" : ""}`;

// Soft ceiling on the encoded payload. Beyond this the URL gets unwieldy and
// some clients truncate; the caller falls back to the JSON export instead.
export const PERMALINK_MAX = 16_000;

// The originating query rides along in the envelope, but it can be a whole SBOM
// or Nmap XML. Cap it so a large query never sinks an otherwise-shareable
// report; the report is the payload, the query is context. Truncation is
// marked so the /r view can be honest that it was clipped.
const SHARED_QUERY_MAX = 4_000;
const TRUNCATION_MARK = "…";

const hasCompression =
  typeof CompressionStream !== "undefined" && typeof DecompressionStream !== "undefined";

function bytesToB64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64UrlToBytes(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function gzip(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function gunzip(bytes: Uint8Array): Promise<string> {
  // Copy into a fresh ArrayBuffer so the Blob part is unambiguously a BlobPart
  // across TS lib versions: TS 5.7+ made TypedArrays generic over their backing
  // buffer, and a bare Uint8Array (Uint8Array<ArrayBufferLike>) is not a
  // BlobPart, whereas a plain ArrayBuffer always is.
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).text();
}

// What a decoded permalink yields: the report plus the query that produced it
// (absent on legacy links minted before the envelope, and on reports shared
// without a query in scope).
export interface SharedReport {
  report: TriageReport;
  query?: string;
  queryTruncated?: boolean;
}

// Envelope written into the fragment since P8. `v` marks the shape so a later
// change is detectable; legacy links carried a bare TriageReport with no
// envelope, and decodeReport still reads them.
interface ShareEnvelope {
  v: 1;
  query?: string;
  queryTruncated?: boolean;
  report: TriageReport;
}

// Trust-but-verify the minimal report shape before handing it to the view.
function isReportShaped(value: unknown): value is TriageReport {
  return (
    !!value &&
    typeof value === "object" &&
    "summary" in value &&
    "severity" in value &&
    "cves" in value
  );
}

export async function encodeReport(report: TriageReport, query?: string): Promise<string> {
  const envelope: ShareEnvelope = { v: 1, report };
  // Keep the query out of the payload when absent so the no-query case is byte-
  // for-byte what it was before the envelope carried a query.
  if (query) {
    if (query.length > SHARED_QUERY_MAX) {
      envelope.query = query.slice(0, SHARED_QUERY_MAX) + TRUNCATION_MARK;
      envelope.queryTruncated = true;
    } else {
      envelope.query = query;
    }
  }
  const json = JSON.stringify(envelope);
  if (hasCompression) {
    return GZIP + bytesToB64Url(await gzip(json));
  }
  return PLAIN + bytesToB64Url(new TextEncoder().encode(json));
}

export async function decodeReport(encoded: string): Promise<SharedReport | null> {
  try {
    const scheme = encoded.slice(0, 1);
    const bytes = b64UrlToBytes(encoded.slice(1));
    const json =
      scheme === GZIP ? await gunzip(bytes) : new TextDecoder().decode(bytes);
    const parsed: unknown = JSON.parse(json);
    // Envelope (P8+): { v, query?, report }.
    if (parsed && typeof parsed === "object" && "report" in parsed) {
      const env = parsed as ShareEnvelope;
      if (isReportShaped(env.report)) {
        return {
          report: env.report,
          query: typeof env.query === "string" ? env.query : undefined,
          queryTruncated: env.queryTruncated === true,
        };
      }
      return null;
    }
    // Legacy (pre-P8): a bare TriageReport, no envelope, no query.
    if (isReportShaped(parsed)) {
      return { report: parsed };
    }
    return null;
  } catch {
    return null;
  }
}

/** Build the full shareable URL for a report, or null if it exceeds the cap. */
export async function buildPermalink(
  report: TriageReport,
  origin: string,
  query?: string,
): Promise<string | null> {
  const encoded = await encodeReport(report, query);
  const url = `${origin}${R_PATH}#r=${encoded}`;
  return url.length - origin.length > PERMALINK_MAX ? null : url;
}
