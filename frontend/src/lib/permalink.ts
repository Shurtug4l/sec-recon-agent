// Self-contained shareable reports. A completed TriageReport is serialized,
// gzip-compressed (native CompressionStream, no dependency), and base64url-
// encoded into a URL fragment. The fragment lives after '#', so it is NEVER
// sent to the server: decoding happens entirely client-side on the /r route.
// No backend, no storage, no leak.

import { DEMO_MODE } from "@/demo/config";
import { GZIP, PERMALINK_MAX, PLAIN, SHARED_QUERY_MAX, decodeReport } from "./shared-report";
import type { TriageReport } from "./types";

export { decodeReport } from "./shared-report";
export type { SharedReport } from "./shared-report";

// Same env var that drives basePath in next.config.mjs, inlined at build time.
// Without it, share links minted on a sub-path host (GitHub Pages) would point
// at the domain root and 404.
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH || "";

// Demo exports build with trailingSlash (next.config.mjs), so /r is served as
// a directory; emit the canonical /r/ form there and skip the host's redirect.
const R_PATH = `${BASE_PATH}/r${DEMO_MODE ? "/" : ""}`;

// The originating query rides along in the envelope, but it can be a whole SBOM
// or Nmap XML. Cap it so a large query never sinks an otherwise-shareable
// report; the report is the payload, the query is context. Truncation is
// marked so the /r view can be honest that it was clipped.
const TRUNCATION_MARK = "…";

const hasCompression =
  typeof CompressionStream !== "undefined" && typeof DecompressionStream !== "undefined";

function bytesToB64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function gzip(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
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

/**
 * Build the full shareable URL for a report, or null if it exceeds the cap or
 * does not survive a round trip through the decoder: a link /r refuses is worse
 * than no link.
 */
export async function buildPermalink(
  report: TriageReport,
  origin: string,
  query?: string,
): Promise<string | null> {
  const encoded = await encodeReport(report, query);
  const url = `${origin}${R_PATH}#r=${encoded}`;
  if (url.length - origin.length > PERMALINK_MAX) return null;
  return (await decodeReport(encoded)) ? url : null;
}
