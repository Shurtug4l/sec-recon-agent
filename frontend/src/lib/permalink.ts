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

export async function encodeReport(report: TriageReport): Promise<string> {
  const json = JSON.stringify(report);
  if (hasCompression) {
    return GZIP + bytesToB64Url(await gzip(json));
  }
  return PLAIN + bytesToB64Url(new TextEncoder().encode(json));
}

export async function decodeReport(encoded: string): Promise<TriageReport | null> {
  try {
    const scheme = encoded.slice(0, 1);
    const bytes = b64UrlToBytes(encoded.slice(1));
    const json =
      scheme === GZIP ? await gunzip(bytes) : new TextDecoder().decode(bytes);
    const parsed: unknown = JSON.parse(json);
    // Trust-but-verify the minimal shape before handing it to the report view.
    if (
      parsed &&
      typeof parsed === "object" &&
      "summary" in parsed &&
      "severity" in parsed &&
      "cves" in parsed
    ) {
      return parsed as TriageReport;
    }
    return null;
  } catch {
    return null;
  }
}

/** Build the full shareable URL for a report, or null if it exceeds the cap. */
export async function buildPermalink(report: TriageReport, origin: string): Promise<string | null> {
  const encoded = await encodeReport(report);
  const url = `${origin}${R_PATH}#r=${encoded}`;
  return url.length - origin.length > PERMALINK_MAX ? null : url;
}
