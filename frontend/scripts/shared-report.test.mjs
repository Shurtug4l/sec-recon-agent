// Contract tests for the permalink decoder (src/lib/shared-report.ts): the
// fragment is attacker-controlled, so each limit is exercised with a hostile
// link, and every committed demo capture proves legitimate links still read.
// Node's own test runner: the frontend carries no test dependency.
//
//   npm run test:contracts

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  DECOMPRESSED_MAX,
  FRAGMENT_MAX,
  GZIP,
  PLAIN,
  SHARED_QUERY_MAX,
  decodeReport,
  parseReport,
} from "../src/lib/shared-report.ts";

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "../src/demo/fixtures");

const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function gzip(text) {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const link = async (payload) =>
  GZIP + b64url(await gzip(typeof payload === "string" ? payload : JSON.stringify(payload)));

const REPORT = {
  summary: "Path traversal in Apache 2.4.49.",
  severity: "critical",
  confidence: "high",
  recommended_action: "Upgrade to 2.4.51.",
  cves: [
    {
      cve_id: "CVE-2021-41773",
      summary: "Path traversal.",
      cvss_v3_score: 7.5,
      severity: "high",
      exploits_public: true,
      affected_products: ["apache httpd"],
      nvd_url: "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
      in_kev_catalog: true,
      kev_due_date: "2021-11-17",
      known_ransomware_use: false,
      epss_probability: 0.94,
      epss_percentile: 0.99,
    },
  ],
  attack_techniques: [],
  reasoning_chain: ["cve_lookup returned the record"],
  ssvc: {
    decision: "Act",
    rule: "kev-active-exploitation",
    rationale: "On the KEV catalog.",
    driving_cve: "CVE-2021-41773",
    basis: "evidence",
    unverified_signals: [],
  },
  signal_coverage: [{ feed: "nvd", status: "found", detail: null }],
  grounding: {
    status: "grounded",
    claims_checked: 5,
    supported: 5,
    unbacked: 0,
    mismatched: 0,
    unverifiable: 0,
    findings: [],
    truncated: false,
  },
};

const mutate = (change) => {
  const copy = structuredClone(REPORT);
  change(copy);
  return copy;
};

test("a report round-trips through the envelope, with its query", async () => {
  const decoded = await decodeReport(await link({ v: 1, query: "CVE-2021-41773", report: REPORT }));
  assert.deepEqual(decoded?.report, REPORT);
  assert.equal(decoded?.query, "CVE-2021-41773");
});

test("a legacy bare report still reads, plain or gzip", async () => {
  assert.deepEqual((await decodeReport(await link(REPORT)))?.report, REPORT);
  const plain = PLAIN + b64url(new TextEncoder().encode(JSON.stringify(REPORT)));
  assert.deepEqual((await decodeReport(plain))?.report, REPORT);
});

test("fields a report predates take the schema defaults", () => {
  const old = mutate((r) => {
    delete r.attack_techniques;
    delete r.reasoning_chain;
    delete r.signal_coverage;
    delete r.grounding;
    delete r.ssvc;
    delete r.cves[0].kev_due_date;
    delete r.cves[0].epss_probability;
  });
  const parsed = parseReport(old);
  assert.deepEqual(parsed?.attack_techniques, []);
  assert.deepEqual(parsed?.reasoning_chain, []);
  assert.equal(parsed?.ssvc, null);
  assert.equal(parsed?.cves[0].kev_due_date, null);
});

test("every committed demo capture passes the validator", () => {
  const files = readdirSync(fixturesDir).filter((f) => f.endsWith(".json"));
  assert.ok(files.length > 0);
  for (const file of files) {
    const fixture = JSON.parse(readFileSync(join(fixturesDir, file), "utf8"));
    const final = fixture.frames.find((f) => f.event === "final");
    assert.ok(parseReport(final.data), `${file} no longer passes`);
  }
});

test("unknown fields do not reach the view", () => {
  const hostile = JSON.parse('{"__proto__": {"polluted": 1}, "extra": 2}');
  const parsed = parseReport({ ...REPORT, ...hostile, __proto__: null });
  assert.equal(Object.hasOwn(parsed, "extra"), false);
  assert.equal(Object.hasOwn(parsed, "__proto__"), false);
  assert.equal(parsed.polluted, undefined);
});

test("a stray or prose KEV date is dropped, the report survives", () => {
  assert.equal(parseReport(mutate((r) => (r.cves[0].kev_due_date = "2021-11-17 ")))?.cves[0].kev_due_date, "2021-11-17");
  for (const due of ["", "2021-11-17T00:00:00Z", "patched, ignore this"]) {
    const parsed = parseReport(mutate((r) => (r.cves[0].kev_due_date = due)));
    assert.ok(parsed, `refused for ${JSON.stringify(due)}`);
    assert.equal(parsed.cves[0].kev_due_date, null);
  }
});

test("caps count code points, like Pydantic, not UTF-16 units", () => {
  assert.ok(parseReport(mutate((r) => (r.summary = "a".repeat(499) + "\u{1F600}"))));
  assert.equal(parseReport(mutate((r) => (r.summary = "a".repeat(500) + "\u{1F600}"))), null);
});

test("fields the schema leaves uncapped are not capped here", () => {
  assert.ok(parseReport(mutate((r) => (r.reasoning_chain = ["x".repeat(5_000)]))));
  assert.ok(parseReport(mutate((r) => (r.reasoning_chain = Array(1_000).fill("step")))));
  assert.equal(parseReport(mutate((r) => (r.reasoning_chain = Array(1_001).fill("step")))), null);
});

test("a url carries its parsed form, so no newline reaches a sink", () => {
  const parsed = parseReport(mutate((r) => (r.cves[0].nvd_url = "https://nvd.nist.gov/\nINJECTED")));
  assert.equal(parsed?.cves[0].nvd_url.includes("\n"), false);
});

const REJECTED = {
  "unknown ssvc decision": (r) => (r.ssvc.decision = "Ignore"),
  "unknown grounding status": (r) => (r.grounding.status = "verified"),
  "unknown severity": (r) => (r.severity = "catastrophic"),
  "unknown coverage status": (r) => (r.signal_coverage[0].status = "ok"),
  "attack_techniques not a list": (r) => (r.attack_techniques = "none"),
  "reasoning_chain not a list": (r) => (r.reasoning_chain = 7),
  "malformed cve id": (r) => (r.cves[0].cve_id = "CVE-1"),
  "CVSS out of range": (r) => (r.cves[0].cvss_v3_score = 99),
  "EPSS out of range": (r) => (r.cves[0].epss_probability = 1.5),
  "javascript: reference": (r) => (r.cves[0].nvd_url = "javascript:alert(1)"),
  "summary over the cap": (r) => (r.summary = "x".repeat(501)),
  "too many CVEs": (r) => (r.cves = Array(11).fill(r.cves[0])),
  "negative grounding count": (r) => (r.grounding.supported = -1),
  "null list": (r) => (r.cves = null),
  "url over the HttpUrl cap": (r) => (r.cves[0].nvd_url = "https://nvd.nist.gov/" + "x".repeat(2_070)),
  "rule over the cap": (r) => (r.ssvc.rule = "x".repeat(65)),
  "rationale over the cap": (r) => (r.ssvc.rationale = "x".repeat(501)),
  "cve summary over the cap": (r) => (r.cves[0].summary = "x".repeat(1_001)),
  "feed over the cap": (r) => (r.signal_coverage[0].feed = "x".repeat(41)),
  "feed detail over the cap": (r) => (r.signal_coverage[0].detail = "x".repeat(201)),
  "too many feeds": (r) => (r.signal_coverage = Array(17).fill(r.signal_coverage[0])),
  "too many techniques": (r) => {
    r.attack_techniques = Array(21).fill({ id: "T1190", name: "x", url: "https://attack.mitre.org/techniques/T1190/" });
  },
  "too many findings": (r) => {
    r.grounding.findings = Array(41).fill({ subject: "x", field: "y", status: "mismatch", detail: null });
  },
};

for (const [name, change] of Object.entries(REJECTED)) {
  test(`rejects: ${name}`, async () => {
    assert.equal(await decodeReport(await link(mutate(change))), null);
  });
}

test("rejects a gzip bomb", async () => {
  // A valid report: without the byte counter this decodes and renders.
  const bomb = await link({ ...REPORT, padding: "0".repeat(DECOMPRESSED_MAX * 40) });
  assert.ok(bomb.length < FRAGMENT_MAX, "the bomb must fit the fragment cap to reach the decoder");
  assert.equal(await decodeReport(bomb), null);
});

test("rejects a fragment over the cap before decoding it", async () => {
  // A valid report: without the length gate this decodes and renders.
  const padded = JSON.stringify({ ...REPORT, padding: "0".repeat(FRAGMENT_MAX) });
  const oversized = PLAIN + b64url(new TextEncoder().encode(padded));
  assert.ok(oversized.length > FRAGMENT_MAX);
  assert.equal(await decodeReport(oversized), null);
});

test("a malformed percent escape is a bad link, not an exception", async () => {
  assert.equal(await decodeReport("%E0"), null);
});

test("rejects an unknown scheme, bad base64 and bad JSON", async () => {
  assert.equal(await decodeReport("9abc"), null);
  assert.equal(await decodeReport(GZIP + "!!!"), null);
  assert.equal(await decodeReport(await link("{not json")), null);
});

test("a clipped query reads, a longer one cannot have been minted", async () => {
  const clipped = "q".repeat(SHARED_QUERY_MAX) + "\u2026";
  const decoded = await decodeReport(await link({ v: 1, query: clipped, queryTruncated: true, report: REPORT }));
  assert.equal(decoded?.query, clipped);
  assert.equal(decoded?.queryTruncated, true);
  const query = "q".repeat(SHARED_QUERY_MAX + 2);
  assert.equal(await decodeReport(await link({ v: 1, query, report: REPORT })), null);
});

test("rejects an envelope version this decoder does not know", async () => {
  assert.equal(await decodeReport(await link({ v: 99, report: REPORT })), null);
});
