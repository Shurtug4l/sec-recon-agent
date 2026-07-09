// Build-time docs pipeline: docs/*.md -> src/lib/docs-generated.json.
//
// The /docs route renders the project's own markdown documentation in-app.
// Rendering happens HERE, at build time, not in the client: markdown -> HTML,
// GFM tables, heading slugs, syntax highlighting, and an allowlist sanitize
// pass all run in Node with dev-only dependencies, so the browser ships no
// markdown parser and no highlighter — only the generated HTML (plus mermaid,
// dynamically imported on /docs for the diagram blocks).
//
// Output is a PURE function of the docs content (no timestamps, no randomness):
// the CI freshness gate regenerates and `git diff --exit-code`s this file, so
// determinism is load-bearing.
//
// Context resilience: the frontend Docker build context is ./frontend only, so
// ../docs is absent there. When the docs directory is missing this script is a
// no-op and the committed docs-generated.json is used as-is. When docs/ is
// present (local dev, CI, the Pages demo build) it regenerates from source.

import { existsSync } from "node:fs";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import remarkRehype from "remark-rehype";
import rehypeSlug from "rehype-slug";
import rehypeHighlight from "rehype-highlight";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";
import rehypeStringify from "rehype-stringify";
import { toString as mdastToString } from "mdast-util-to-string";
import { toText as hastToText } from "hast-util-to-text";
import { visit } from "unist-util-visit";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DOCS_DIR = resolve(root, "..", "docs");
const OUT_FILE = resolve(root, "src", "lib", "docs-generated.json");
const GITHUB_BLOB = "https://github.com/Shurtug4l/sec-recon-agent/blob/main/docs";

// Grouping, order, and short rail labels. Anything not listed is skipped (the
// docs set surfaced in-app is a deliberate curation, not a directory dump).
const GROUPS = [
  { name: "Engineering & operations", slugs: ["design", "tools", "evaluation", "running", "frontend"] },
  { name: "Governance & security", slugs: ["owasp_llm_top10", "mitre_atlas", "iso_42001", "mcp_self_audit", "security_findings"] },
  { name: "Narrative", slugs: ["case_study"] },
];

const NAV_LABEL = {
  design: "Design brief",
  tools: "Tool contracts",
  evaluation: "Evaluation",
  running: "Running",
  frontend: "Frontend",
  owasp_llm_top10: "OWASP LLM Top 10",
  mitre_atlas: "MITRE ATLAS",
  iso_42001: "ISO 42001",
  mcp_self_audit: "MCP self-audit",
  security_findings: "Security findings",
  case_study: "Case study",
};

// Allowlist sanitize: defense in depth even on first-party build-time content.
// Extends the default schema to keep heading `id`s (deep-link anchors), the
// highlighter's `className`s, and the mermaid placeholder class/attribute.
const SCHEMA = {
  ...defaultSchema,
  // First-party content: disable the anti-DOM-clobbering id prefix so deep-link
  // anchors stay clean (#threat-model, not #user-content-threat-model). The
  // clobber defense guards against untrusted ids shadowing getElementById; our
  // headings are our own, and the URLs are part of the UX.
  clobberPrefix: "",
  tagNames: [...(defaultSchema.tagNames || []), "div"],
  attributes: {
    ...defaultSchema.attributes,
    "*": [...(defaultSchema.attributes?.["*"] || []), "className", "id"],
    // tabIndex lets the scroll-container divs (docs-mermaid, docs-table-scroll)
    // and code blocks take keyboard focus so a wide diagram/table/code line
    // stays reachable without a mouse (WCAG 2.1.1, scrollable-region-focusable).
    div: [...(defaultSchema.attributes?.div || []), "className", "dataMermaid", "tabIndex"],
    pre: [...(defaultSchema.attributes?.pre || []), "tabIndex"],
  },
};

// remark plugin: pull the leading H1 as the doc title and the first paragraph
// as the purpose blurb, then strip the H1 from the body so the rendered panel
// does not repeat the title the rail already shows.
function extractTitleAndStripH1(meta) {
  return (tree) => {
    const first = tree.children[0];
    if (first && first.type === "heading" && first.depth === 1) {
      meta.title = mdastToString(first).trim();
      tree.children.shift();
    }
    const firstPara = tree.children.find((n) => n.type === "paragraph");
    meta.purpose = firstPara ? mdastToString(firstPara).trim() : "";
  };
}

// rehype plugin: replace a ```mermaid fence (pre > code.language-mermaid) with
// a <div class="docs-mermaid"> holding the raw diagram source as text. The
// client finds these on /docs and renders them with mermaid, themed live.
function rehypeMermaid() {
  return (tree) => {
    visit(tree, "element", (node, index, parent) => {
      if (node.tagName !== "pre" || !parent || index === null) return;
      const code = node.children.find((c) => c.type === "element" && c.tagName === "code");
      const cls = code?.properties?.className || [];
      if (!Array.isArray(cls) || !cls.includes("language-mermaid")) return;
      const source = code.children.map((c) => (c.type === "text" ? c.value : "")).join("");
      parent.children[index] = {
        type: "element",
        tagName: "div",
        properties: { className: ["docs-mermaid"], tabIndex: 0 },
        children: [{ type: "text", value: source }],
      };
    });
  };
}

// rehype plugin: wrap each table in a horizontally-scrollable container so a
// wide table scrolls inside its own box instead of forcing the page body to
// scroll sideways (a11y + the frontend's horizontal-layout principle).
function rehypeWrapTables() {
  return (tree) => {
    visit(tree, "element", (node, index, parent) => {
      if (node.tagName !== "table" || !parent || index === null) return;
      parent.children[index] = {
        type: "element",
        tagName: "div",
        properties: { className: ["docs-table-scroll"], tabIndex: 0 },
        children: [node],
      };
    });
  };
}

// rehype plugin: make code blocks keyboard-focusable. A long code line scrolls
// horizontally inside its <pre>; without a tab stop a mouseless reader cannot
// reach the hidden text (WCAG 2.1.1). Runs after mermaid replacement, so the
// only <pre> left are real code blocks.
function rehypeFocusableCode() {
  return (tree) => {
    visit(tree, "element", (node) => {
      if (node.tagName === "pre") {
        node.properties = { ...node.properties, tabIndex: 0 };
      }
    });
  };
}

// rehype plugin: after slug + sanitize, walk the body and cut it into sections
// keyed by h2/h3/h4 (id, title, depth) with the following prose as `content`,
// so the client search can return a specific section and deep-link its anchor.
function collectSections(store) {
  return (tree) => {
    const body = tree.children.filter((n) => n.type === "element");
    const sections = [];
    let current = null;
    for (const node of body) {
      const m = /^h([2-4])$/.exec(node.tagName);
      if (m) {
        current = {
          id: String(node.properties?.id || ""),
          title: hastToText(node).trim(),
          depth: Number(m[1]),
          content: "",
        };
        sections.push(current);
      } else if (current) {
        current.content += " " + hastToText(node);
      }
    }
    store.sections = sections.map((s) => ({ ...s, content: s.content.replace(/\s+/g, " ").trim() }));
  };
}

async function renderDoc(slug, raw) {
  const meta = { title: slug, purpose: "" };
  const store = { sections: [] };
  const file = await unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(extractTitleAndStripH1, meta)
    .use(remarkRehype)
    .use(rehypeSlug)
    .use(rehypeMermaid)
    .use(rehypeWrapTables)
    .use(rehypeHighlight, { detect: false, ignoreMissing: true })
    .use(rehypeFocusableCode)
    .use(rehypeSanitize, SCHEMA)
    .use(collectSections, store)
    .use(rehypeStringify)
    .process(raw);
  return {
    slug,
    title: meta.title,
    navLabel: NAV_LABEL[slug] || meta.title,
    purpose: meta.purpose,
    html: String(file),
    sections: store.sections,
    hasMermaid: raw.includes("```mermaid"),
    githubUrl: `${GITHUB_BLOB}/${slug}.md`,
  };
}

async function main() {
  if (!existsSync(DOCS_DIR)) {
    console.log("gen-docs: docs/ not in build context, keeping committed docs-generated.json");
    return;
  }
  const present = new Set((await readdir(DOCS_DIR)).filter((f) => f.endsWith(".md")).map((f) => f.slice(0, -3)));
  const groups = [];
  for (const g of GROUPS) {
    const docs = [];
    for (const slug of g.slugs) {
      if (!present.has(slug)) {
        console.warn(`gen-docs: WARNING configured doc '${slug}.md' not found, skipping`);
        continue;
      }
      const raw = await readFile(resolve(DOCS_DIR, `${slug}.md`), "utf8");
      docs.push(await renderDoc(slug, raw));
    }
    if (docs.length) groups.push({ name: g.name, docs });
  }
  // Stable 2-space JSON so the freshness diff is readable and deterministic.
  await writeFile(OUT_FILE, JSON.stringify({ groups }, null, 2) + "\n", "utf8");
  const count = groups.reduce((n, g) => n + g.docs.length, 0);
  console.log(`gen-docs: wrote ${count} docs across ${groups.length} groups -> ${OUT_FILE}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
