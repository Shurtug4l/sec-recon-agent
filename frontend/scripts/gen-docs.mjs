// Build-time docs pipeline: the repo's markdown -> src/lib/docs-generated.json.
//
// The /docs route renders the project's own markdown documentation in-app.
// Rendering happens HERE, at build time, not in the client: markdown -> HTML,
// GFM tables, heading slugs, syntax highlighting, and an allowlist sanitize
// pass all run in Node with dev-only dependencies, so the browser ships no
// markdown parser and no highlighter — only the generated HTML (plus mermaid,
// dynamically imported on /docs for the diagram blocks).
//
// The corpus is assembled by DISCOVERY, not by an allowlist (P9): every tracked
// markdown file across docs/, the repo root, and examples/ is a candidate. A
// candidate MUST be assigned to a group (below) or explicitly excluded; a file
// that is present but unconfigured FAILS the build, so a new doc cannot be
// silently dropped and orphans (examples/triage_walkthrough.md) are closed by
// construction. The two exclusions are documented, not an allowlist in disguise.
//
// Output is a PURE function of the corpus content (no timestamps, no randomness)
// AND of the fixed GROUPS order (never of readdir order, which is filesystem-
// dependent): the CI freshness gate regenerates and `git diff --exit-code`s this
// file, so determinism across machines (local macOS, Ubuntu CI) is load-bearing.
//
// Context resilience: the frontend Docker build context is ./frontend only, so
// ../docs is absent there. When the docs directory is missing this script is a
// no-op and the committed docs-generated.json is used as-is. When docs/ is
// present (local dev, CI, the Pages demo build) it regenerates from source.

import { existsSync } from "node:fs";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, posix, resolve } from "node:path";
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
import { visit, SKIP } from "unist-util-visit";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(root, "..");
const DOCS_DIR = resolve(REPO_ROOT, "docs");
const EXAMPLES_DIR = resolve(REPO_ROOT, "examples");
const OUT_FILE = resolve(root, "src", "lib", "docs-generated.json");
const GITHUB_BLOB = "https://github.com/Shurtug4l/sec-recon-agent/blob/main";

// Root markdown that discovery must skip, by basename. The default is
// ingest-everything; these two are the documented exceptions:
//   - CLAUDE:    untracked (global gitignore), so it is present locally but
//                ABSENT in CI. Ingesting it would make the JSON diverge between
//                machines and flap the freshness gate. It is never repo content.
//   - SCORECARD: already a first-class route (/scorecard, tabbed bands) and a
//                machine-generated artifact (`make scorecard`); rendering it in
//                /docs too would double-surface the same content.
const EXCLUDE_BASENAMES = new Set(["CLAUDE", "SCORECARD"]);

// Non-corpus markdown that nonetheless owns a first-class in-app route. SCORECARD
// is in EXCLUDE_BASENAMES (its own /scorecard tab), so a cross-link to it cannot
// become a ?doc= slug; instead the P10 rewrite hands the client a data-doc-route
// marker it upgrades to a basePath-aware router.push, with a GitHub-blob href as
// the no-JS fallback. Keyed by lowercased basename -> route.
const EXTERNAL_ROUTE = { scorecard: "/scorecard" };

// Grouping, order, and short rail labels. Every discovered doc must appear here
// (or in EXCLUDE_BASENAMES); a present-but-unconfigured file fails the build.
// The first group's first doc is the /docs landing (Overview = the README, far
// lighter than design.md's 72 KB first-paint).
const GROUPS = [
  { name: "Overview", slugs: ["readme"] },
  { name: "Engineering & operations", slugs: ["design", "tools", "evaluation", "running", "frontend", "contributing"] },
  { name: "Governance & security", slugs: ["owasp_llm_top10", "mitre_atlas", "iso_42001", "mcp_self_audit", "security_findings", "security"] },
  { name: "Narrative", slugs: ["case_study", "triage_walkthrough"] },
];

const NAV_LABEL = {
  readme: "Overview",
  design: "Design brief",
  tools: "Tool contracts",
  evaluation: "Evaluation",
  running: "Running",
  frontend: "Frontend",
  contributing: "Contributing",
  owasp_llm_top10: "OWASP LLM Top 10",
  mitre_atlas: "MITRE ATLAS",
  iso_42001: "ISO 42001",
  mcp_self_audit: "MCP self-audit",
  security_findings: "Security findings",
  security: "Security policy",
  case_study: "Case study",
  triage_walkthrough: "Triage walkthrough",
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
    // The P10 xref rewrite stamps these markers on rewritten cross-links so the
    // client can upgrade a corpus link to an in-place doc switch (dataDocSlug /
    // dataDocSection) or a routed link to a basePath-aware push (dataDocRoute).
    a: [...(defaultSchema.attributes?.a || []), "dataDocSlug", "dataDocSection", "dataDocRoute"],
    // tabIndex lets the scroll-container divs (docs-mermaid, docs-table-scroll)
    // and code blocks take keyboard focus so a wide diagram/table/code line
    // stays reachable without a mouse (WCAG 2.1.1, scrollable-region-focusable).
    div: [...(defaultSchema.attributes?.div || []), "className", "dataMermaid", "tabIndex"],
    pre: [...(defaultSchema.attributes?.pre || []), "tabIndex"],
  },
};

// remark plugin: strip images and image-only links from the corpus. No doc uses
// a raster image for content (diagrams are ```mermaid fences, rendered client-
// side); the only images are the README's shields.io badges (a link wrapping an
// image) and the demo GIF — GitHub-landing chrome that would be a dead relative
// path or an external request in-app. Runs BEFORE title/lead extraction so the
// removed badge paragraph cannot be mistaken for the lead blurb. The README
// keeps its badges/GIF on GitHub; only the in-app rendering drops them.
function stripBadgesAndImages() {
  const isBlank = (n) => n.type === "text" && n.value.trim() === "";
  return (tree) => {
    // Standalone images (the demo GIF).
    visit(tree, "image", (_node, index, parent) => {
      if (parent && index !== null) {
        parent.children.splice(index, 1);
        return [SKIP, index];
      }
    });
    // Links left with no meaningful child (a badge = link whose only child was
    // the image just removed).
    visit(tree, "link", (node, index, parent) => {
      if (parent && index !== null && node.children.every(isBlank)) {
        parent.children.splice(index, 1);
        return [SKIP, index];
      }
    });
    // Paragraphs that are now empty / whitespace-only (the badge row itself).
    visit(tree, "paragraph", (node, index, parent) => {
      if (parent && index !== null && node.children.every(isBlank)) {
        parent.children.splice(index, 1);
        return [SKIP, index];
      }
    });
  };
}

// remark plugin: pull the leading H1 as the doc title and the leading paragraph
// as the purpose blurb, then strip BOTH from the body. The panel renders the
// purpose as its lead line, so leaving the paragraph in the body repeats it
// verbatim right below (same rationale as stripping the title-carrying H1).
function extractTitleAndStripH1(meta) {
  return (tree) => {
    const first = tree.children[0];
    if (first && first.type === "heading" && first.depth === 1) {
      meta.title = mdastToString(first).trim();
      tree.children.shift();
    }
    const lead = tree.children[0];
    if (lead && lead.type === "paragraph") {
      // The normal shape (H1 then an intro paragraph): this IS the lead, so
      // remove it from the body to avoid the duplicate.
      meta.purpose = mdastToString(lead).trim();
      tree.children.shift();
    } else {
      // Edge shape (H1 straight into a heading): keep the old behavior and do
      // not yank a mid-section paragraph up as the lead.
      const firstPara = tree.children.find((n) => n.type === "paragraph");
      meta.purpose = firstPara ? mdastToString(firstPara).trim() : "";
    }
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

// rehype plugin (P10 "docs mesh"): rewrite relative markdown cross-links so they
// resolve IN-APP instead of dead-ending on a raw `.md` path the /docs route can't
// serve. A link whose basename maps to a corpus slug becomes a basePath-agnostic
// `?doc=slug#anchor` (relative to the current /docs URL, so it survives the Pages
// sub-path) carrying data-doc-* markers the client upgrades to an in-place doc
// switch (no reload, honors the anchor). A link to a doc that owns a route but is
// NOT in the corpus (SCORECARD -> /scorecard) gets a GitHub-blob href as the
// no-JS fallback plus a data-doc-route marker the client turns into a basePath-
// aware push. Absolute URLs, in-page #anchors, and unknown `.md` are left as-is
// (an unknown `.md` stays visibly dead on purpose, for the P12 completeness gate).
// Runs before rehypeSanitize, so the markers are added under the allowlist above.
const XREF = /^([^#?]*?)\.md(#.+)?$/;
function rehypeRewriteXrefs({ validSlugs, docPath }) {
  return (tree) => {
    visit(tree, "element", (node) => {
      if (node.tagName !== "a") return;
      const href = node.properties?.href;
      if (typeof href !== "string") return;
      if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return; // absolute / in-page
      const m = XREF.exec(href);
      if (!m) return;
      const anchor = m[2] ? m[2].slice(1) : "";
      const base = m[1].split("/").pop().toLowerCase();
      if (validSlugs.has(base)) {
        node.properties.href = `?doc=${base}${anchor ? `#${anchor}` : ""}`;
        node.properties.dataDocSlug = base;
        if (anchor) node.properties.dataDocSection = anchor;
        return;
      }
      const route = EXTERNAL_ROUTE[base];
      if (route) {
        const resolved = posix.normalize(posix.join(posix.dirname(docPath), `${m[1]}.md`));
        node.properties.href = `${GITHUB_BLOB}/${resolved}${anchor ? `#${anchor}` : ""}`;
        node.properties.dataDocRoute = route;
      }
    });
  };
}

async function renderDoc(slug, path, raw, validSlugs) {
  const meta = { title: slug, purpose: "" };
  const store = { sections: [] };
  const file = await unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(stripBadgesAndImages)
    .use(extractTitleAndStripH1, meta)
    .use(remarkRehype)
    .use(rehypeSlug)
    .use(rehypeMermaid)
    .use(rehypeWrapTables)
    .use(rehypeHighlight, { detect: false, ignoreMissing: true })
    .use(rehypeFocusableCode)
    .use(rehypeRewriteXrefs, { validSlugs, docPath: path })
    .use(rehypeSanitize, SCHEMA)
    .use(collectSections, store)
    .use(rehypeStringify)
    .process(raw);
  return {
    slug,
    path,
    title: meta.title,
    navLabel: NAV_LABEL[slug] || meta.title,
    purpose: meta.purpose,
    html: String(file),
    sections: store.sections,
    hasMermaid: raw.includes("```mermaid"),
    githubUrl: `${GITHUB_BLOB}/${path}`,
  };
}

// Discover every candidate markdown file across the three source roots, mapped
// to {slug, path}. path is repo-relative (drives githubUrl and the panel label);
// slug is the lowercased basename (drives ?doc= deep links and the group config).
async function discover() {
  const found = [];
  const scan = async (dir, relPrefix) => {
    if (!existsSync(dir)) return;
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith(".md")) continue;
      const base = entry.name.slice(0, -3);
      if (EXCLUDE_BASENAMES.has(base)) continue;
      found.push({
        slug: base.toLowerCase(),
        path: relPrefix ? `${relPrefix}/${entry.name}` : entry.name,
        absPath: resolve(dir, entry.name),
      });
    }
  };
  await scan(REPO_ROOT, "");
  await scan(DOCS_DIR, "docs");
  await scan(EXAMPLES_DIR, "examples");
  return found;
}

async function main() {
  if (!existsSync(DOCS_DIR)) {
    console.log("gen-docs: docs/ not in build context, keeping committed docs-generated.json");
    return;
  }
  const discovered = await discover();

  // Collision guard: two source files must not resolve to the same slug (the
  // slug keys deep links and the group config).
  const bySlug = new Map();
  for (const d of discovered) {
    const prev = bySlug.get(d.slug);
    if (prev) throw new Error(`gen-docs: slug collision '${d.slug}' from ${prev.path} and ${d.path}`);
    bySlug.set(d.slug, d);
  }

  // Discovery contract: every discovered doc must be assigned to a group. A
  // present-but-unconfigured file fails the build (closes orphans by
  // construction; forces a deliberate group/label or an EXCLUDE_BASENAMES entry).
  const configured = new Set(GROUPS.flatMap((g) => g.slugs));
  const unconfigured = discovered
    .filter((d) => !configured.has(d.slug))
    .map((d) => d.path)
    .sort();
  if (unconfigured.length) {
    throw new Error(
      `gen-docs: ${unconfigured.length} markdown file(s) present but not assigned to a group:\n` +
        unconfigured.map((p) => `  - ${p}`).join("\n") +
        "\nAdd each to a GROUPS entry (with a NAV_LABEL) or to EXCLUDE_BASENAMES in scripts/gen-docs.mjs.",
    );
  }

  // Slugs that actually resolve to a rendered doc; the P10 xref rewrite consults
  // this to decide whether a `.md` cross-link becomes an in-app ?doc= link or is
  // left alone. Built from the corpus, so it is independent of readdir order.
  const validSlugs = new Set(GROUPS.flatMap((g) => g.slugs).filter((s) => bySlug.has(s)));

  // Output order follows GROUPS (fixed), never readdir order, so the JSON is
  // byte-stable across filesystems. A configured slug with no source file only
  // warns (a doc can be renamed/removed without a hard stop); the fatal
  // direction is present-but-unconfigured, handled above.
  const groups = [];
  for (const g of GROUPS) {
    const docs = [];
    for (const slug of g.slugs) {
      const doc = bySlug.get(slug);
      if (!doc) {
        console.warn(`gen-docs: WARNING configured doc '${slug}' has no source file, skipping`);
        continue;
      }
      const raw = await readFile(doc.absPath, "utf8");
      docs.push(await renderDoc(slug, doc.path, raw, validSlugs));
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
