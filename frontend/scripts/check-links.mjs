// P12 completeness gate — static broken-link check over the exported demo site.
//
// Runs AFTER `npm run build:demo` produces out/. Browser-free: it reads the
// exported HTML and resolves every internal `<a href>` against the exported
// filesystem, so a header/footer/landing link that points at a route the export
// never shipped fails the build instead of 404-ing on the live Pages site. The
// P6 baseline broke on exactly this class (a nav link surviving a route rename);
// this gate makes that a red check, not a post-deploy discovery.
//
// Scope, and why it is complementary to the gen-docs gate (not redundant):
//   - Corpus cross-link integrity (every P10-rewritten data-doc-* link resolves)
//     is validated at BUILD time in scripts/gen-docs.mjs, over docs-generated.json
//     where all 15 docs' HTML exists. The /docs route is a client component whose
//     export server-renders ONLY the default doc, so the other docs' cross-links
//     are simply not in out/ — a browser/DOM check here would miss them. That gate
//     owns the doc-to-doc graph; this one owns the exported site's own links.
//   - Here we resolve internal href PATHS to real exported files, and validate any
//     `?doc=<slug>` query (footer/landing deep-links) against the live corpus, so a
//     stale deep-link slug is caught too.
//
// Deterministic and dependency-free (node: builtins only): safe to run anywhere
// the export exists. Exit 0 when every internal link resolves, 1 otherwise.

import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = resolve(root, process.env.LINK_CHECK_OUT || "out");
const DOCS_JSON = resolve(root, "src", "lib", "docs-generated.json");

// The export is served under a sub-path on Pages (/<repo>); links are prefixed
// with it. Honor NEXT_PUBLIC_BASE_PATH when set (CI passes it), otherwise detect
// it from the asset prefix Next stamps on every page, so a local run against an
// existing out/ needs no flag. "" means a root-served export.
async function detectBasePath() {
  const env = process.env.NEXT_PUBLIC_BASE_PATH;
  if (env !== undefined) return env.replace(/\/$/, "");
  const home = join(OUT_DIR, "index.html");
  if (existsSync(home)) {
    const html = await readFile(home, "utf8");
    const m = html.match(/(?:href|src)="([^"]*?)\/_next\//);
    if (m) return m[1];
  }
  return "";
}

async function collectHtml(dir) {
  const files = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await collectHtml(full)));
    else if (entry.name.endsWith(".html")) files.push(full);
  }
  return files;
}

// Resolve a root-relative path (basePath already stripped) to an exported file,
// mirroring Next's trailingSlash directory-style export:
//   ""            -> index.html
//   "/x/"         -> x/index.html
//   "/x/y.css"    -> x/y.css        (has an extension: a literal file/asset)
//   "/x"          -> x.html | x/index.html
function resolvesToFile(routePath) {
  const rel = routePath.replace(/^\//, "");
  const candidates = [];
  if (rel === "" || routePath === "/") {
    candidates.push("index.html");
  } else if (routePath.endsWith("/")) {
    candidates.push(posix.join(rel, "index.html"));
  } else if (/\.[a-z0-9]+$/i.test(rel)) {
    candidates.push(rel);
  } else {
    candidates.push(`${rel}.html`, posix.join(rel, "index.html"));
  }
  return candidates.some((c) => existsSync(join(OUT_DIR, c)));
}

async function main() {
  if (!existsSync(OUT_DIR)) {
    console.error(`check-links: ${OUT_DIR} not found — run 'npm run build:demo' first.`);
    process.exitCode = 1;
    return;
  }

  const basePath = await detectBasePath();
  const corpus = JSON.parse(await readFile(DOCS_JSON, "utf8"));
  const corpusSlugs = new Set(corpus.groups.flatMap((g) => g.docs.map((d) => d.slug)));

  const htmlFiles = await collectHtml(OUT_DIR);
  // href -> { reason, sample } so an identical dead link across many pages reports
  // once (with a count) instead of flooding the log.
  const dead = new Map();
  const flag = (href, reason, file) => {
    if (!dead.has(href)) dead.set(href, { reason, files: new Set() });
    dead.get(href).files.add(file.slice(OUT_DIR.length + 1));
  };

  for (const file of htmlFiles) {
    const html = await readFile(file, "utf8");
    for (const m of html.matchAll(/\bhref="([^"]*)"/g)) {
      const href = m[1];
      // External (scheme:, mailto:, //) and pure in-page anchors: not our concern.
      if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) continue;

      const noFrag = href.split("#")[0];
      const [rawPath, query = ""] = noFrag.split("?");

      // Deep-link `?doc=<slug>` must name a doc the corpus actually ships.
      const docParam = new URLSearchParams(query).get("doc");
      if (docParam && !corpusSlugs.has(docParam)) {
        flag(href, `?doc=${docParam} is not a corpus slug`, file);
      }

      if (rawPath === "") continue; // same-page query/fragment link

      // Absolute internal path: it must live under the export's sub-path.
      let routePath;
      if (rawPath.startsWith("/")) {
        if (basePath && rawPath !== basePath && !rawPath.startsWith(`${basePath}/`)) {
          flag(href, `absolute path escapes the base path (${basePath})`, file);
          continue;
        }
        routePath = basePath ? rawPath.slice(basePath.length) : rawPath;
      } else {
        // Relative path (Next rarely emits these): resolve against this file's dir.
        const relDir = dirname(file).slice(OUT_DIR.length) || "/";
        routePath = posix.join(relDir, rawPath);
      }

      if (!resolvesToFile(routePath)) {
        flag(href, "no exported file resolves this path", file);
      }
    }
  }

  console.log(
    `check-links: scanned ${htmlFiles.length} exported page(s), base path '${basePath || "(root)"}'`,
  );
  if (dead.size === 0) {
    console.log("check-links: all internal links resolve.");
    return;
  }
  console.error(`check-links: ${dead.size} unresolved internal link(s):`);
  for (const [href, { reason, files }] of [...dead].sort()) {
    const where = [...files].sort();
    const suffix = where.length > 1 ? ` (in ${where[0]} +${where.length - 1} more)` : ` (in ${where[0]})`;
    console.error(`  - ${href} — ${reason}${suffix}`);
  }
  process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
