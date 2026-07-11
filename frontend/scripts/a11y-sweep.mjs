// P12 completeness gate — accessibility + horizontal-overflow sweep.
//
// Institutionalizes the manual Playwright/axe verification recipe that shipped
// every P0-P11 PR: serve the basePath export exactly as GitHub Pages does, then
// across every route x both themes assert (1) the page never scrolls sideways
// (document width <= viewport across a full width band) and (2) axe-core finds no
// serious/critical WCAG 2.2 AA violation at representative widths. The P6 baseline
// broke on the horizontal-overflow class (the header's intrinsic width pushed a
// sideways scroll across the whole 768-1196px band, invisible to a 390/1280-only
// check), which is why the width band here is dense and the whole thing is a
// blocking check rather than a pre-push ritual someone can forget to run.
//
// Playwright + @axe-core/playwright are installed ephemerally in the CI job (and
// in the local scratchpad per the repo recipe), NOT declared in package.json:
// the browser binary is heavy and the other CI jobs must stay lean. Run locally:
//   npm run build:demo   # with NEXT_PUBLIC_BASE_PATH=/sec-recon-agent for parity
//   npm i --no-save playwright @axe-core/playwright && npx playwright install chromium
//   NEXT_PUBLIC_BASE_PATH=/sec-recon-agent node scripts/a11y-sweep.mjs
//
// Exit 0 when every route passes both axes in both themes, 1 otherwise.

import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { extname, join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = resolve(root, process.env.A11Y_SWEEP_OUT || "out");
const BASE_PATH = (process.env.NEXT_PUBLIC_BASE_PATH ?? "/sec-recon-agent").replace(/\/$/, "");

const ROUTES = ["/", "/triage", "/dashboard", "/scorecard", "/case-study", "/guide", "/docs", "/r"];
const THEMES = ["dark", "light"];
// Dense band: the P6 overflow lived at 768-1196, which a 390/1280 check missed.
const WIDTHS = [360, 390, 414, 480, 640, 768, 834, 1024, 1196, 1280, 1440, 1536];
// axe is the slow axis; three representative widths x every route x both themes.
const AXE_WIDTHS = [390, 768, 1280];
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const FAIL_IMPACTS = new Set((process.env.A11Y_FAIL_IMPACTS || "serious,critical").split(","));
const OVERFLOW_TOLERANCE = 1; // sub-pixel rounding

const CONTENT_TYPE = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".map": "application/json; charset=utf-8",
};

// Serve out/ exactly as Pages does: everything under BASE_PATH, directory-style
// (trailingSlash) index resolution, a 404 for anything outside the sub-path so
// an escaped-subpath link fails here just like it would live.
function startServer() {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    let path = decodeURIComponent(url.pathname);
    if (BASE_PATH) {
      if (path !== BASE_PATH && !path.startsWith(`${BASE_PATH}/`)) {
        res.writeHead(404).end("outside base path");
        return;
      }
      path = path.slice(BASE_PATH.length) || "/";
    }
    const rel = path.replace(/^\//, "");
    const candidates =
      path === "/" || rel === ""
        ? ["index.html"]
        : path.endsWith("/")
          ? [join(rel, "index.html")]
          : extname(rel)
            ? [rel]
            : [`${rel}.html`, join(rel, "index.html")];
    for (const c of candidates) {
      const file = join(OUT_DIR, c);
      if (existsSync(file)) {
        const body = await readFile(file);
        res.writeHead(200, { "content-type": CONTENT_TYPE[extname(file)] || "application/octet-stream" });
        res.end(body);
        return;
      }
    }
    res.writeHead(404).end("not found");
  });
  return new Promise((ok) => server.listen(0, () => ok(server)));
}

async function main() {
  if (!existsSync(OUT_DIR)) {
    console.error(`a11y-sweep: ${OUT_DIR} not found — run 'npm run build:demo' first.`);
    process.exitCode = 1;
    return;
  }

  const server = await startServer();
  const port = server.address().port;
  const origin = `http://localhost:${port}${BASE_PATH}`;
  const browser = await chromium.launch();

  const overflowFails = [];
  const axeFails = [];
  let axeRuns = 0;

  try {
    for (const theme of THEMES) {
      // Fresh context per theme; addInitScript pins localStorage.theme before the
      // layout's pre-paint script reads it, so the theme is right on first paint.
      const context = await browser.newContext({ reducedMotion: "reduce" });
      await context.addInitScript((t) => {
        try {
          localStorage.setItem("theme", t);
        } catch {}
      }, theme);
      const page = await context.newPage();

      for (const route of ROUTES) {
        const url = `${origin}${route}${route.endsWith("/") ? "" : "/"}`;
        await page.goto(url, { waitUntil: "networkidle", timeout: 20000 }).catch(() =>
          page.goto(url, { waitUntil: "load", timeout: 20000 }),
        );

        for (const width of WIDTHS) {
          await page.setViewportSize({ width, height: 900 });
          const scrollWidth = await page.evaluate(
            () => Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
          );
          if (scrollWidth > width + OVERFLOW_TOLERANCE) {
            overflowFails.push({ theme, route, width, scrollWidth });
          }
        }

        for (const width of AXE_WIDTHS) {
          await page.setViewportSize({ width, height: 900 });
          const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
          axeRuns++;
          for (const v of violations) {
            if (!FAIL_IMPACTS.has(v.impact)) continue;
            axeFails.push({ theme, route, width, id: v.id, impact: v.impact, nodes: v.nodes.length });
          }
        }
      }
      await context.close();
    }
  } finally {
    await browser.close();
    server.close();
  }

  const targets = THEMES.length * ROUTES.length;
  console.log(
    `a11y-sweep: ${targets} route/theme targets, ${targets * WIDTHS.length} overflow checks, ${axeRuns} axe scans`,
  );

  if (overflowFails.length) {
    console.error(`a11y-sweep: ${overflowFails.length} horizontal-overflow failure(s):`);
    for (const f of overflowFails) {
      console.error(`  - ${f.theme} ${f.route} @ ${f.width}px: document width ${f.scrollWidth}px`);
    }
  }
  if (axeFails.length) {
    console.error(`a11y-sweep: ${axeFails.length} axe violation(s) (${[...FAIL_IMPACTS].join("/")}):`);
    for (const f of axeFails) {
      console.error(`  - ${f.theme} ${f.route} @ ${f.width}px: ${f.id} [${f.impact}] x${f.nodes}`);
    }
  }
  if (overflowFails.length || axeFails.length) {
    process.exitCode = 1;
    return;
  }
  console.log("a11y-sweep: no overflow, no serious/critical axe violation. Clean.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
