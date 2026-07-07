// NEXT_PUBLIC_DEMO_MODE=1 switches the build to a fully static, keyless export
// (`out/`) that replays committed real SSE fixtures instead of calling the
// backend — see scripts/build-demo.mjs, which stashes the API route handlers
// (incompatible with `output: export`) for the duration of the build. A normal
// build stays `standalone` for slim Docker images and keeps the SSE proxy.
const isDemo = process.env.NEXT_PUBLIC_DEMO_MODE === "1";

// Serve the export under a sub-path (GitHub Pages project site lives at
// /<repo>). Empty for a root-served host (Vercel / Netlify / Cloudflare Pages),
// so basePath is orthogonal to demo mode: only the Pages workflow sets it.
// Must start with "/" and carry no trailing slash; Next prefixes routes AND
// assets from it.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH || "";

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: isDemo ? "export" : "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  ...(basePath ? { basePath, assetPrefix: basePath } : {}),
  ...(isDemo
    ? {
        // next/image has no optimization server in a static export.
        images: { unoptimized: true },
        // Directory-style export (/triage/index.html). Load-bearing under a
        // basePath: without it the client router requests the root route's
        // RSC payload at `${basePath}.txt` — OUTSIDE the project sub-path on
        // GitHub Pages — so every Home prefetch/navigation 404s and falls
        // back to a full page load. With trailing slashes the request is
        // `${basePath}/index.txt`, which the export actually ships.
        trailingSlash: true,
      }
    : {
        experimental: {
          // Allow SSE / streaming response from API routes without the App
          // Router wrapping them.
          proxyTimeout: 600_000,
        },
      }),
};

export default nextConfig;
