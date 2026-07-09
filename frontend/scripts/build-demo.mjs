// Build the keyless static demo export (`out/`).
//
// `output: export` rejects App Router route handlers (they need a server), but
// the app carries /api/triage and /api/meta for the live build. This script
// stashes the whole api/ tree OUTSIDE the app/ routing root for the duration of
// the export build, then restores it — even if the build fails — so the working
// tree is never left mutated. Idempotent and safe to Ctrl-C: on the next run it
// restores a leftover stash before starting.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const API_DIR = resolve(root, "src/app/api");
const STASH_DIR = resolve(root, "src/_api_stash"); // outside app/: not routed

async function restore() {
  if (existsSync(STASH_DIR) && !existsSync(API_DIR)) {
    await rename(STASH_DIR, API_DIR);
  }
}

async function main() {
  // Recover from an interrupted previous run before doing anything.
  await restore();

  // Regenerate the docs corpus first (this script bypasses the `prebuild`
  // hook by calling `next build` directly). No-op when docs/ is out of context.
  const gen = spawnSync("node", ["scripts/gen-docs.mjs"], { cwd: root, stdio: "inherit" });
  if (gen.status !== 0) {
    process.exitCode = gen.status ?? 1;
    return;
  }

  const hadApi = existsSync(API_DIR);
  if (hadApi) await rename(API_DIR, STASH_DIR);

  try {
    const result = spawnSync("npx", ["--no-install", "next", "build"], {
      cwd: root,
      stdio: "inherit",
      env: { ...process.env, NEXT_PUBLIC_DEMO_MODE: "1" },
    });
    if (result.status !== 0) {
      process.exitCode = result.status ?? 1;
    }
  } finally {
    if (hadApi) await restore();
  }

  if (process.exitCode === undefined || process.exitCode === 0) {
    console.log("\nStatic demo export written to out/. Serve it with any static host.");
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
