// Build-time demo flag. Set NEXT_PUBLIC_DEMO_MODE=1 for the keyless static
// export (see scripts/build-demo.mjs): the app then replays committed real SSE
// fixtures instead of calling the backend, so the whole thing runs with no
// Anthropic key, no ChromaDB seed, and no server. In a normal build the flag is
// unset and the app talks to the live agent API as usual.
export const DEMO_MODE = process.env.NEXT_PUBLIC_DEMO_MODE === "1";

// The model the demo fixtures were actually captured with (surfaced in the demo
// banner so the run is honestly attributed; the deployment default is haiku).
export const DEMO_MODEL = "sonnet";
