import type { SseEvent } from "@/lib/types";

import type { DemoFixture, RawSseFrame } from "./fixtures";

// Replays a captured fixture as if it were a live SSE stream: emits the same
// event sequence, in order, with a compressed version of the real inter-event
// cadence so the progress waterfall still feels alive without making a recruiter
// wait the real ~60-130s. The pacing is cosmetic only; the persisted history
// entry is stamped with the fixture's REAL measured timing (see use-triage), so
// the observability waterfall stays honest.

const SPEED = 12; // real ms / SPEED = replayed ms
const MAX_STEP_MS = 900; // cap any single gap so a slow tool call is not a dead wait
const MIN_STEP_MS = 60; // keep successive events visually distinct

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    function onAbort() {
      clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export interface ReplayOptions {
  signal?: AbortSignal;
  onEvent: (event: SseEvent) => void;
}

export async function replayFixture(
  fixture: DemoFixture,
  opts: ReplayOptions,
): Promise<void> {
  let prevAtMs = 0;
  for (const frame of fixture.frames as RawSseFrame[]) {
    if (opts.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const realGap = Math.max(0, frame.at_ms - prevAtMs);
    prevAtMs = frame.at_ms;
    const wait = Math.min(MAX_STEP_MS, Math.max(MIN_STEP_MS, realGap / SPEED));
    await sleep(wait, opts.signal);
    // Frame shape mirrors the wire: { event, data }. The union cast is safe
    // because the fixtures are real captures validated server-side at capture
    // time, exactly like the live parser trusts them (see lib/sse.ts).
    opts.onEvent({ type: frame.event, data: frame.data } as SseEvent);
  }
}
