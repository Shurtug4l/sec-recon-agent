import type { SseEvent } from "./types";

// EventSource cannot POST a body, so we use fetch + ReadableStream and
// parse the SSE wire format manually. Format reminder:
//
//   event: started
//   data: {"query": "..."}
//   <blank line>
//
// Frames are separated by a blank line. Each frame carries one `event:`
// and one `data:` line in our wire (we never split data across multiple
// lines on the server side).

export interface SseStreamOptions {
  url: string;
  body: unknown;
  signal?: AbortSignal;
  onEvent: (event: SseEvent) => void;
}

export async function streamSse(opts: SseStreamOptions): Promise<void> {
  const response = await fetch(opts.url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify(opts.body),
    signal: opts.signal,
  });

  if (!response.ok || !response.body) {
    throw new Error(`HTTP ${response.status} ${response.statusText}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    // SSE servers commonly use CRLF (\r\n) line endings - sse-starlette,
    // the Starlette SSE helper used by our backend, defaults to that.
    // Normalize to LF so the \n\n frame separator and prefix checks below
    // work uniformly. Without this normalization the parser silently
    // accumulates the entire response in `buffer` and never emits events.
    buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");

    // Split out complete frames (separated by blank line).
    let frameEnd: number;
    while ((frameEnd = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, frameEnd);
      buffer = buffer.slice(frameEnd + 2);

      const event = parseFrame(frame);
      if (event) opts.onEvent(event);
    }
  }
}

function parseFrame(frame: string): SseEvent | null {
  let eventType: string | null = null;
  let dataLine: string | null = null;

  for (const line of frame.split("\n")) {
    if (line.startsWith(": ")) continue; // SSE comment (keepalive)
    if (line.startsWith("event:")) {
      eventType = line.slice("event:".length).trim();
    } else if (line.startsWith("data:")) {
      dataLine = line.slice("data:".length).trimStart();
    }
  }

  if (!eventType || dataLine === null) return null;

  try {
    const data = JSON.parse(dataLine);
    // Trust the typed union; runtime shape is validated server-side.
    return { type: eventType, data } as SseEvent;
  } catch {
    return null;
  }
}
