/**
 * SSE proxy from the browser to the FastAPI agent.
 *
 * We do not want CORS open on the backend (single-tenant demo with no
 * authentication), so the browser talks only to this Next.js route on
 * the same origin, and this route forwards the SSE stream byte-for-byte
 * to the upstream agent API.
 *
 * The upstream URL is configurable via AGENT_API_URL (defaults to the
 * compose-internal hostname `agent-api`). When running `next dev` on
 * the host outside Docker, set AGENT_API_URL=http://localhost:8000.
 */

import { NextRequest } from "next/server";

const AGENT_API_URL = process.env.AGENT_API_URL ?? "http://agent-api:8000";
// Server-side env: never exposed to the browser. When set, the proxy
// attaches it as a Bearer header to upstream calls so the FastAPI
// dependency `verify_api_key` accepts the request. Read inside the
// handler (not at module scope) so a `next dev` restart picks up
// changes without rebuilding the route module.
function agentApiKey(): string | undefined {
  return process.env.AGENT_API_KEY;
}

// Streaming responses can outlive the typical 30s edge timeout. Pin to
// the Node runtime and lift the default route response timeout.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function POST(request: NextRequest) {
  const body = await request.text();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "text/event-stream",
  };
  const key = agentApiKey();
  if (key) headers["Authorization"] = `Bearer ${key}`;

  const upstream = await fetch(`${AGENT_API_URL}/v1/triage`, {
    method: "POST",
    headers,
    body,
  });

  if (!upstream.ok || !upstream.body) {
    return new Response(
      JSON.stringify({ error: `Upstream returned HTTP ${upstream.status}` }),
      { status: upstream.status, headers: { "Content-Type": "application/json" } },
    );
  }

  return new Response(upstream.body, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
