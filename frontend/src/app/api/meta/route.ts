/**
 * Proxy to the FastAPI /v1/meta endpoint. Same rationale as
 * /api/triage: the browser only talks same-origin so no CORS is opened
 * on the backend.
 */

const AGENT_API_URL = process.env.AGENT_API_URL ?? "http://agent-api:8000";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const upstream = await fetch(`${AGENT_API_URL}/v1/meta`, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  if (!upstream.ok) {
    return new Response(
      JSON.stringify({ error: `Upstream HTTP ${upstream.status}` }),
      { status: upstream.status, headers: { "Content-Type": "application/json" } },
    );
  }
  const body = await upstream.text();
  return new Response(body, {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
