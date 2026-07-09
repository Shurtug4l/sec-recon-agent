/**
 * Proxy to the FastAPI /v1/audit endpoint. Same rationale as /api/meta:
 * the browser only talks same-origin, so no CORS is opened on the backend.
 * The `limit` query param is forwarded (and re-clamped upstream).
 */

const AGENT_API_URL = process.env.AGENT_API_URL ?? "http://agent-api:8000";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const limit = new URL(request.url).searchParams.get("limit") ?? "50";
  const headers: Record<string, string> = { Accept: "application/json" };
  const key = process.env.AGENT_API_KEY;
  if (key) headers["Authorization"] = `Bearer ${key}`;

  const upstream = await fetch(
    `${AGENT_API_URL}/v1/audit?limit=${encodeURIComponent(limit)}`,
    { method: "GET", headers },
  );
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
