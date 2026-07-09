import demoAudit from "@/demo/audit.json";
import { DEMO_MODE } from "@/demo/config";
import type { AuditTrail } from "@/lib/types";

// Demo builds have no backend: serve the committed /v1/audit snapshot (a real
// hash chain sealed from the seven captured triages, digest-only) so the
// tamper-evident trail is demonstrable keyless. Live builds proxy the real
// endpoint through /api/audit. Same shape either way.
export async function loadAudit(limit = 50): Promise<AuditTrail> {
  if (DEMO_MODE) return demoAudit as AuditTrail;
  const res = await fetch(`/api/audit?limit=${limit}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as AuditTrail;
}
