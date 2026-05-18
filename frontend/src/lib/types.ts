// Mirror of the Pydantic schemas defined in
// src/sec_recon_agent/agent/schema.py. Kept in sync by hand; the agent
// can only return shapes that pass Pydantic validation, so anything new
// here that does not exist server-side is dead code.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface CVEReference {
  cve_id: string;
  summary: string;
  cvss_v3_score: number | null;
  severity: Severity;
  exploits_public: boolean;
  affected_products: string[];
  nvd_url: string;
}

export interface AttackMitigation {
  id: string;        // M-XXXX
  name: string;
  url: string;
}

export interface AttackTechnique {
  id: string;        // T-XXXX or T-XXXX.YYY
  name: string;
  tactics: string[];
  url: string;
  mitigations: AttackMitigation[];
  related_cwes: string[];
}

export interface TriageReport {
  summary: string;
  severity: Severity;
  confidence: Confidence;
  recommended_action: string;
  cves: CVEReference[];
  attack_techniques: AttackTechnique[];
  reasoning_chain: string[];
}

// SSE event payload shapes emitted by api/stream.py.
export type SseEvent =
  | { type: "started"; data: { query: string } }
  | { type: "node"; data: { node: string } }
  | { type: "final"; data: TriageReport }
  | { type: "error"; data: { type: string; message: string } };

// Local history entry persisted in localStorage.
export interface HistoryEntry {
  id: string;
  query: string;
  report: TriageReport | null;
  startedAt: string; // ISO 8601
  durationMs: number | null;
  error: string | null;
}

// /v1/meta response — system prompt + tool inventory for the transparency view.
export interface ToolMeta {
  name: string;
  description: string;
}

export interface AgentMeta {
  system_prompt: string;
  model: string;
  tools: ToolMeta[];
}
