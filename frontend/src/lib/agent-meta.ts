import { DEMO_MODE } from "@/demo/config";
import demoMeta from "@/demo/meta.json";
import type { AgentMeta } from "@/lib/types";

// Demo builds have no backend: serve the committed /v1/meta snapshot so the
// real system prompt + tool inventory still resolve, keyless. Shared by the
// transparency tab and the command palette's "copy system prompt" action.
export async function loadAgentMeta(): Promise<AgentMeta> {
  if (DEMO_MODE) return demoMeta as AgentMeta;
  const res = await fetch("/api/meta");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as AgentMeta;
}
