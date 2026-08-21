// Thin API client (TDD §6 lib/api.ts). Logic-light by design (RECOMMENDATION in
// TDD §6): all vulnerability behaviour lives server-side so the FYP analyses the
// real surfaces, not the browser.

import type {
  DocSummary,
  EvidenceRecord,
  Health,
  LabDetail,
  LabSummary,
  MCPToolDetail,
  MCPToolSummary,
  Mode,
  SessionSummary,
  TelemetryEventView,
} from "./types";

// The dev server proxies /api to the backend (see vite.config.ts).
const BASE = "/api";

async function getJSON<T>(path: string): Promise<T> {
  const resp = await fetch(`${BASE}${path}`);
  if (!resp.ok) throw new Error(`GET ${path} -> ${resp.status}`);
  return (await resp.json()) as T;
}

async function postJSON<T>(path: string, body?: unknown): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`POST ${path} -> ${resp.status}`);
  return (await resp.json()) as T;
}

export const api = {
  health: () => getJSON<Health>("/health"),
  listLabs: () => getJSON<LabSummary[]>("/labs"),
  getLab: (id: number) => getJSON<LabDetail>(`/labs/${id}`),
  setMode: (id: number, mode: Mode) =>
    postJSON<{ mode: Mode }>(`/labs/${id}/mode`, { mode }),
  resetLab: (id: number) => postJSON<{ status: string }>(`/labs/${id}/reset`),
  attack: (id: number, trigger: string, params: Record<string, unknown>) =>
    postJSON<{ lab_run_id: number; evidence_ref: string }>(`/labs/${id}/attack`, {
      trigger,
      params,
    }),
  evidence: (labRunId?: number) =>
    getJSON<EvidenceRecord[]>(
      labRunId === undefined ? "/evidence" : `/evidence?lab_run_id=${labRunId}`,
    ),
  telemetry: (labId: number, labRunId?: number) =>
    getJSON<TelemetryEventView[]>(
      labRunId === undefined
        ? `/labs/${labId}/telemetry`
        : `/labs/${labId}/telemetry?lab_run_id=${labRunId}`,
    ),
  listTools: () => getJSON<MCPToolSummary[]>("/mcp/tools"),
  getTool: (id: number) => getJSON<MCPToolDetail>(`/mcp/tools/${id}`),
  // MCP03 docs corpus (list + add-your-own).
  listDocs: (labId: number) => getJSON<DocSummary[]>(`/labs/${labId}/docs`),
  addDoc: (labId: number, doc: { doc_id: string; title: string; body: string }) =>
    postJSON<{ doc_id: string; added: boolean }>(`/labs/${labId}/docs`, doc),
  llmProbe: (labId: number, docId: string) =>
    postJSON<Record<string, unknown>>(`/labs/${labId}/llm`, { doc_id: docId }),
  listSessions: (labId: number) => getJSON<SessionSummary[]>(`/labs/${labId}/sessions`),
};
