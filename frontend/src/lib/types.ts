// Shared types mirroring the control-plane API (TDD §12).
// None of these carry a vulnerability verdict (SEC-006) — the UI shows evidence
// and mode, never a boolean "is vulnerable".

export type Mode = "vulnerable" | "secure";

export interface LabSummary {
  id: number;
  slug: string;
  title: string;
  owasp_id: string;
  severity: string;
  difficulty: string;
  status: string;
  mode: Mode;
}

export interface VulnerabilityDescriptor {
  vuln_code: string;
  owasp_id: string;
  component: string;
  attack_surface: string;
}

export interface LabDetail extends LabSummary {
  vulnerability: VulnerabilityDescriptor | null;
}

export interface Health {
  backend: string;
  mcp_server: string;
  mode?: Mode | null;
}

export interface EvidenceRecord {
  id: number;
  lab_run_id: number;
  kind: string;
  observable: string;
  raw_signal: unknown;
  created_at: string;
}

export interface TelemetryEventView {
  id: number;
  lab_run_id: number | null;
  ts: string;
  direction: string;
  method: string;
  payload: unknown;
  mode: string | null;
  security_event: string | null;
}
