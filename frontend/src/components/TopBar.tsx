// Top bar showing the lab identity + live environment status (FR-005).
// It renders health (backend/mcp-server/mode) but never a vuln verdict.
import { useEffect, useState, type JSX } from "react";
import { api } from "../lib/api";
import type { Health } from "../lib/types";

export function TopBar(): JSX.Element {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch((e: unknown) => setError(String(e)));
  }, []);

  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-surface-border">
      <div>
        <h1 className="text-lg font-bold tracking-tight">
          vuln_mcp_app
          <span className="ml-2 text-xs font-normal text-severity-info">
            MCP Security Testing Laboratory
          </span>
        </h1>
      </div>
      <div className="mono text-xs text-slate-400">
        {error ? (
          <span className="text-severity-high">backend unreachable</span>
        ) : health ? (
          <span>
            backend:{health.backend} · mcp:{health.mcp_server}
            {health.mode ? ` · mode:${health.mode}` : ""}
          </span>
        ) : (
          <span>connecting…</span>
        )}
      </div>
    </header>
  );
}
