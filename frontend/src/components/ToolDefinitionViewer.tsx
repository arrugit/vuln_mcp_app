// ToolDefinitionViewer (S6) — shows a lab tool's stored versions side by side
// so the trusted-vs-unsafe difference is inspectable (FR-013). It reads stored
// definition metadata; it is not a verdict (SEC-006). The version marked active
// is the one currently served in the lab's mode.
import { useEffect, useState, type JSX } from "react";
import { api } from "../lib/api";
import type { MCPToolDetail, ToolVersionView } from "../lib/types";

// Resolve the tool id for a tool name (the viewer takes a name for convenience).
function useToolDetail(toolName: string): MCPToolDetail | null {
  const [detail, setDetail] = useState<MCPToolDetail | null>(null);
  useEffect(() => {
    let cancelled = false;
    api
      .listTools()
      .then((tools) => {
        const t = tools.find((x) => x.name === toolName);
        if (t) return api.getTool(t.id);
        return null;
      })
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch(() => {
        if (!cancelled) setDetail(null);
      });
    return () => {
      cancelled = true;
    };
  }, [toolName]);
  return detail;
}

function VersionCard({ v }: { v: ToolVersionView }): JSX.Element {
  const poisoned = v.trust_status !== "trusted";
  return (
    <div
      className={`flex-1 rounded border p-3 ${
        poisoned ? "border-severity-critical" : "border-team-blue"
      }`}
    >
      <div className="flex items-center gap-2 mb-2">
        <span
          className={`text-xs font-semibold uppercase ${
            poisoned ? "text-severity-critical" : "text-team-blue"
          }`}
        >
          {v.trust_status}
        </span>
        {v.is_active && (
          <span className="text-[10px] uppercase border border-team-purple text-team-purple rounded px-1">
            active
          </span>
        )}
      </div>
      <p className="mono text-xs text-slate-300 whitespace-pre-wrap break-words">
        {v.definition.description}
      </p>
    </div>
  );
}

export function ToolDefinitionViewer({ toolName }: { toolName: string }): JSX.Element {
  const detail = useToolDetail(toolName);

  if (!detail) {
    return <p className="mono text-xs text-slate-500">Loading tool definition…</p>;
  }
  const trusted = detail.versions.find((v) => v.trust_status === "trusted");
  const unsafe = detail.versions.find((v) => v.trust_status !== "trusted");

  return (
    <div className="card space-y-2">
      <h3 className="text-sm font-semibold uppercase tracking-wide text-team-purple">
        Tool definition — trusted vs unsafe ({detail.name})
      </h3>
      {trusted && unsafe ? (
        <div className="flex flex-col md:flex-row gap-3">
          <VersionCard v={trusted} />
          <VersionCard v={unsafe} />
        </div>
      ) : (
        <p className="mono text-xs text-slate-400">
          {detail.versions.length} stored version(s); no diff to show.
        </p>
      )}
      <p className="text-xs text-slate-500">
        The "active" version is what the server currently serves in this lab's
        mode. This is stored metadata, not a verdict.
      </p>
    </div>
  );
}
