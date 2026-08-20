// TelemetryConsole (S7) — renders the MCP protocol trace for one lab run in a
// monospace CLIENT<->SERVER style (FR-014, TDD §6). It shows raw protocol
// evidence; it is not a verdict (SEC-006).
import type { JSX } from "react";
import type { TelemetryEventView } from "../lib/types";

export function TelemetryConsole({
  events,
}: {
  events: TelemetryEventView[];
}): JSX.Element {
  if (events.length === 0) {
    return (
      <p className="mono text-xs text-slate-500">No telemetry for this run yet.</p>
    );
  }
  return (
    <div className="mono text-xs bg-surface-base border border-surface-border rounded p-3 space-y-1 max-h-64 overflow-y-auto">
      {events.map((e) => {
        const arrow = e.direction.includes("client->") ? "→" : "←";
        return (
          <div key={e.id} className="flex gap-2">
            <span className="text-slate-600">{e.ts.slice(11, 19)}</span>
            <span className="text-team-purple">{arrow}</span>
            <span className="text-team-blue">{e.method}</span>
            {e.security_event && (
              <span className="text-severity-critical">
                [{e.security_event}]
              </span>
            )}
            <span className="text-slate-400 truncate">
              {JSON.stringify(e.payload)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
