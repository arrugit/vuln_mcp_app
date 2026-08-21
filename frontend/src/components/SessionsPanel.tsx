// SessionsPanel (MCP10) — shows the synthetic sessions, their contexts, and
// tokens, so the owner can recall as one session and see whether another's data
// leaks. Clicking a token fills the exploit runner's session_token via onPick.
import { useEffect, useState, type JSX } from "react";
import { api } from "../lib/api";
import type { SessionSummary } from "../lib/types";

export function SessionsPanel({
  labId,
  onPick,
}: {
  labId: number;
  onPick?: (token: string) => void;
}): JSX.Element {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  useEffect(() => {
    api.listSessions(labId).then(setSessions).catch(() => {});
  }, [labId]);

  return (
    <div className="card space-y-2">
      <h3 className="text-sm font-semibold uppercase tracking-wide text-team-purple">
        Sessions (synthetic)
      </h3>
      <div className="grid md:grid-cols-2 gap-2">
        {sessions.map((s) => (
          <div key={s.session_token} className="border border-surface-border rounded p-2">
            <div className="text-sm font-semibold">
              {s.user_label} · <span className="text-slate-400">{s.context}</span>
            </div>
            <button
              onClick={() => onPick?.(s.session_token)}
              className="mono text-xs text-team-blue underline"
              title="Use as caller session_token"
            >
              {s.session_token}
            </button>
            <div className="mono text-xs text-slate-500">
              entries: {s.entry_keys.join(", ")}
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-500">
        Recall as <span className="mono">User B</span>; in vulnerable mode you will
        also see <span className="mono">User A</span>'s entries (incl. the secret).
      </p>
    </div>
  );
}
