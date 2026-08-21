// Optional live-LLM demo (MCP03). Sends a document to the local Ollama model via
// the backend; the vulnerable path pastes untrusted doc text into the prompt
// (indirect prompt injection), the secure path guards it. Degrades gracefully
// when Ollama is off (shows a hint). Non-deterministic by nature — this is the
// realism layer, not the deterministic core (which is the docs.fetch runner).
import { useState, type JSX } from "react";
import { api } from "../lib/api";

export function LlmDemoPanel({ labId }: { labId: number }): JSX.Element {
  const [docId, setDocId] = useState("product-review");
  const [out, setOut] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    try {
      setOut(await api.llmProbe(labId, docId));
    } catch (e: unknown) {
      setOut({ error: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const available = out ? out["available"] !== false : true;
  const followed = out?.["injection_followed"] === true;

  return (
    <details className="card">
      <summary className="cursor-pointer text-sm font-semibold uppercase tracking-wide text-team-purple">
        Live LLM demo (Ollama) — optional
      </summary>
      <div className="mt-3 space-y-2">
        <p className="text-xs text-slate-500">
          Sends a document to your local Ollama model. Needs ENABLE_LOCAL_LLM=true
          and Ollama running. Try the seeded <span className="mono">product-review</span>{" "}
          doc (contains an embedded instruction) in each mode.
        </p>
        <div className="flex items-center gap-2">
          <input
            className="flex-1 bg-surface-base border border-surface-border rounded px-2 py-1 mono text-xs"
            value={docId}
            onChange={(e) => setDocId(e.target.value)}
          />
          <button onClick={run} disabled={busy} className="btn-ghost text-xs">
            {busy ? "Running…" : "Run LLM"}
          </button>
        </div>
        {out && !available && (
          <p className="text-xs text-severity-info">{String(out["note"] ?? "unavailable")}</p>
        )}
        {out && available && (
          <div className="space-y-1">
            <div
              className={`text-xs font-semibold ${
                followed ? "text-severity-critical" : "text-team-blue"
              }`}
            >
              {followed
                ? "model FOLLOWED the injected instruction"
                : "model did not follow the injection"}
              {out["model"] ? ` · ${String(out["model"])}` : ""}
            </div>
            <pre className="mono text-xs bg-surface-base border border-surface-border rounded p-2 overflow-x-auto whitespace-pre-wrap">
              {String(out["llm_output"] ?? out["error"] ?? "")}
            </pre>
          </div>
        )}
      </div>
    </details>
  );
}
