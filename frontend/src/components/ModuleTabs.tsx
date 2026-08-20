// Three-tab module bar — the app's PRIMARY navigation (FR-052 / UX-008).
// One tab per vulnerability (MCP03, MCP05, MCP10). The active tab is visually
// distinct; switching tabs switches between the three self-contained modules.
import type { JSX } from "react";
import type { LabSummary } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  labs: LabSummary[];
  activeId: number | null;
  onSelect: (id: number) => void;
}

export function ModuleTabs({ labs, activeId, onSelect }: Props): JSX.Element {
  return (
    <nav
      className="flex gap-2 px-6 pt-4"
      role="tablist"
      aria-label="Vulnerability modules"
    >
      {labs.map((lab) => {
        const active = lab.id === activeId;
        return (
          <button
            key={lab.id}
            role="tab"
            aria-selected={active}
            onClick={() => onSelect(lab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg border-b-2 transition-colors ${
              active
                ? "border-team-purple bg-surface-raised text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <span className="mono text-xs">{lab.owasp_id}</span>
            <span className="text-sm">{lab.title.replace(/^MCP\d+ — /, "")}</span>
            <SeverityBadge severity={lab.severity} />
          </button>
        );
      })}
    </nav>
  );
}
