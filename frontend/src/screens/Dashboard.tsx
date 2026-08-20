// Dashboard — loads the lab catalog, renders the three-tab module bar, and
// shows the active vulnerability module (FR-052/FR-053).
import { useEffect, useState, type JSX } from "react";
import { api } from "../lib/api";
import type { LabSummary } from "../lib/types";
import { ModuleTabs } from "../components/ModuleTabs";
import { VulnerabilityModule } from "./VulnerabilityModule";

export function Dashboard(): JSX.Element {
  const [labs, setLabs] = useState<LabSummary[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listLabs()
      .then((rows) => {
        setLabs(rows);
        if (rows.length > 0) setActiveId(rows[0].id);
      })
      .catch((e: unknown) => setError(String(e)));
  }, []);

  if (error) {
    return (
      <div className="p-6 text-severity-high">
        Could not load labs. Is the backend running on :8000? ({error})
      </div>
    );
  }

  return (
    <div>
      <ModuleTabs labs={labs} activeId={activeId} onSelect={setActiveId} />
      {activeId !== null && <VulnerabilityModule labId={activeId} />}
    </div>
  );
}
