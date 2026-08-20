// Lab lifecycle status badge. This is NOT a vulnerability verdict (SEC-006):
// "pending" means the lab implementation is not built yet, "ready" means the
// lab module is implemented — neither states whether the target is exploitable.
import type { JSX } from "react";

export function StatusBadge({ status }: { status: string }): JSX.Element {
  const ready = status === "ready";
  const cls = ready
    ? "text-team-blue border-team-blue"
    : "text-severity-info border-severity-info";
  return (
    <span
      className={`inline-block text-[10px] font-medium uppercase tracking-wider border rounded px-1.5 py-0.5 ${cls}`}
    >
      {status}
    </span>
  );
}
