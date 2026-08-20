// Severity badge with a NON-color indicator too (UX-003 / §38 accessibility):
// color alone never conveys meaning — the label text is always present.
import type { JSX } from "react";

const SEVERITY_CLASS: Record<string, string> = {
  Critical: "text-severity-critical border-severity-critical",
  High: "text-severity-high border-severity-high",
  Medium: "text-severity-medium border-severity-medium",
  Low: "text-severity-low border-severity-low",
  Info: "text-severity-info border-severity-info",
};

export function SeverityBadge({ severity }: { severity: string }): JSX.Element {
  const cls = SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.Info;
  return (
    <span
      className={`inline-block text-xs font-semibold uppercase tracking-wide border rounded px-2 py-0.5 ${cls}`}
    >
      {severity}
    </span>
  );
}
