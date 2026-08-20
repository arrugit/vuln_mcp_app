// TelemetryConsole test (Vitest + Testing Library).
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { TelemetryConsole } from "./TelemetryConsole";
import type { TelemetryEventView } from "../lib/types";

const EVENTS: TelemetryEventView[] = [
  {
    id: 1,
    lab_run_id: 1,
    ts: "2026-08-20T10:00:00+00:00",
    direction: "client->server",
    method: "tools/call",
    payload: { name: "docs.fetch" },
    mode: "vulnerable",
    security_event: "secret_leak",
  },
];

describe("TelemetryConsole", () => {
  it("renders a method and its security_event tag", () => {
    render(<TelemetryConsole events={EVENTS} />);
    expect(screen.getByText("tools/call")).toBeInTheDocument();
    expect(screen.getByText("[secret_leak]")).toBeInTheDocument();
  });

  it("shows an empty-state message when there are no events", () => {
    render(<TelemetryConsole events={[]} />);
    expect(screen.getByText(/No telemetry/i)).toBeInTheDocument();
  });
});
