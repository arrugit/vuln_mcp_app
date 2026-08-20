// Foundation frontend test (Vitest + Testing Library, TDD §4).
// Verifies the severity badge renders its label (non-color indicator, UX-003).
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "./SeverityBadge";

describe("SeverityBadge", () => {
  it("renders the severity label as text (not color-only)", () => {
    render(<SeverityBadge severity="Critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("falls back gracefully for unknown severities", () => {
    render(<SeverityBadge severity="Unknown" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });
});
