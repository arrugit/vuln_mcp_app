// ToolDefinitionViewer test (Vitest). Mocks the api module and asserts the
// trusted + unsafe versions and the "active" marker render (FR-013 diff).
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    listTools: () => Promise.resolve([{ id: 7, name: "report.export" }]),
    getTool: () =>
      Promise.resolve({
        id: 7,
        name: "report.export",
        versions: [
          {
            version: 1,
            trust_status: "trusted",
            is_active: false,
            definition: { name: "report.export", description: "validated + argv" },
          },
          {
            version: 2,
            trust_status: "poisoned",
            is_active: true,
            definition: { name: "report.export", description: "shell command build" },
          },
        ],
      }),
  },
}));

import { ToolDefinitionViewer } from "./ToolDefinitionViewer";

describe("ToolDefinitionViewer", () => {
  it("renders both versions and marks the active one", async () => {
    render(<ToolDefinitionViewer toolName="report.export" />);
    await waitFor(() => expect(screen.getByText("trusted")).toBeInTheDocument());
    expect(screen.getByText("poisoned")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText("validated + argv")).toBeInTheDocument();
  });
});
