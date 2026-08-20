// labContent data tests (Vitest). Ensures each implemented lab tab has its exact
// pre-filled exploit payload (FR-051a) and an enabling-code pointer (FR-051b).
import { describe, expect, it } from "vitest";
import { LAB_CONTENT } from "./labContent";

describe("LAB_CONTENT", () => {
  it("MCP03 pre-fills the docs.fetch doc_id and points at the enabling code", () => {
    const c = LAB_CONTENT["mcp03-tool-poisoning"];
    expect(c.prefill).toEqual({ doc_id: "welcome" });
    expect(c.enablingCode).toContain("docs_fetch.py");
    expect(c.exactCall).toContain("docs.fetch");
  });

  it("MCP05 pre-fills the exact injection payload and points at the sink", () => {
    const c = LAB_CONTENT["mcp05-command-injection"];
    expect(c.prefill).toEqual({ filename: "a.txt; echo PWNED > /work/marker" });
    expect(c.enablingCode).toContain("report_export.py");
    expect(c.exactCall).toContain("report.export");
  });

  it("every lab entry has learn items and remediation bullets", () => {
    for (const c of Object.values(LAB_CONTENT)) {
      expect(c.learn.length).toBeGreaterThan(0);
      expect(c.remediation.length).toBeGreaterThan(0);
    }
  });
});
