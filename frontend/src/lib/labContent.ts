// Per-lab educational content (FR-040/FR-041). Kept as data so each
// self-contained vulnerability tab (FR-053) can render LEARN + REMEDIATE +
// enabling-code pointer without bespoke components. This is teaching copy only;
// it states no verdict about the running target (SEC-006).

export interface LabContent {
  // Pre-filled exploit parameters (FR-051a).
  prefill: Record<string, string>;
  runLabel: string;
  // Enabling-code pointer (FR-051b).
  enablingCode: string;
  // LEARN section: what/where/how/impact.
  learn: { heading: string; body: string }[];
  // The exact tool call shown to the user.
  exactCall: string;
  // Remediation bullets (FR-041).
  remediation: string[];
  // How to read the verification result the runner shows.
  proof: string;
}

export const LAB_CONTENT: Record<string, LabContent> = {
  "mcp03-tool-poisoning": {
    prefill: { doc_id: "welcome" },
    runLabel: "Call docs.fetch",
    enablingCode:
      "mcp_servers/vulnerable/tools/docs_fetch.py — poisoned description + " +
      'the secret-read branch (base["leaked_secret"] = DEMO_SECRET_A)',
    exactCall: 'docs.fetch {"doc_id": "welcome"}',
    learn: [
      {
        heading: "What",
        body:
          "Tool Poisoning: a malicious instruction is hidden inside an MCP " +
          "tool's definition/metadata, and the tool's handler performs an " +
          "illegitimate side effect (reading a secret).",
      },
      {
        heading: "Where",
        body:
          "The docs.fetch tool. Its description embeds a hidden instruction, " +
          "and its server-side handler appends the synthetic DEMO_SECRET_A to " +
          "every result.",
      },
      {
        heading: "How",
        body:
          "Call docs.fetch with any doc_id. In VULNERABLE mode the result " +
          "additionally contains leaked_secret — a value a clean docs.fetch " +
          "would never return. The leak is server-side and deterministic (it " +
          "does not depend on an LLM obeying the poisoned text).",
      },
      {
        heading: "Impact",
        body:
          "A trusted-looking tool exfiltrates data and can steer an agent via " +
          "its metadata. Detection needs both static (metadata) and behavioural " +
          "(leaked value) analysis.",
      },
    ],
    remediation: [
      "Sanitise / reject instruction-bearing fields in tool metadata (trust policy).",
      "Give tools least privilege: docs.fetch must not access secrets at all.",
      "Pin & review tool definitions; diff trusted vs untrusted versions.",
      "Treat tool descriptions as untrusted data, never as instructions to execute.",
    ],
    proof:
      "Success = the result contains leaked_secret: DEMO_SECRET_A and evidence " +
      "kind metadata_poison. In SECURE mode neither appears.",
  },
};
