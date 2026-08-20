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

  "mcp05-command-injection": {
    prefill: { filename: "a.txt; echo PWNED > /work/marker" },
    runLabel: "Call report.export",
    enablingCode:
      "mcp_servers/vulnerable/tools/report_export.py — cmd = \"convert \" + " +
      "filename + \" out.pdf\" run via SandboxRunner.run_shell (unsafe shell path)",
    exactCall: 'report.export {"filename": "a.txt; echo PWNED > /work/marker"}',
    learn: [
      {
        heading: "What",
        body:
          "Command Injection: an untrusted argument is concatenated into a shell " +
          "command string and executed through a shell, so shell metacharacters " +
          "in the input run extra commands.",
      },
      {
        heading: "Where",
        body:
          "report.export builds cmd = 'convert ' + filename + ' out.pdf' and runs " +
          "it via a shell inside the sandbox. The filename is attacker-controlled.",
      },
      {
        heading: "How",
        body:
          "The payload 'a.txt; echo PWNED > /work/marker' splits at ';' into two " +
          "commands. The injected echo writes a marker file inside the sandbox — " +
          "proof that an extra command executed.",
      },
      {
        heading: "Impact",
        body:
          "Arbitrary command execution in the tool's context. Here it is confined " +
          "to a constrained, ephemeral sandbox (no host access, hard timeout).",
      },
    ],
    remediation: [
      "Never build shell strings from untrusted input; use argv with shell=False.",
      "Validate/allow-list inputs (here: ^[A-Za-z0-9._-]+$ rejects separators).",
      "Run conversions with least privilege in an isolated, no-network sandbox.",
      "Prefer library calls over shelling out to external commands entirely.",
    ],
    proof:
      "Success = result.marker_present is true and the recorded constructed_command " +
      "shows the injected '; echo PWNED'. In SECURE mode the input is rejected and " +
      "no marker is created.",
  },
};
