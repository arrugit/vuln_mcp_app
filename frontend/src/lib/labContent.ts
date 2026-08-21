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
    prefill: { doc_id: "onboarding-notes" },
    runLabel: "Fetch document",
    enablingCode:
      "mcp_servers/vulnerable/tools/docs_fetch.py — render_context = " +
      '{"config": APP_CONFIG}: the whole app config (incl. api_key) is exposed ' +
      "to the {{ }} template renderer (over-broad context).",
    exactCall: 'docs.fetch {"doc_id": "onboarding-notes"}',
    learn: [
      {
        heading: "What",
        body:
          "The docs service renders help articles with a {{ }} template. The " +
          "vulnerable handler passes the ENTIRE app config — including a " +
          "credential (api_key) — into the template context. No line says " +
          "'leak the secret'; the scope is just too broad.",
      },
      {
        heading: "Where",
        body:
          "docs.fetch. Any article whose body contains {{ config.api_key }} — a " +
          "seeded internal doc (onboarding-notes), or one you add below — has " +
          "the credential rendered straight into the returned text.",
      },
      {
        heading: "How",
        body:
          "Fetch onboarding-notes (or add your own doc with {{ config.api_key }}). " +
          "In VULNERABLE mode the body comes back containing DEMO_SECRET_A. In " +
          "SECURE mode the renderer only sees allow-listed public keys, so the " +
          "placeholder is left inert.",
      },
      {
        heading: "Impact",
        body:
          "Untrusted document content reaches sensitive config via templating — " +
          "an information-disclosure / SSTI-style bug. Detection needs dataflow " +
          "analysis (doc content → template scope → secret in output).",
      },
    ],
    remediation: [
      "Give the template renderer least authority: allow-list which keys it can see.",
      "Never place credentials in a context reachable from user/templated content.",
      "Separate secrets from display config; treat document bodies as untrusted.",
      "Add output checks so responses can't contain known-secret material.",
    ],
    proof:
      "Success = the returned body contains DEMO_SECRET_A and evidence kind " +
      "metadata_poison. In SECURE mode the placeholder stays literal and no " +
      "secret appears. Try the public docs (welcome/faq) — they never leak.",
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

  "mcp10-context-oversharing": {
    prefill: { session_token: "sess-bob-b2b2b2", query: "what do you remember?" },
    runLabel: "Recall as Session B",
    enablingCode:
      "mcp_servers/vulnerable/tools/memory_recall.py — entries = store.all_entries() " +
      "(no ownership filter); the caller's session_token is accepted but never used to scope.",
    exactCall:
      'memory.recall {"session_token": "sess-bob-b2b2b2", "query": "what do you remember?"}',
    learn: [
      {
        heading: "What",
        body:
          "Context over-sharing: memory.recall is supposed to return only the " +
          "calling session's remembered entries, but the ownership check is " +
          "missing, so it returns every session's entries.",
      },
      {
        heading: "Where",
        body:
          "memory.recall. It accepts the caller's session_token but reads " +
          "store.all_entries() without scoping to that session (a missing " +
          "WHERE-owner filter — broken access control / IDOR).",
      },
      {
        heading: "How",
        body:
          "Recall as Session B (User B). In VULNERABLE mode the result contains " +
          "Session A's (User A) Project Orion entry and api_token (DEMO_SECRET_A) — " +
          "data B must never see. In SECURE mode B receives only B's entries.",
      },
      {
        heading: "Impact",
        body:
          "One user reads another user's private memory / secrets. Detection is " +
          "behavioural/authorization testing: recall as one session, check for " +
          "another session's data in the result.",
      },
    ],
    remediation: [
      "Enforce ownership: scope every read to the authenticated caller's session.",
      "Filter at the data layer (WHERE session = caller), not just in the UI.",
      "Deny-by-default access; never trust a client-supplied id without a check.",
      "Add tests that recall as one user and assert no other user's data appears.",
    ],
    proof:
      "Success = evidence kind context_leak and the result contains an entry whose " +
      "session_token differs from the caller (incl. DEMO_SECRET_A). In SECURE mode " +
      "only the caller's own entries are returned.",
  },
};
