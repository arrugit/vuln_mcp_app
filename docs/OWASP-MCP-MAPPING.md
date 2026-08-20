# OWASP-MCP-MAPPING.md — `vuln_mcp_app`

Maps each planted vulnerability to the official **OWASP MCP Top 10** (verified
2026-08-18; living document, currently beta — re-verify before finalising
detection claims, ASSUMPTION A-01). This is the single point of update if OWASP
renumbers/renames.

## Full OWASP MCP Top 10 (reference)

| ID | Official name | In this lab? |
|----|---------------|--------------|
| MCP01 | Token Mismanagement & Secret Exposure | no |
| MCP02 | Privilege Escalation via Scope Creep | no |
| **MCP03** | **Tool Poisoning** | **yes — VULN-MCP03-001 (implemented)** |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | no |
| **MCP05** | **Command Injection & Execution** | **yes — VULN-MCP05-001 (implemented)** |
| MCP06 | Intent Flow Subversion | no |
| MCP07 | Insufficient Authentication & Authorization | no |
| MCP08 | Lack of Audit and Telemetry | infra only (telemetry) — NOT a lab |
| MCP09 | Shadow MCP Servers | no |
| **MCP10** | **Context Injection & Over-Sharing** | **yes — VULN-MCP10-001 (pending)** |

## Mapping detail

### MCP03 — Tool Poisoning → `VULN-MCP03-001` (implemented)

- **Why MCP03:** the vulnerability lives in the MCP **tool definition/metadata**
  and the tool handler — malicious/misleading instructions injected via a tool
  definition to manipulate behaviour, plus a data-exfiltration side effect. This
  is MCP-native (it only exists because of MCP's tool-definition trust model).
- **Detector capability exercised:** static analysis of tool metadata +
  behavioural analysis of tool output.
- **Component:** `mcp_servers/vulnerable/tools/docs_fetch.py`.
- **Not MCP06 (Intent Flow Subversion):** the effect here is deterministic and
  server-side, not an LLM's objective being hijacked at runtime.
- **Not MCP01 (Secret Exposure):** the secret is synthetic and the flaw is the
  poisoned tool, not generic secret storage.

### MCP05 — Command Injection & Execution → `VULN-MCP05-001` (implemented)

- **Why MCP05:** untrusted input reaches a command construction sink via an MCP
  tool call — classic injection reached through the MCP delivery path.
- **Detector capability exercised:** taint/dataflow analysis from input to sink.
- **Component:** `mcp_servers/vulnerable/tools/report_export.py` (unsafe string
  concatenation) + `sandbox/runner.py::run_shell`.
- **Not MCP03:** the flaw is in the handler's command construction, not the tool
  metadata (the stored definitions differ only to make the diff visible).

### MCP10 — Context Injection & Over-Sharing → `VULN-MCP10-001` (pending)

- **Why MCP10:** shared context crosses a session/user boundary because an
  ownership check is missing — MCP-native context isolation failure.
- **Detector capability exercised:** behavioural/authorization testing across
  sessions.

## Note on MCP08 (telemetry)

Telemetry is implemented as **supporting infrastructure** (audit trail) to make
evidence observable. It is deliberately **not** a fourth vulnerability lab
(PRD §11, SEC scope).
