# Lab: MCP05 — Command Injection & Execution (`VULN-MCP05-001`)

> **Phase 0 status: scaffold only.** No vulnerable behaviour is implemented yet.
> This directory will hold payloads, expected outputs, and the exploitation
> write-up added in the MCP05 phases.

- **OWASP MCP:** MCP05 — Command Injection & Execution
- **Component (planned):** `mcp_servers/vulnerable/tools/report_export.py`
- **Attack surface:** untrusted input → command construction → sandboxed exec
- **Exact payload (planned):** `a.txt; echo PWNED > /work/marker`
- **Exact tool call (planned):** `report.export {"filename": "a.txt; echo PWNED > /work/marker"}`
- **Intended proof:** `/work/marker` created inside the sandbox; constructed
  command recorded with the injected `; echo PWNED …`
- **Secure control (planned):** allow-list regex validation + parameterised
  (argv) execution, no shell

Execution is confined to the isolated sandbox (SEC-003). The blast radius ends
at the sandbox — never the host (SEC-001).
