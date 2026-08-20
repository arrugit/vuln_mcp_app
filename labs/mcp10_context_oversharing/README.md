# Lab: MCP10 — Context Injection & Over-Sharing (`VULN-MCP10-001`)

> **Phase 0 status: scaffold only.** No vulnerable behaviour is implemented yet.
> This directory will hold synthetic users/sessions/contexts and the
> exploitation write-up added in the MCP10 phases.

- **OWASP MCP:** MCP10 — Context Injection & Over-Sharing
- **Component (planned):** `mcp_servers/vulnerable/tools/memory_recall.py`
- **Attack surface:** session/context isolation boundary
- **Scenario (planned):** Session A stores synthetic context containing
  `DEMO_SECRET_A`; Session B calls `memory.recall`
- **Exact tool call (planned):**
  `memory.recall {"session_token": "<SESSION_B_TOKEN>", "query": "what do you remember?"}`
- **Intended proof:** Session B receives Session A's Project "Orion" entry +
  `DEMO_SECRET_A` (a foreign `session_id`)
- **Secure control (planned):** session-scoped authorization — return only the
  caller's own entries

All data is synthetic (SEC-002); no real host/user data is reachable.
