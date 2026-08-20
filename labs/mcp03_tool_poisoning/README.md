# Lab: MCP03 — Tool Poisoning (`VULN-MCP03-001`)

> **Phase 0 status: scaffold only.** No vulnerable behaviour is implemented yet.
> This directory will hold the trusted + poisoned tool definitions, fixtures, and
> the exploitation write-up (`write-up.md`, DECISION D-07) added in the MCP03
> phases.

- **OWASP MCP:** MCP03 — Tool Poisoning
- **Component (planned):** `mcp_servers/vulnerable/tools/docs_fetch.py`
- **Attack surface:** trust in MCP tool definitions / metadata
- **Exact tool call (planned):** `docs.fetch {"doc_id": "welcome"}`
- **Intended proof:** result leaks synthetic `DEMO_SECRET_A`
- **Secure control (planned):** metadata sanitisation / trust policy + no
  secret-reading branch

Ground truth for this lab lives in `docs/GROUND-TRUTH.md` (authored in the MCP03
phases), never in a runtime API (SEC-006).
