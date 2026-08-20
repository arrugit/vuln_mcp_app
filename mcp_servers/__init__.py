"""MCP plane package (TDD §8, §14).

Two physically separate implementation trees keep vulnerable code away from
infrastructure (DECISION D-04 / SEC-004):

  * ``mcp_servers.vulnerable`` — INTENTIONALLY VULNERABLE tools (added per lab
    in each lab's Phase B; empty scaffolding in Phase 0).
  * ``mcp_servers.secure``     — genuinely-fixed counterparts (added per lab).

``mcp_servers.common`` holds the shared, always-safe machinery: the tool
registry abstraction and the legit control tools (notes.search / notes.summarize)
that are never vulnerable in any mode.
"""
