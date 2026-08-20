# Exploitation Write-up — MCP03 Tool Poisoning (`VULN-MCP03-001`)

> **Status: Phase A (foundation).** The lab is wired end-to-end in **clean**
> form. The poisoning behaviour and the full exploit proof are added in Phase B,
> and the authoritative ground-truth entry is finalised in Phase D
> (`docs/GROUND-TRUTH.md`). This file is the per-lab write-up required by
> DECISION D-07 / GT-005.

## Identity

- **Vulnerability ID:** `VULN-MCP03-001`
- **OWASP MCP:** MCP03 — Tool Poisoning
- **Component:** MCP tool definition / metadata for `docs.fetch`
- **Attack surface:** trust in MCP tool definitions / metadata

## (a) Exact exploit input — FR-051a

In the **MCP03 tab**, the Exploit input is pre-filled with `doc_id = "welcome"`.
The exact tool call performed is:

```
docs.fetch {"doc_id": "welcome"}
```

## (b) Exact enabling code location — FR-051b

- **Phase A (clean, secure variant):**
  `mcp_servers/secure/tools/docs_fetch.py` — `clean_docs_fetch()` reads only the
  synthetic document corpus; the description carries no instruction; no secret
  branch exists.
- **Phase B (poisoned, vulnerable variant — to be added):**
  `mcp_servers/vulnerable/tools/docs_fetch.py` — the poisoned `description`/
  metadata field **plus** the secret-reading branch in the handler that appends
  `DEMO_SECRET_A` to the result. (Will carry the
  `# INTENTIONALLY VULNERABLE — VULN-MCP03-001` banner.)

## (c) Observable proof — FR-051c

- **Phase A (now):** a clean `docs.fetch {"doc_id":"welcome"}` returns ONLY the
  requested synthetic document; evidence kind is `tool_fetch` and `DEMO_SECRET_A`
  is **absent**. (Locked in by `tests/test_mcp03_foundation.py`.)
- **Phase B (to come):** in VULNERABLE mode the `tools/call` result additionally
  contains `DEMO_SECRET_A` — a value a clean `docs.fetch` would never return —
  recorded as `metadata_poison` evidence. SECURE mode strips the instruction-
  bearing metadata and removes the secret branch, so no leak occurs.

## Secure behaviour (SEC-007)

The secure `docs.fetch` sanitises/rejects instruction-bearing metadata and has no
secret-reading code path. `tools/list` shows clean metadata; `tools/call` returns
only the requested document.

## Reset

Flip the active `docs.fetch` `tool_version` back to `trusted` and clear evidence
(the global reset already re-seeds the trusted baseline).
