# Exploitation Write-up — MCP10 Context Injection & Over-Sharing (`VULN-MCP10-001`)

> **Status: implemented.** Authoritative entry in `docs/GROUND-TRUTH.md`.
> Satisfies D-07 / GT-005.

## Identity

| Field | Value |
|---|---|
| Vulnerability ID | `VULN-MCP10-001` |
| OWASP MCP | MCP10 — Context Injection & Over-Sharing |
| Component | `memory.recall` access scoping |
| Attack surface | Session/context isolation boundary |
| Severity | High · Baseline mode `vulnerable` |

## The bug

`memory.recall` accepts the caller's `session_token` but reads memory without
scoping to that session:

```python
# mcp_servers/vulnerable/tools/memory_recall.py -> memory_recall()
entries = get_context_store().all_entries()   # no owner filter (the flaw)
```

The secure variant scopes to `store.entries_for(token)`. The missing ownership
check is a classic broken-access-control / IDOR mistake.

Synthetic data: Session A (`sess-alice-a1a1`, User A) owns Project Orion and
`api_token = DEMO_SECRET_A`; Session B (`sess-bob-b2b2b2`, User B) owns benign
notes.

## (a) Exact exploit input — FR-051a

```
memory.recall {"session_token": "sess-bob-b2b2b2", "query": "what do you remember?"}
```

## (b) Exact enabling code location — FR-051b

`mcp_servers/vulnerable/tools/memory_recall.py`, `memory_recall()`:
`entries = get_context_store().all_entries()`. Store:
`labs/mcp10_context_oversharing/fixtures.py`. Banner:
`# INTENTIONALLY VULNERABLE — VULN-MCP10-001 — see docs/GROUND-TRUTH.md`.

## (c) Observable proof — FR-051c

Recalling as Session B returns entries whose `session_token` is Session A's,
including `DEMO_SECRET_A`. Evidence `kind=context_leak`; telemetry
`security_event=context_leak`.

## Secure behaviour (SEC-007)

`mcp_servers/secure/tools/memory_recall.py` scopes to `entries_for(caller)`; B
sees only B, no foreign secret. Evidence `context_recall`.

## Manual verification

1. `vulnerable` mode → `GET /api/labs/{id}/sessions` shows User A & B tokens.
2. Recall as Session B → result contains User A's Orion entry + `DEMO_SECRET_A`.
3. Toggle **Secure** → B sees only B.
4. **Reset** → baseline restored, sessions re-seeded, identical evidence on replay.

Automated: `tests/test_mcp10_security.py`, `tests/test_mcp10_integration.py`.

## Reset procedure (RST-001)

`POST /api/labs/{id}/reset` clears runtime state, re-seeds, restores baseline
mode (`vulnerable`), flips the active `memory.recall` version, and re-seeds the
synthetic sessions/contexts.
