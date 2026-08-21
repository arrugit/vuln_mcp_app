# Exploitation Write-up — MCP05 Command Injection & Execution (`VULN-MCP05-001`)

> **Status: implemented (Phase B).** Vulnerable + secure behaviours are live and
> tested. The authoritative entry is consolidated in `docs/GROUND-TRUTH.md`
> (Phase D). Satisfies DECISION D-07 / GT-005.

## Identity

| Field | Value |
|---|---|
| Vulnerability ID | `VULN-MCP05-001` |
| OWASP MCP | MCP05 — Command Injection & Execution |
| Component | `report.export` command construction → sandbox |
| Attack surface | Untrusted input → command construction → sandboxed exec |
| Severity | Critical |
| Baseline mode | `vulnerable` (reset restores this) |

## (a) Exact exploit input — FR-051a

In the MCP05 tab the Exploit input is pre-filled with the literal payload:

```
a.txt; echo PWNED > /work/marker
```

which drives the tool call
`report.export {"filename": "a.txt; echo PWNED > /work/marker"}`.

## (b) Exact enabling code location — FR-051b

`mcp_servers/vulnerable/tools/report_export.py`, in `unsafe_report_export()`:

```python
cmd = "convert " + filename + " out.pdf"   # unsafe concatenation (the sink)
result = sandbox.run_shell(cmd)             # executed through a POSIX shell
```

The unsafe execution primitive is `SandboxRunner.run_shell` in
`sandbox/runner.py`. The file carries the banner
`# INTENTIONALLY VULNERABLE — VULN-MCP05-001 — see docs/GROUND-TRUTH.md`.

## (c) Observable proof — FR-051c

- The sandbox marker file `/work/marker` is created (`marker_present = True`).
- The recorded `constructed_command` shows the injected separator:
  `convert a.txt; echo PWNED > /work/marker out.pdf`.
- Evidence `kind = command_injection`; telemetry tagged
  `security_event = command_injection`.

## Vulnerable behaviour

The shell parses the concatenated string, so `;` splits it into two commands:
the fake `convert a.txt` and the injected `echo PWNED > /work/marker`. The extra
command runs and writes the marker.

## Secure behaviour (SEC-007)

`mcp_servers/secure/tools/report_export.py`:
1. `is_safe_filename()` allow-list (`^[A-Za-z0-9._-]+$`) rejects the payload
   (it contains spaces, `;`, `>`), and
2. execution uses `argv` with `shell=False`, so even a valid filename is passed
   as an inert literal. No marker is created.

## Sandbox containment (SEC-003, D-08)

Execution is a constrained in-process subprocess runner (no Docker): an ephemeral
`tempfile.mkdtemp()` work dir (the `/work` alias), only a fake `convert` shim on
PATH, a hard timeout, and capped output. The marker is written
inside the throwaway dir and deleted when the run ends — nothing persists on the
host. Trade-off vs. the old container sandbox is documented in `sandbox/README.md`.

## Manual verification procedure

1. Ensure MCP05 is `vulnerable` (baseline).
2. Run `report.export {"filename": "a.txt; echo PWNED > /work/marker"}`.
3. Confirm `marker_present = True` and the constructed command shows `; echo PWNED`.
4. Toggle **Secure**, re-run: confirm `rejected = True`, `marker_present = False`.
5. **Reset**: confirm `vulnerable` baseline restored and a re-run reproduces
   identical evidence (modulo ids/timestamps).

Automated: `tests/test_mcp05_security.py`, `tests/test_mcp05_integration.py`.

## Reset procedure (RST-001)

`POST /api/labs/{id}/reset` clears runtime state, re-seeds, restores baseline
mode (`vulnerable`), and flips the active `report.export` version to the unsafe
one.
