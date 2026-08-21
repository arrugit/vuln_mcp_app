# TEST-SCENARIOS.md — `vuln_mcp_app`

FYP-validation scenarios per vulnerability (TST-006). Each scenario names its
objective, target configuration, trigger, expected vulnerable behaviour and
evidence, expected OWASP class/severity, expected detection, secure-mode
behaviour, and reset. Automated equivalents live under `tests/`.

---

## Scenario S-MCP03 — Tool Poisoning (`VULN-MCP03-001`) — IMPLEMENTED

| Field | Value |
|---|---|
| **Objective** | Detect a poisoned MCP tool (metadata instruction + secret leak) |
| **Preconditions** | App running; MCP03 lab present |
| **Target config** | MCP03 mode = `vulnerable` (baseline) |
| **Trigger** | `docs.fetch {"doc_id":"welcome"}` (MCP03 tab Exploit/Run) |
| **Expected vulnerable behaviour** | Result includes `leaked_secret = DEMO_SECRET_A` |
| **Expected evidence** | `metadata_poison` evidence; telemetry `security_event=secret_leak`; poisoned description visible in `tools/list` and in the stored `poisoned` version |
| **Expected OWASP class** | MCP03 |
| **Expected severity** | High |
| **Expected detection result** | Detected (static metadata signal AND behavioural leak) |
| **Secure-mode behaviour** | mode = `secure` → no `leaked_secret`; evidence `tool_fetch`; clean metadata; FYP should report nothing (false-positive check) |
| **Reset** | `POST /api/labs/{id}/reset` → baseline `vulnerable`, evidence cleared, re-run reproduces identical evidence |

**Automated coverage:**
- `tests/test_mcp03_security.py::test_mcp03_tool_poisoning`
- `tests/test_mcp03_security.py::test_mcp03_secure_blocks_poison`
- `tests/test_mcp03_security.py::test_mcp03_repeatable_evidence_after_reset`
- `tests/test_mcp03_integration.py::*`
- `tests/test_foundation_anti_oracle.py::*` (SEC-006)

**Manual steps:** see `docs/GROUND-TRUTH.md` → VULN-MCP03-001 → Manual
verification procedure.

---

## Scenario S-MCP05 — Command Injection (`VULN-MCP05-001`) — IMPLEMENTED

| Field | Value |
|---|---|
| **Objective** | Detect command injection from an MCP tool argument to an exec sink |
| **Target config** | MCP05 mode = `vulnerable` (baseline) |
| **Trigger** | `report.export {"filename":"a.txt; echo PWNED > /work/marker"}` |
| **Expected vulnerable behaviour** | `marker_present = true`; constructed command shows the injected `; echo PWNED` |
| **Expected evidence** | `command_injection` evidence; telemetry `security_event=command_injection`; the two `report.export` versions diff-able |
| **Expected OWASP class / severity** | MCP05 / Critical |
| **Expected detection result** | Detected (dataflow: untrusted arg → shell string → exec) |
| **Secure-mode behaviour** | mode = `secure` → filename rejected by allow-list + argv exec; `marker_present=false`; evidence `command_exec`; FYP should report nothing |
| **Reset** | `POST /api/labs/{id}/reset` → baseline `vulnerable`, evidence cleared, re-run reproduces identical evidence |

**Automated coverage:**
- `tests/test_mcp05_security.py::test_mcp05_command_injection`
- `tests/test_mcp05_security.py::test_mcp05_secure_blocks_injection`
- `tests/test_mcp05_security.py::test_mcp05_repeatable_evidence_after_reset`
- `tests/test_mcp05_security.py::test_sandbox_timeout_kills_long_command`
- `tests/test_mcp05_security.py::test_marker_is_confined_to_ephemeral_sandbox_dir`
- `tests/test_mcp05_integration.py::*`

**Manual steps:** see `docs/GROUND-TRUTH.md` → VULN-MCP05-001 → Manual
verification procedure.

---

## Scenario S-MCP10 — Context Over-Sharing (`VULN-MCP10-001`) — IMPLEMENTED

| Field | Value |
|---|---|
| **Objective** | Detect cross-session context leakage (missing ownership check) |
| **Target config** | MCP10 mode = `vulnerable` (baseline) |
| **Trigger** | Session B: `memory.recall {"session_token":"sess-bob-b2b2b2","query":"…"}` |
| **Expected vulnerable behaviour** | result contains Session A's Orion entry + `DEMO_SECRET_A` (foreign `session_token`) |
| **Expected evidence** | `context_leak` evidence (foreign_entries listed); telemetry `security_event=context_leak`; two `memory.recall` versions diff-able |
| **Expected OWASP class / severity** | MCP10 / High |
| **Expected detection result** | Detected (authorization/behavioural: foreign-session data in the result) |
| **Secure-mode behaviour** | mode = `secure` → session-scoped; B sees only B; evidence `context_recall`; FYP should report nothing |
| **Reset** | `POST /api/labs/{id}/reset` → baseline `vulnerable`, evidence cleared, identical evidence on replay |

**Automated coverage:** `tests/test_mcp10_security.py`,
`tests/test_mcp10_integration.py`, `tests/test_ground_truth_verification.py`.

**Manual steps:** see `docs/GROUND-TRUTH.md` → VULN-MCP10-001.

---

## Anti-oracle scenario (SEC-006)

**Objective:** confirm no endpoint reveals a vulnerability verdict. **Expected:**
`/api/vulnerabilities` returns catalog metadata only; no `is-vulnerable`,
`scan-result`, or `vulnerability-status` route exists; no response field states
exploitability. **Automated:** `tests/test_foundation_anti_oracle.py`.
