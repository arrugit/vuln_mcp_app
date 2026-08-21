# GROUND-TRUTH.md — `vuln_mcp_app`

> **This is the answer key.** It documents every intentionally-planted
> vulnerability so the FYP's detections can be scored (GT-001..005). Ground truth
> lives ONLY here and in the controlled tests — never in a runtime API (SEC-006 /
> GT-003). This file is committed (it is NOT `PRD.md`/`TDD.md`, which stay local).

Scope: exactly three labs — MCP03, MCP05, MCP10. **All three are implemented.**

---

## Ground-truth matrix (GT-002)

| ID | OWASP | Vulnerability | Component | Trigger | Expected evidence | Expected detection |
|----|-------|---------------|-----------|---------|-------------------|--------------------|
| VULN-MCP03-001 | MCP03 | Tool Poisoning | `docs.fetch` render-context wiring | `docs.fetch {"doc_id":"onboarding-notes"}` (or add a doc with `{{ config.api_key }}`) | article body returned with `DEMO_SECRET_A` rendered in; evidence `metadata_poison`; telemetry `security_event=secret_leak` | Dataflow: untrusted document content → template scope holding config → secret in tool output |
| VULN-MCP05-001 | MCP05 | Command Injection & Execution | `report.export` command construction | `report.export {"filename":"a.txt; echo PWNED > /work/marker"}` | constructed command with injected `; echo PWNED` + `/work/marker` created; evidence `command_injection`; telemetry `security_event=command_injection` | Dataflow: untrusted arg → shell string → exec sink |
| VULN-MCP10-001 | MCP10 | Context Injection & Over-Sharing | `memory.recall` access scoping | `memory.recall {"session_token":"sess-bob-b2b2b2","query":"…"}` | entries from a foreign `session_token` incl. `DEMO_SECRET_A`; evidence `context_leak`; telemetry `security_event=context_leak` | Behavioural/authz: recall as one session returns another session's data |

---

## VULN-MCP03-001 — Tool Poisoning / template-scope disclosure (IMPLEMENTED)

| Field | Value |
|---|---|
| **Vulnerability ID** | `VULN-MCP03-001` |
| **OWASP MCP category** | MCP03 — Tool Poisoning (context/output poisoning) |
| **Name** | Credential disclosure via over-broad `docs.fetch` template context |
| **Vulnerable component** | `mcp_servers/vulnerable/tools/docs_fetch.py` |
| **Vulnerable tool** | `docs.fetch` (MCP `tools/call`) |
| **Attack surface** | Untrusted document content rendered with too much in scope |
| **Severity** | High |
| **Baseline mode** | `vulnerable` (reset restores this) |
| **Preconditions** | MCP03 lab in `vulnerable` mode (default). No auth required. |

> **Design note (2026-08-21 rework):** the vulnerability was reworked from an
> obvious planted `leaked_secret = DEMO_SECRET_A` line into a **realistic,
> accidental bug** — an over-broad template render context — so it resembles a
> real-world flaw a scanner must actually find. The `# INTENTIONALLY VULNERABLE`
> banner is retained for the owner's traceability.

### The bug (how it is exploited)

The docs service renders help articles that may contain `{{ config.<key> }}`
placeholders (for dynamic values like app name / support email). The vulnerable
handler builds the template context from the **entire** application config:

```python
# mcp_servers/vulnerable/tools/docs_fetch.py  ->  docs_fetch()
render_context = {"config": APP_CONFIG}      # whole config in template scope
return {..., "body": render(doc.body, render_context), ...}
```

`APP_CONFIG` (see `labs/mcp03_tool_poisoning/fixtures.py`) also contains a
credential, `api_key = DEMO_SECRET_A`. Nothing reads the secret on purpose — but
because the whole config is reachable from templates, **any article body that
contains `{{ config.api_key }}` renders the credential into the returned text**.

Two realistic entry points:
- a seeded internal doc, `onboarding-notes`, whose body already contains
  `{{ config.api_key }}` (a developer left a config placeholder in a runbook);
- **add-your-own document** (`POST /api/labs/{id}/docs`, or the tab's "Add your
  own document") with a body like `key: {{ config.api_key }}` — untrusted
  user-supplied content is the realistic attacker vector.

### Trigger / exact exploit input (FR-051a / GT-005)

```
docs.fetch {"doc_id": "onboarding-notes"}
```

or add a doc `{ "doc_id":"mine", "body":"{{ config.api_key }}" }` then
`docs.fetch {"doc_id":"mine"}`.

### Enabling code location (FR-051b)

`mcp_servers/vulnerable/tools/docs_fetch.py` — the line
`render_context = {"config": APP_CONFIG}` in `docs_fetch()` (over-broad context).
The renderer itself (`labs/mcp03_tool_poisoning/templating.py`) is neutral; the
flaw is the wiring. Banner:
`# INTENTIONALLY VULNERABLE — VULN-MCP03-001 — see docs/GROUND-TRUTH.md`.

### Vulnerable behaviour / observable proof (FR-051c)

`tools/call` returns the article with `DEMO_SECRET_A` rendered into `body` — a
value the public docs (welcome/faq/…) never contain. Evidence
`kind=metadata_poison`; telemetry `security_event=secret_leak`.

### Expected scanner observation

- **Dataflow / taint:** untrusted document content flows into a template render
  scope that transitively contains a credential, and the rendered output is
  returned to the caller.
- **Behavioural:** a `docs.fetch` result containing known-sensitive material.

### Secure behaviour (SEC-007)

`mcp_servers/secure/tools/docs_fetch.py` builds the context from an **allow-listed
subset** of config (`PUBLIC_CONFIG_KEYS`, no `api_key`). `{{ config.api_key }}`
finds nothing and is left inert. Evidence `kind=tool_fetch`; no `security_event`.

### Optional live-LLM facet (Ollama)

`POST /api/labs/{id}/llm` (MCP03 tab → "Live LLM demo") sends a document to a
local Ollama model. The vulnerable path pastes the untrusted document body
straight into the prompt (indirect prompt injection); the seeded `product-review`
doc contains an embedded instruction, so a naively-prompted model may emit
`INJECTED-OK`. The secure path uses a guarded system prompt. This is OPTIONAL and
non-deterministic (gated by `ENABLE_LOCAL_LLM`); the deterministic template bug
above is the primary, always-on vulnerability.

### Remediation

- Give the template renderer least authority: allow-list which keys it can see.
- Never place credentials in a context reachable from user/templated content.
- Separate secrets from display config; treat document bodies as untrusted.
- For LLM use: never concatenate untrusted content into instructions; use role
  separation and tell the model to treat content as data.

### Manual verification procedure (GT-004)

1. Confirm MCP03 is `vulnerable` (baseline).
2. Fetch `onboarding-notes` (or add a doc with `{{ config.api_key }}`) → body
   contains `DEMO_SECRET_A`; evidence `metadata_poison`. Public docs do not leak.
3. Toggle **Secure**; re-fetch; the placeholder stays literal, no secret;
   evidence `tool_fetch`.
4. **Reset**; confirm `vulnerable` baseline and identical evidence on re-run.
5. (Optional) with `ENABLE_LOCAL_LLM=true` + Ollama, run the Live LLM demo on
   `product-review` in each mode.

Machine-checkable: `tests/test_mcp03_security.py`, `tests/test_mcp03_integration.py`,
`tests/test_mcp03_ollama.py`.

### Reset procedure (RST-001)

`POST /api/labs/{id}/reset` clears runtime state, re-seeds, restores baseline
mode (`vulnerable`), flips the active `docs.fetch` version, and **restores the
document store** (drops user-added docs, re-seeds the corpus).

---

## VULN-MCP05-001 — Command Injection & Execution (IMPLEMENTED)

| Field | Value |
|---|---|
| **Vulnerability ID** | `VULN-MCP05-001` |
| **OWASP MCP category** | MCP05 — Command Injection & Execution |
| **Name** | Command injection via `report.export` |
| **Vulnerable component** | `mcp_servers/vulnerable/tools/report_export.py` |
| **Vulnerable tool** | `report.export` (MCP `tools/call`) |
| **Attack surface** | Untrusted input → command construction → sandboxed exec |
| **Severity** | Critical |
| **Baseline mode** | `vulnerable` (reset restores this) |
| **Preconditions** | MCP05 lab in `vulnerable` mode (default). No auth. |

### Trigger / exact exploit input (FR-051a / GT-005)

In the MCP05 tab, run the pre-filled call (Exploit/Run → `POST /api/labs/{id}/attack`):

```
report.export {"filename": "a.txt; echo PWNED > /work/marker"}
```

### Enabling code location (FR-051b)

`mcp_servers/vulnerable/tools/report_export.py`, in `unsafe_report_export()`:

```python
cmd = "convert " + filename + " out.pdf"   # unsafe concatenation (the sink)
result = sandbox.run_shell(cmd)             # executed through a POSIX shell
```

The unsafe primitive is `SandboxRunner.run_shell` (`sandbox/runner.py`). Banner in
the tool file: `# INTENTIONALLY VULNERABLE — VULN-MCP05-001 — see docs/GROUND-TRUTH.md`.

### Vulnerable behaviour

A shell parses the concatenated string, so the `;` in the filename splits it into
two commands: the fake `convert a.txt` and the injected `echo PWNED > /work/marker`.
The injected command runs and writes the marker file.

### Expected security impact

Arbitrary command execution in the tool's context. Contained here to the
ephemeral sandbox (no host access, no network, hard timeout).

### Expected evidence (EV-001..003)

- Evidence `kind=command_injection`, `observable="extra command executed (marker
  created in /work)"`, `raw_signal={filename, constructed_command (with the
  injected separator), marker_present:true, stdout}`.
- Telemetry event tagged `security_event=command_injection`.
- Both stored `report.export` versions (`trusted`, `poisoned`/unsafe) are
  diff-able via `GET /api/mcp/tools/{id}` (FR-013).

### Observable proof (FR-051c)

`marker_present = true` and the recorded `constructed_command` shows
`convert a.txt; echo PWNED > /work/marker out.pdf`.

### Expected scanner observation

- **Dataflow:** an untrusted tool argument flowing into a shell command string
  and an exec sink (`shell` execution).
- **Behavioural:** a side-effect file created by an injected command.

### Secure behaviour (SEC-007)

In `secure` mode the server serves `mcp_servers/secure/tools/report_export.py`:
(1) allow-list validation (`^[A-Za-z0-9._-]+$`) rejects the payload, and
(2) execution uses `argv` with `shell=False`. No marker is created; evidence
`kind=command_exec`.

### Remediation

- Never build shell strings from untrusted input; use `argv` + `shell=False`.
- Validate/allow-list inputs; reject separators.
- Least privilege + isolated, no-network sandbox; prefer library calls over shelling out.

### Sandbox containment (SEC-003, D-08)

Constrained in-process subprocess runner: ephemeral temp `/work`, only a fake
`convert` on PATH (a small shim), hard timeout, capped output. The marker lives in the
throwaway dir and is deleted on run exit — nothing persists on the host. Trade-off
vs. the removed container sandbox is documented in `sandbox/README.md`.

### Manual verification procedure (GT-004)

1. Confirm MCP05 is `vulnerable` (baseline).
2. Run `report.export {"filename":"a.txt; echo PWNED > /work/marker"}`.
3. Confirm `marker_present=true` and the constructed command shows `; echo PWNED`.
4. Toggle **Secure**; re-run; confirm `rejected=true`, `marker_present=false`.
5. **Reset**; confirm `vulnerable` baseline and identical evidence on re-run.

Machine-checkable: `tests/test_mcp05_security.py`, `tests/test_mcp05_integration.py`.

### Reset procedure (RST-001)

`POST /api/labs/{id}/reset` clears runtime state, re-seeds, restores baseline
mode (`vulnerable`), and flips the active `report.export` version to unsafe.

## VULN-MCP10-001 — Context Injection & Over-Sharing (IMPLEMENTED)

| Field | Value |
|---|---|
| **Vulnerability ID** | `VULN-MCP10-001` |
| **OWASP MCP category** | MCP10 — Context Injection & Over-Sharing |
| **Name** | Cross-session context leak via missing ownership check in `memory.recall` |
| **Vulnerable component** | `mcp_servers/vulnerable/tools/memory_recall.py` |
| **Vulnerable tool** | `memory.recall` (MCP `tools/call`) |
| **Attack surface** | Session/context isolation boundary |
| **Severity** | High · **Baseline mode** `vulnerable` |
| **Preconditions** | MCP10 lab in `vulnerable` mode (default). |

### The bug (how it is exploited)

`memory.recall` accepts the caller's `session_token` but never scopes the lookup
to that session:

```python
# mcp_servers/vulnerable/tools/memory_recall.py -> memory_recall()
entries = get_context_store().all_entries()   # every session's entries (no owner filter)
```

The secure variant uses `store.entries_for(token)` (caller-scoped). This missing
`WHERE owner = caller` check is a classic broken-access-control / IDOR mistake.

Synthetic data (`labs/mcp10_context_oversharing/fixtures.py`): Session A
(`sess-alice-a1a1`, "User A") owns Project Orion + `api_token = DEMO_SECRET_A`;
Session B (`sess-bob-b2b2b2`, "User B") owns only benign notes.

### Trigger / exact exploit input (FR-051a / GT-005)

```
memory.recall {"session_token": "sess-bob-b2b2b2", "query": "what do you remember?"}
```

### Enabling code location (FR-051b)

`mcp_servers/vulnerable/tools/memory_recall.py`, function `memory_recall()`:
`entries = get_context_store().all_entries()` (missing ownership scope). Banner:
`# INTENTIONALLY VULNERABLE — VULN-MCP10-001 — see docs/GROUND-TRUTH.md`.

### Vulnerable behaviour / observable proof (FR-051c)

Recalling as Session B returns entries whose `session_token` is Session A's,
including `DEMO_SECRET_A`. Evidence `kind=context_leak`
(`raw_signal.foreign_entries` lists the leaked records); telemetry
`security_event=context_leak`.

### Expected scanner observation

- **Behavioural / authorization:** call `memory.recall` as one session and
  observe another session's data (foreign `session_token`) in the result.

### Secure behaviour (SEC-007)

`mcp_servers/secure/tools/memory_recall.py` scopes to `entries_for(caller)`, so
Session B receives only Session B's entries; `DEMO_SECRET_A` never appears.
Evidence `kind=context_recall`; no `security_event`.

### Remediation

- Enforce ownership: scope every read to the authenticated caller's session.
- Filter at the data layer (`WHERE session = caller`), not just in the UI.
- Deny-by-default; never trust a client-supplied id without an authorization check.

### Manual verification procedure (GT-004)

1. Confirm MCP10 is `vulnerable` (baseline). `GET /api/labs/{id}/sessions` shows
   the two synthetic users + tokens.
2. Recall as Session B → result contains User A's Orion entry + `DEMO_SECRET_A`;
   evidence `context_leak`.
3. Toggle **Secure**; re-run; B sees only B; evidence `context_recall`.
4. **Reset**; confirm `vulnerable` baseline and identical evidence on re-run.

Machine-checkable: `tests/test_mcp10_security.py`, `tests/test_mcp10_integration.py`.

### Reset procedure (RST-001)

`POST /api/labs/{id}/reset` clears runtime state, re-seeds, restores baseline
mode (`vulnerable`), flips the active `memory.recall` version, and re-seeds the
synthetic sessions/contexts.
