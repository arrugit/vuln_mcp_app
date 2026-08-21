# Exploitation Write-up — MCP03 Tool Poisoning (`VULN-MCP03-001`)

> **Status: implemented (reworked 2026-08-21 to a realistic, accidental bug).**
> Authoritative entry in `docs/GROUND-TRUTH.md`. Satisfies D-07 / GT-005.

## Identity

| Field | Value |
|---|---|
| Vulnerability ID | `VULN-MCP03-001` |
| OWASP MCP | MCP03 — Tool Poisoning (context/output poisoning) |
| Component | `docs.fetch` template render context |
| Attack surface | Untrusted document content rendered with too much in scope |
| Severity | High · Baseline mode `vulnerable` |

## The realistic bug

The docs service lets help articles use `{{ config.<key> }}` placeholders. The
vulnerable `docs.fetch` handler exposes the **whole** app config — which also
holds a credential (`api_key = DEMO_SECRET_A`) — to the renderer:

```python
# mcp_servers/vulnerable/tools/docs_fetch.py -> docs_fetch()
render_context = {"config": APP_CONFIG}          # over-broad context (the flaw)
body = render(doc.body, render_context)
```

So any article containing `{{ config.api_key }}` renders the credential into the
returned text. There is **no** "leak this secret" line — the mistake is that the
render scope is too wide, a common accidental information-disclosure / SSTI bug.

## (a) Exact exploit input — FR-051a

```
docs.fetch {"doc_id": "onboarding-notes"}      # seeded internal doc with the placeholder
```

or, using the untrusted-content entry point (the tab's "Add your own document" /
`POST /api/labs/{id}/docs`):

```
add doc { "doc_id":"mine", "body":"key: {{ config.api_key }}" }
docs.fetch {"doc_id": "mine"}
```

## (b) Exact enabling code location — FR-051b

`mcp_servers/vulnerable/tools/docs_fetch.py`, function `docs_fetch()`:
`render_context = {"config": APP_CONFIG}`. The neutral renderer is
`labs/mcp03_tool_poisoning/templating.py`; the credential lives in
`labs/mcp03_tool_poisoning/fixtures.py::APP_CONFIG["api_key"]`.

## (c) Observable proof — FR-051c

The returned `body` contains `DEMO_SECRET_A`. Evidence `kind=metadata_poison`;
telemetry `security_event=secret_leak`. Public docs (welcome/faq) never leak.

## Secure behaviour (SEC-007)

`mcp_servers/secure/tools/docs_fetch.py` builds the context from
`PUBLIC_CONFIG_KEYS` only (no `api_key`), so `{{ config.api_key }}` is left
literal and inert.

## Optional Ollama demo

`POST /api/labs/{id}/llm` sends a document to a local model. Vulnerable = raw
concat of untrusted body into the prompt (indirect prompt injection; the seeded
`product-review` doc tries to make the model emit `INJECTED-OK`); secure = guarded
prompt. Optional, non-deterministic, gated by `ENABLE_LOCAL_LLM`.

## Manual verification

1. `vulnerable` mode → fetch `onboarding-notes` → secret in body.
2. Add your own doc with `{{ config.api_key }}` → fetch → secret in body.
3. Toggle **Secure** → placeholder stays literal, no secret.
4. **Reset** → baseline restored, user docs dropped, identical evidence on replay.

Automated: `tests/test_mcp03_security.py`, `tests/test_mcp03_integration.py`,
`tests/test_mcp03_ollama.py`.
