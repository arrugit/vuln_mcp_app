# CLAUDE.md — Implementation Memory (vuln_mcp_app)

> This is the **implementation state document** for future sessions. It is NOT
> the PRD/TDD (those are design contracts, kept local-only and git-ignored).
> Update this after each completed phase/vulnerability.

## Project purpose

`vuln_mcp_app` is an **intentionally vulnerable, local MCP security lab** — a
controlled *target* ("DVWA for MCP") for evaluating a separate FYP scanner. It
hosts exactly **three** planted vulnerabilities and **emits evidence**; it never
reveals a vulnerability verdict (no oracle, SEC-006). Everything is local,
synthetic, sandboxed, deterministic, and resettable.

## Scope (fixed — do not expand)

Implement in this exact order, one at a time, gated by owner approval:
1. **VULN-MCP03-001** — MCP03 Tool Poisoning (`docs.fetch`)
2. **VULN-MCP05-001** — MCP05 Command Injection & Execution (`report.export`)
3. **VULN-MCP10-001** — MCP10 Context Injection & Over-Sharing (`memory.recall`)

Do NOT start a vulnerability until the previous one is fully complete AND the
owner explicitly approves. Once a vulnerability is complete, **lock it** — later
phases must not modify already-finished code.

## Current implementation phase

- **PHASE 0 — Foundation: COMPLETE** (committed + pushed to origin).
- **MCP03 — Phase A (`phase/mcp03-foundation`): COMPLETE** (clean/trusted
  `docs.fetch` wired end-to-end; NO poisoning yet — that is Phase B).
- Active vulnerability: **MCP03** (Phase B is next, awaiting owner approval).

## Branch structure & status

| Branch | Purpose | Status |
|---|---|---|
| `main` | integration | created (empty of code until foundation merges) |
| `phase/foundation` | Phase 0 foundation | **complete, committed, pushed** |
| `phase/mcp03-foundation` | MCP03 Phase A | **complete, committed** |
| `phase/mcp03-vulnerability` | MCP03 Phase B | next (awaiting approval) |
| `phase/mcp03-ui-tests` | MCP03 Phase C | pending |
| `phase/mcp03-finalization` | MCP03 Phase D | pending |
| (mcp05-*, mcp10-* branches) | later | pending |

## Vulnerability status

- **MCP03:** Phase A COMPLETE (clean/trusted `docs.fetch` end-to-end; no poison).
  Phase B (poisoning + secure control) not started.
- **MCP05:** NOT STARTED (scaffold catalog row only).
- **MCP10:** NOT STARTED (scaffold catalog row only).

## MCP03 — Phase A implementation (clean, no vulnerability)

- `labs/mcp03_tool_poisoning/fixtures.py` — synthetic docs corpus (incl.
  `welcome`) + `DEMO_SECRET_A` (kept OUTSIDE the corpus; nothing reads it yet).
- `mcp_servers/secure/tools/docs_fetch.py` — clean `docs.fetch` (factual
  description, no secret branch) + `CLEAN_DOCS_FETCH_DEFINITION` (single source
  of truth) + `register_docs_fetch()`.
- `mcp_servers/{secure,vulnerable}/__init__.py` — both register the CLEAN
  docs.fetch in Phase A (identical registries; poisoning arrives in Phase B and
  only touches the vulnerable builder).
- `backend/app/db/seed.py` — seeds `docs.fetch` DB catalog row + a single
  `trusted` `tool_version` (`is_active=True`).
- `backend/app/services/labs/{__init__.py,mcp03_service.py}` — slug dispatcher +
  MCP03 orchestrator (runs `docs.fetch {"doc_id":"welcome"}`, records telemetry +
  evidence; classifies `tool_fetch` vs future `metadata_poison` by secret
  presence — no oracle).
- `backend/app/api/routes_labs.py` — `/attack` now dispatches to the orchestrator.
- Frontend: `components/ExploitRunner.tsx` + MCP03 wiring in
  `screens/VulnerabilityModule.tsx` (pre-filled `doc_id="welcome"`,
  enabling-code pointer).
- `labs/mcp03_tool_poisoning/write-up.md` — D-07 write-up scaffold.

**Phase B TODO (do NOT do in Phase A):** add
`mcp_servers/vulnerable/tools/docs_fetch.py` (poisoned metadata + secret branch,
with the `# INTENTIONALLY VULNERABLE — VULN-MCP03-001` banner); point
`build_vulnerable_registry` at it; add the `poisoned` `tool_version` + mode-driven
`is_active` flip; security/secure-mode/determinism tests.

## Foundation — implemented files (Phase 0)

Ordinarily-secure infrastructure only; **no vulnerability behaviour**.

- **Backend (FastAPI control plane)** — `backend/app/`
  - `config/settings.py` — env-driven settings, safe defaults.
  - `models/entities.py` — SQLModel schema (TDD §9). No "is_present" field.
  - `db/database.py`, `db/seed.py`, `db/reset.py` — engine, baseline seed, reset.
  - `services/` — `telemetry_service`, `evidence_service`, `lab_service`,
    `mcp_service`.
  - `mcp_client/client.py` — transport-agnostic MCP client (in-process in P0);
    records telemetry.
  - `api/` — routers: health, labs, mcp, evidence, vulnerabilities. No oracle.
  - `main.py` — app assembly (lifespan seed, CORS to local frontend).
- **MCP plane** — `mcp_servers/`
  - `common/registry.py`, `common/tools_legit.py` — registry + always-safe
    `notes.search` / `notes.summarize`.
  - `vulnerable/`, `secure/` — physically separate trees; **baseline-safe only**
    in P0 (`build_vulnerable_registry` / `build_secure_registry`).
  - `serve.py` — Phase 0 stdlib server entrypoint (health + tools/list).
- **Frontend (React/TS/Vite/Tailwind)** — `frontend/src/`
  - `components/` — `AppShell`, `TopBar`, `ModuleTabs` (three-tab bar),
    `SeverityBadge`, `StatusBadge`.
  - `screens/` — `Dashboard`, `VulnerabilityModule` (scaffold; exploit runner
    added per lab in Phase C).
  - `lib/api.ts`, `lib/types.ts`.
- **Sandbox** — `sandbox/README.md` (runner contract), `sandbox/runner.py`
  (idle placeholder; guarded runner added in MCP05).
- **Docker** — `docker-compose.yml`, `docker/*.Dockerfile` (frontend, backend,
  mcp-server, sandbox). `sandbox-net` is `internal: true`.
- **Tests** — `tests/` (pytest): health, labs, reset, telemetry, evidence,
  registry, anti-oracle. `frontend/src/**.test.tsx` (Vitest): SeverityBadge.
- **Docs/config** — `README.md`, `.env.example`, `.gitignore` (ignores
  `docs/PRD.md`, `docs/TDD.md`), `pytest.ini`, `CLAUDE.md`.

## Architectural decisions in effect

- Stack per TDD D-02: React/TS + FastAPI + Python MCP SDK + SQLite + Docker.
- **D-03 transport:** streamable HTTP is the production target; Phase 0 uses an
  in-process registry transport so the control plane is testable without a
  running container. The client API (`list_tools`/`call_tool`) is
  transport-agnostic so swapping to the SDK later does not ripple.
- **D-04:** `mcp_servers/vulnerable/` and `/secure/` are physically separate;
  every vulnerable file will carry the `# INTENTIONALLY VULNERABLE — <ID>` banner.
- **D-05:** `/api/health` mode field gated by `EXPOSE_HEALTH_MODE`.
- **SEC-006 (anti-oracle):** enforced by `tests/test_foundation_anti_oracle.py`.
- Baseline mode of every lab is `secure` + `status="pending"` in P0 (mode is
  inert with no vuln code). Each lab's Phase B sets its documented baseline.

## Security boundaries (foundation)

- Control plane: validated inputs, CORS to local frontend, localhost bind.
- MCP plane: only always-safe legit tools registered in P0.
- Sandbox: isolated container, `internal` network, non-root, read-only, tmpfs
  `/work`, `cap_drop: ALL` — no execution surface yet.
- No endpoint reveals vulnerability status.

## Tests (Phase 0)

- **26 backend tests pass** (`.venv/Scripts/python -m pytest`).
- Coverage: health/anti-oracle, lab catalog + mode toggle + reset, telemetry
  capture, evidence record/retrieve, registry loads legit tools + determinism.
- Frontend Vitest test present (`SeverityBadge`); run after `npm install`.

## Commands

```bash
# Backend tests
.venv/Scripts/python -m pytest
# Run backend (dev)
uvicorn backend.app.main:app --reload
# Full stack
cp .env.example .env && docker compose up --build
# Frontend tests
cd frontend && npm install && npm test
```

## Known issues / notes

- Frontend deps not installed in this environment yet (`npm install` needed to
  run Vitest / dev server). Docker images not built here (compose config
  validated only).
- MCP SDK (`mcp`) is listed in `backend/requirements.txt` but not used until the
  streamable-HTTP transport is wired in a later phase.

## Next recommended phase

**MCP03 — Phase B (`phase/mcp03-vulnerability`)**: implement the intentionally
poisoned `docs.fetch` (vulnerable tree) + keep the genuinely-secure counterpart,
exact deterministic trigger, evidence/telemetry/reset, and security +
secure-mode + determinism tests. Both modes manually verified.

**STATUS: MCP03 Phase A complete — WAITING FOR OWNER APPROVAL before Phase B.**
