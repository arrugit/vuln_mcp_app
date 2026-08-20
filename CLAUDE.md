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
- **MCP03 — Phase A (`phase/mcp03-foundation`): COMPLETE**.
- **MCP03 — Phase B (`phase/mcp03-vulnerability`): COMPLETE**.
- **MCP03 — Phase C (`phase/mcp03-ui-tests`): COMPLETE** — full MCP03 tab +
  integration tests + run-model shift (FastAPI serves the SPA at `/`).
- **MCP03 — Phase D (`phase/mcp03-finalization`): COMPLETE** — ground-truth /
  OWASP-mapping / test-scenarios docs, README + PRD/TDD updated to the
  Docker-free run model, Docker files removed, final verification (13-point).
- **MCP03 STATUS: COMPLETE and LOCKED.** Do not modify MCP03 code in later work.
- Active vulnerability: **none** (MCP05 is next — awaiting owner approval).

## Run model (Docker removed — see Phase D docs)

Build the UI once, then run one command and open the browser:
```
cd frontend && npm install && npm run build
uv run uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```
FastAPI serves `frontend/dist` at `/` when present (SPA), and the API under
`/api`. Backend-only dev (no build) still works; `/` then returns a JSON hint.

## Branch structure & status

| Branch | Purpose | Status |
|---|---|---|
| `main` | integration | created (empty of code until foundation merges) |
| `phase/foundation` | Phase 0 foundation | **complete, committed, pushed** |
| `phase/mcp03-foundation` | MCP03 Phase A | **complete, committed** |
| `phase/mcp03-vulnerability` | MCP03 Phase B | **complete, committed** |
| `phase/mcp03-ui-tests` | MCP03 Phase C | **complete, committed** |
| `phase/mcp03-finalization` | MCP03 Phase D | **complete, committed** |
| `phase/mcp03-ui-tests` | MCP03 Phase C | pending |
| `phase/mcp03-finalization` | MCP03 Phase D | pending |
| (mcp05-*, mcp10-* branches) | later | pending |

## Vulnerability status

- **MCP03:** ✅ COMPLETE & LOCKED (all four phases). Vulnerable + secure modes,
  deterministic leak, evidence + telemetry, reset, full UI, docs, tests.
- **MCP05:** NOT STARTED (scaffold catalog row only). Sandbox will be a
  constrained in-process subprocess runner (Docker removed, D-08).
- **MCP10:** NOT STARTED (scaffold catalog row only).

## MCP03 — final verification (13-point checklist, Phase D)

1. vulnerable mode works — ✅ `leaked_secret=DEMO_SECRET_A`, evidence `metadata_poison`.
2. secure mode prevents it — ✅ no leak, evidence `tool_fetch`.
3. exploit deterministic — ✅ server-side branch; repeatable-after-reset test.
4. reset works — ✅ restores vulnerable baseline + clears evidence.
5. evidence persisted — ✅ `evidence` table + `GET /api/evidence`.
6. telemetry recorded — ✅ tools/list + tools/call + `security_event=secret_leak`.
7. UI demonstrates it — ✅ MCP03 tab: LEARN/CONFIGURE/exploit/evidence/telemetry/verify.
8. exploit procedure documented — ✅ GROUND-TRUTH + labs write-up.
9. enabling code documented — ✅ file + line region (poisoned desc + secret sink).
10. observable proof documented — ✅ `leaked_secret` in result.
11. no oracle introduced — ✅ anti-oracle tests pass.
12. infra not gratuitously vulnerable — ✅ control plane validated, no leak paths.
13. 500+ meaningful lines/branch — ✅ A 751 / B 563 / C 510 / D (docs) satisfied.

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
- **Sandbox** — `sandbox/README.md` (in-process runner contract, D-08),
  `sandbox/runner.py` (idle placeholder; guarded runner added in MCP05).
- **Run/serve** — `backend/app/main.py` mounts `frontend/dist` at `/`;
  `pyproject.toml` drives `uv run`. Docker removed (D-08).
- **Tests** — `tests/` (pytest): foundation + MCP03 (foundation/security/
  integration). `frontend/src/**.test.tsx` (Vitest).
- **Docs/config** — `README.md`, `docs/GROUND-TRUTH.md`,
  `docs/OWASP-MCP-MAPPING.md`, `docs/TEST-SCENARIOS.md`, `.env.example`,
  `.gitignore` (ignores `docs/PRD.md`, `docs/TDD.md`), `pyproject.toml`,
  `pytest.ini`, `CLAUDE.md`.

## Architectural decisions in effect

- Stack per TDD D-02: React/TS + FastAPI + Python MCP SDK + SQLite. **Docker
  removed (D-08):** single `uvicorn` process serves SPA + API; MCP server
  in-process; MCP05 sandbox = constrained subprocess runner.
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
- Sandbox (MCP05, when built): constrained in-process subprocess runner —
  ephemeral temp `/work`, fake `convert` shim, timeout, no shell in secure mode.
- No endpoint reveals vulnerability status.

## Tests (Phase 0)

- **26 backend tests pass** (`.venv/Scripts/python -m pytest`).
- Coverage: health/anti-oracle, lab catalog + mode toggle + reset, telemetry
  capture, evidence record/retrieve, registry loads legit tools + determinism.
- Frontend Vitest test present (`SeverityBadge`); run after `npm install`.

## Commands

```bash
# Build UI once, then run the whole app on one port (open http://127.0.0.1:8000)
cd frontend && npm install && npm run build && cd ..
uv run uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
# Backend tests
uv run pytest              # or: .venv/Scripts/python -m pytest
# Frontend tests
cd frontend && npm test && npx tsc --noEmit
```

## Known issues / notes

- `frontend/dist` is git-ignored: after cloning, run `npm run build` once before
  `uvicorn` will serve the UI at `/` (backend-only dev still works; `/` returns a
  JSON hint).
- MCP SDK (`mcp`) is a dependency but the in-process registry transport is used
  until the streamable-HTTP transport is wired (future).
- MCP05 (when built) will use a constrained subprocess sandbox instead of Docker
  (D-08) — softer OS isolation, mitigated by executing only a fake shim in a
  throwaway dir. Documented in `sandbox/README.md`.

## Next recommended phase

**MCP05 — Phase A (`phase/mcp05-foundation`)**: lab structure for
`report.export`, the constrained subprocess sandbox runner contract, fixtures,
API/registry wiring, evidence/telemetry/reset integration, test + frontend
scaffolding. Do NOT implement the injection in Phase A (that is Phase B).

**STATUS: MCP03 COMPLETE & LOCKED — WAITING FOR OWNER APPROVAL before MCP05.**
