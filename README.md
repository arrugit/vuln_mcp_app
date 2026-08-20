# vuln_mcp_app

An **intentionally vulnerable, locally-runnable Model Context Protocol (MCP)
security laboratory** — a controlled *target* (conceptually a "DVWA for MCP")
used to evaluate a separate FYP security scanner. **This app is the target, not
the scanner.** It hosts a small, documented set of MCP vulnerabilities and
**emits evidence**; it never reports whether it is vulnerable (no oracle,
SEC-006).

> ⚠️ **Educational / research use only.** Everything runs locally with synthetic
> data and dummy secrets (`DEMO_SECRET_*`). No real credentials, no external
> targets, no Internet scanning, no host access. The MCP05 sandbox contains all
> command execution (SEC-001/SEC-003).

## Scope (exactly three labs)

| ID | OWASP MCP | Vulnerability | Status |
|----|-----------|---------------|--------|
| VULN-MCP03-001 | MCP03 | Tool Poisoning | scaffold (foundation) |
| VULN-MCP05-001 | MCP05 | Command Injection & Execution | scaffold (foundation) |
| VULN-MCP10-001 | MCP10 | Context Injection & Over-Sharing | scaffold (foundation) |

No additional vulnerability labs are in scope. Each lab ships a **VULNERABLE**
and a genuinely-fixed **SECURE** mode (implemented in later phases).

## Architecture (TDD §2)

```
Frontend (React/TS/Vite/Tailwind)         Control plane (ordinarily secure)
        │  HTTP/JSON                       ┌───────────────────────────────┐
        ▼                                  │ FastAPI  ·  MCP client         │
  Backend API  ─────────────────────────► │ SQLite   ·  telemetry/evidence │
        │  in-process (Phase 0) / MCP HTTP └───────────────────────────────┘
        ▼
   MCP server (vulnerable | secure)  ──MCP05 only──►  Sandbox (no egress, non-root)
```

The **control plane is ordinarily-secure infrastructure** (SEC-004). Only the
clearly-labelled MCP-plane components become vulnerable, and only in later
phases. Intentionally-vulnerable files carry a banner:
`# INTENTIONALLY VULNERABLE — <VULN-ID> — see docs/GROUND-TRUTH.md`.

## Tech stack (TDD §4)

React + TypeScript + Vite + Tailwind · Python 3.12 + FastAPI + Pydantic v2 ·
official Python MCP SDK · SQLite + SQLModel · Docker Compose · pytest + httpx ·
Vitest + Testing Library.

## Run locally

### Full stack (Docker Compose, DEP-001)

```bash
cp .env.example .env
docker compose up --build
# Frontend: http://127.0.0.1:5173   API: http://127.0.0.1:8000/docs
```

All ports bind to `127.0.0.1` only (DEP-004). The sandbox network is
`internal: true` (no Internet egress, SEC-005).

### Backend only (dev)

```bash
python -m venv .venv && .venv/Scripts/activate      # Windows
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

### Tests

```bash
# Backend (pytest)
.venv/Scripts/python -m pytest

# Frontend (Vitest) — after `npm install` in ./frontend
cd frontend && npm test
```

## API surfaces (analysable by the FYP; TDD §12)

`GET /api/health` · `GET /api/labs` · `GET /api/labs/{id}` ·
`POST /api/labs/{id}/mode|reset|attack|start` · `GET /api/mcp/servers|tools` ·
`GET /api/mcp/tools/{id}` · `POST /api/mcp/tools/{id}/call` ·
`GET /api/vulnerabilities` (catalog metadata only) · `GET /api/evidence`.

**No endpoint discloses a vulnerability verdict** (SEC-006). The
`/api/vulnerabilities` route returns descriptive catalog metadata only — never
"is exploitable".

## FYP evaluation loop (TDD §34)

1. Start the target (VULNERABLE mode). 2. Confirm labs active via manual
   verification. 3. Run the FYP against the HTTP + MCP surfaces. 4. Compare
   findings to `docs/GROUND-TRUTH.md`. 5. Switch SECURE and re-run to measure
   false positives. 6. Reset and repeat.

## Project docs

- `docs/GROUND-TRUTH.md`, `docs/OWASP-MCP-MAPPING.md`, `docs/TEST-SCENARIOS.md`
  — authored per lab in later phases (the answer key; never a runtime API).
- `CLAUDE.md` — implementation memory / current phase state.
- `docs/PRD.md`, `docs/TDD.md` — design contracts, kept **local only** (git-ignored).

## Current state

**Phase 0 (foundation) complete** — ordinarily-secure control plane, MCP
client/registry with legit tools only, three-tab UI scaffold, Docker topology,
and a passing test suite. No vulnerability behaviour is implemented yet. See
`CLAUDE.md` for the phase plan.
