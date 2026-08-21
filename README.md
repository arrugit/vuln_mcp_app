# vuln_mcp_app

An **intentionally vulnerable, locally-runnable Model Context Protocol (MCP)
security laboratory** — a controlled *target* (conceptually a "DVWA for MCP")
used to evaluate a separate FYP security scanner. **This app is the target, not
the scanner.** It hosts a small, documented set of MCP vulnerabilities and
**emits evidence**; it never reports whether it is vulnerable (no oracle,
SEC-006).

> ⚠️ **Educational / research use only.** Everything runs locally with synthetic
> data and dummy secrets (`DEMO_SECRET_*`). No real credentials, no external
> targets, no Internet scanning, no host access.

## Scope (exactly three labs)

| ID | OWASP MCP | Vulnerability | Status |
|----|-----------|---------------|--------|
| VULN-MCP03-001 | MCP03 | Tool Poisoning | **implemented** |
| VULN-MCP05-001 | MCP05 | Command Injection & Execution | **implemented** |
| VULN-MCP10-001 | MCP10 | Context Injection & Over-Sharing | **implemented** |

No additional vulnerability labs are in scope. Each implemented lab ships a
**VULNERABLE** and a genuinely-fixed **SECURE** mode.

## Run it (no Docker — one command + a browser)

The whole app runs from a single `uvicorn` process: FastAPI serves the built UI
at `/` and the API under `/api`.

### First time

```bash
# 1) Build the UI once (Node 18+). Produces frontend/dist.
cd frontend && npm install && npm run build && cd ..

# 2) Run the app (uv resolves Python deps automatically; Python 3.12+).
uv run uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open **http://127.0.0.1:8000** — the lab UI appears. Interactive API docs
are at **http://127.0.0.1:8000/docs**.

> Prefer a classic venv instead of `uv`?
> ```bash
> python -m venv .venv && source .venv/Scripts/activate   # Windows Git Bash
> pip install -r backend/requirements.txt
> uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
> ```

### After the first build

Just run the `uvicorn` command and open the browser. Rebuild the UI
(`npm run build`) only after changing frontend code.

### Frontend hot-reload (optional, for UI development)

Run the API on `:8000` and the Vite dev server on `:5173` (it proxies `/api`):

```bash
# terminal 1
uv run uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
# terminal 2
cd frontend && npm run dev      # open http://127.0.0.1:5173
```

## Tests

```bash
# Backend (pytest)
uv run pytest                    # or: .venv/Scripts/python -m pytest

# Frontend (Vitest + tsc)
cd frontend && npm test && npx tsc --noEmit
```

## Architecture

```
Browser (React SPA, served by FastAPI at :8000)
        │  HTTP/JSON  (/api)
        ▼
  FastAPI control plane (ordinarily secure)  ── MCP client ──►  MCP tool registry
        │                                                        (vulnerable | secure)
        ▼                                                              │
   SQLite (labs, tools, telemetry, evidence)  ◄── telemetry/evidence ─┘
```

The **control plane is ordinarily-secure infrastructure** (SEC-004). Only the
clearly-labelled MCP-plane tools become vulnerable, and only in `vulnerable`
mode. Intentionally-vulnerable files carry a banner:
`# INTENTIONALLY VULNERABLE — <VULN-ID> — see docs/GROUND-TRUTH.md`.

> **MCP transport:** Phase 0 uses an in-process registry transport so the whole
> app runs in one process. The streamable-HTTP MCP transport (official SDK) is a
> future upgrade behind the same client API.
>
> **MCP05 sandbox (when built):** with Docker removed, command execution for the
> MCP05 lab runs in a **constrained in-process subprocess runner** — an ephemeral
> temp work dir, a project-provided fake `convert` shim, a hard timeout, and no
> shell in secure mode. Blast radius stays local and synthetic (SEC-001/003); the
> OS-level isolation Docker gave (no-network, cap-drop) is replaced by that
> constrained runner. See `sandbox/README.md`.

## Tech stack

React + TypeScript + Vite + Tailwind · Python 3.12 + FastAPI + Pydantic v2 ·
official Python MCP SDK · SQLite + SQLModel · pytest + httpx · Vitest + Testing
Library. Run with `uv`/`uvicorn` (no Docker).

## API surfaces (analysable by the FYP)

`GET /api/health` · `GET /api/labs` · `GET /api/labs/{id}` ·
`POST /api/labs/{id}/mode|reset|attack|start` · `GET /api/labs/{id}/telemetry` ·
`GET /api/mcp/servers|tools` · `GET /api/mcp/tools/{id}` ·
`POST /api/mcp/tools/{id}/call` · `GET /api/vulnerabilities` (catalog metadata
only) · `GET /api/evidence`.

**No endpoint discloses a vulnerability verdict** (SEC-006).

## Using it against the FYP (evaluation loop)

1. Start the target (MCP03 is `vulnerable` by default). 2. Confirm the lab active
   via the manual verification in `docs/GROUND-TRUTH.md`. 3. Run the FYP against
   the HTTP + MCP surfaces. 4. Compare findings to `docs/GROUND-TRUTH.md`.
5. Toggle **Secure** and re-run to measure false positives. 6. Reset and repeat.

## Project docs

- `docs/GROUND-TRUTH.md` — the answer key (per-vuln + matrix).
- `docs/OWASP-MCP-MAPPING.md` — OWASP MCP Top 10 mapping.
- `docs/TEST-SCENARIOS.md` — FYP-validation scenarios.
- `CLAUDE.md` — implementation memory / current phase state.
- `docs/PRD.md`, `docs/TDD.md` — design contracts, kept **local only**
  (git-ignored). Updated 2026-08-21 to the Docker-free run model.

## Current state

**All three labs complete** (MCP03, MCP05, MCP10). Runs Docker-free via
`uvicorn`. See `CLAUDE.md`.
