"""FastAPI application assembly (control plane).

Ordinarily-secure infrastructure (SEC-004): CORS is scoped to the local
frontend origin, inputs are validated by the routers/schemas, and the app binds
to localhost via uvicorn config (DEP-004). On startup it creates tables and
seeds the baseline catalog so a fresh checkout is immediately usable.

Path bootstrap
--------------
The control plane imports the physically-separate ``mcp_servers`` package
(repo-root sibling of ``backend``). We add the repo root to ``sys.path`` here so
``import mcp_servers`` works whether launched via uvicorn, Docker, or pytest.
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

# --- path bootstrap (must run before importing mcp-plane packages) ---------
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from sqlmodel import Session  # noqa: E402

from .api import api_router  # noqa: E402
from .config import get_settings  # noqa: E402
from .db import get_engine, init_db  # noqa: E402
from .db.seed import seed_baseline  # noqa: E402


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup: create tables and seed the baseline catalog (idempotent, RST-002)."""
    init_db()
    with Session(get_engine()) as session:
        seed_baseline(session)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="vuln_mcp_app control plane",
        description=(
            "Intentionally vulnerable MCP security lab (TARGET, not a scanner). "
            "This HTTP surface is ordinarily-secure infrastructure; it emits "
            "evidence and never discloses a vulnerability verdict (SEC-006)."
        ),
        version="0.1.0",
        lifespan=_lifespan,
    )

    # CORS restricted to the local frontend origin (infra hardening).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.include_router(api_router)

    @app.get("/")
    def root() -> dict:
        return {
            "app": "vuln_mcp_app",
            "role": "vulnerable MCP target (not a scanner)",
            "docs": "/docs",
        }

    return app


app = create_app()
