"""Pytest fixtures (TDD §29).

Each test gets an isolated, temporary SQLite database so runs are deterministic
and independent (NFR-002). We point ``DATABASE_URL`` at a temp file, clear the
settings + engine caches, initialise + seed, and yield a FastAPI TestClient.

The repo root is added to ``sys.path`` so both ``backend.app`` and the
physically-separate ``mcp_servers`` package import cleanly.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Configure an isolated temp SQLite DB and return its path."""
    db_path = tmp_path / "test_vuln_mcp.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    # EXPOSE_HEALTH_MODE default true; individual tests may override.

    from backend.app.config import get_settings
    from backend.app.db import database as db_module

    get_settings.cache_clear()
    db_module.reset_engine()

    from backend.app.db import init_db
    from backend.app.db.seed import seed_baseline
    from sqlmodel import Session

    init_db(drop_first=True)
    with Session(db_module.get_engine()) as session:
        seed_baseline(session)

    yield db_path

    db_module.reset_engine()
    get_settings.cache_clear()


@pytest.fixture()
def client(temp_db):
    """FastAPI TestClient wired to the temp DB."""
    from fastapi.testclient import TestClient
    from backend.app.main import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def session(temp_db):
    """A raw DB session for service-layer unit tests."""
    from sqlmodel import Session
    from backend.app.db import database as db_module

    with Session(db_module.get_engine()) as s:
        yield s
