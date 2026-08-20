"""SQLite engine + session management (TDD §9).

Infrastructure only (SEC-004): this is ordinary, careful data-access code. The
only mild "cleverness" is that the engine is created lazily and cached so tests
can point ``DATABASE_URL`` at a temporary file, clear the settings cache, and
call :func:`reset_engine` to get a fresh database — supporting deterministic,
repeatable runs (NFR-002).
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from ..config import get_settings

# Import the entities module for its side effect: registering every table on
# SQLModel.metadata so ``create_all`` knows about them.
from .. import models as _models  # noqa: F401

_ENGINE: Optional[Engine] = None


def _ensure_sqlite_dir(database_url: str) -> None:
    """Create the parent directory for a file-backed SQLite DB if needed.

    Robustness: a fresh checkout has no ``backend/data`` directory; without this
    the first connection would fail. In-memory URLs are skipped.
    """
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return
    path_part = database_url[len(prefix):]
    if not path_part or path_part == ":memory:":
        return
    db_path = Path(path_part)
    db_path.parent.mkdir(parents=True, exist_ok=True)


def get_engine() -> Engine:
    """Return the cached engine, creating it on first use."""
    global _ENGINE
    if _ENGINE is None:
        settings = get_settings()
        _ensure_sqlite_dir(settings.database_url)
        # check_same_thread=False lets FastAPI's threadpool share the SQLite
        # connection safely for our simple, low-concurrency workload.
        connect_args = {"check_same_thread": False}
        _ENGINE = create_engine(
            settings.database_url,
            echo=False,
            connect_args=connect_args,
        )
    return _ENGINE


def reset_engine() -> None:
    """Dispose and forget the cached engine (used by tests between DB switches)."""
    global _ENGINE
    if _ENGINE is not None:
        _ENGINE.dispose()
    _ENGINE = None


def init_db(*, drop_first: bool = False) -> None:
    """Create all tables (optionally dropping them first for a clean baseline)."""
    engine = get_engine()
    if drop_first:
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    with Session(get_engine()) as session:
        yield session


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context-manager session with commit/rollback for service-layer code."""
    session = Session(get_engine())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def sqlite_file_path() -> Optional[str]:
    """Return the on-disk path of the SQLite file, if the URL is file-backed."""
    url = get_settings().database_url
    prefix = "sqlite:///"
    if url.startswith(prefix):
        candidate = url[len(prefix):]
        if candidate and candidate != ":memory:" and os.path.isabs(candidate) is False:
            return candidate
        return candidate or None
    return None
