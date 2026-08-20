"""Shared API dependencies."""
from __future__ import annotations

from typing import Iterator

from sqlmodel import Session

from ..db import get_engine


def db_session() -> Iterator[Session]:
    """Yield a request-scoped DB session (FastAPI dependency)."""
    with Session(get_engine()) as session:
        yield session
