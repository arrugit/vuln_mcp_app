"""Synthetic fixtures for the MCP10 Context Injection & Over-Sharing lab.

Model
-----
A memory service where each **session** (a signed-in user) has its own private
**context** of remembered entries. ``memory.recall`` is supposed to return only
the caller's own entries. Session A (User A) keeps a project note and an API
token (``DEMO_SECRET_A``); Session B (User B) keeps unrelated personal notes.

The vulnerability (added in Phase B) is a missing ownership filter — a very common
broken-access-control mistake — so a recall from Session B returns Session A's
entries too. Everything here is synthetic (SEC-002).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEMO_SECRET_A = "DEMO_SECRET_A"

# Stable synthetic session tokens (opaque strings a client would present).
SESSION_A_TOKEN = "sess-alice-a1a1"
SESSION_B_TOKEN = "sess-bob-b2b2b2"


@dataclass
class Entry:
    key: str
    value: str


@dataclass
class SessionCtx:
    token: str
    user_label: str
    context_name: str
    entries: List[Entry] = field(default_factory=list)


# Seed: A owns the secret; B owns only benign content.
_SEED: List[SessionCtx] = [
    SessionCtx(
        SESSION_A_TOKEN,
        "User A",
        "Orion",
        [
            Entry("project", "Project Orion — launch plan draft"),
            Entry("api_token", DEMO_SECRET_A),
        ],
    ),
    SessionCtx(
        SESSION_B_TOKEN,
        "User B",
        "Personal",
        [
            Entry("reminder", "Buy milk"),
            Entry("note", "Nothing sensitive here"),
        ],
    ),
]


class ContextStore:
    """In-memory sessions/contexts store, resettable to baseline."""

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionCtx] = {}
        self.reset()

    def reset(self) -> None:
        self._sessions = {s.token: copy.deepcopy(s) for s in _SEED}

    def list_sessions(self) -> List[SessionCtx]:
        return list(self._sessions.values())

    def get_session(self, token: str) -> Optional[SessionCtx]:
        return self._sessions.get(token)

    def _flatten(self, sessions: List[SessionCtx]) -> List[Dict[str, str]]:
        """Return entries annotated with their owning session (for evidence)."""
        out: List[Dict[str, str]] = []
        for s in sessions:
            for e in s.entries:
                out.append(
                    {
                        "session_token": s.token,
                        "user_label": s.user_label,
                        "context": s.context_name,
                        "key": e.key,
                        "value": e.value,
                    }
                )
        return out

    def entries_for(self, token: str) -> List[Dict[str, str]]:
        """Only the caller's own entries (the correctly-scoped lookup)."""
        s = self._sessions.get(token)
        return self._flatten([s] if s is not None else [])

    def all_entries(self) -> List[Dict[str, str]]:
        """Every session's entries — no ownership scoping (the over-share)."""
        return self._flatten(list(self._sessions.values()))


_STORE = ContextStore()


def get_context_store() -> ContextStore:
    return _STORE


def reset_context_store() -> None:
    _STORE.reset()
