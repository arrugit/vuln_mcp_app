"""Telemetry capture (FR-014, TDD §22).

Every MCP interaction is recorded as one ``TelemetryEvent`` row so the S7
console can render a CLIENT<->SERVER protocol trace. This satisfies MCP08 as
*supporting infrastructure only* — it is explicitly NOT implemented as a fourth
vulnerability lab (PRD §11).

Nothing here discloses a verdict. ``security_event`` is a neutral tag the lab
code may set (e.g. "secret_read") so evidence is *inspectable*, but it never
says "vulnerable" — the FYP infers that from the payloads (SEC-006).
"""
from __future__ import annotations

import json
from typing import Any, Optional

from sqlmodel import Session, select

from ..models import TelemetryEvent


class TelemetryService:
    """Thin, well-tested recorder around the ``telemetry_events`` table."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(
        self,
        *,
        direction: str,
        method: str,
        payload: Any,
        lab_run_id: Optional[int] = None,
        mode: Optional[str] = None,
        security_event: Optional[str] = None,
    ) -> TelemetryEvent:
        """Persist one protocol event.

        ``direction`` is "client->server" or "server->client"; ``method`` is an
        MCP method like "tools/list" or "tools/call"; ``payload`` is any
        JSON-serialisable object (dumped to a stable string).
        """
        event = TelemetryEvent(
            lab_run_id=lab_run_id,
            direction=direction,
            method=method,
            payload=json.dumps(payload, sort_keys=True, default=str),
            mode=mode,
            security_event=security_event,
        )
        self._session.add(event)
        self._session.commit()
        self._session.refresh(event)
        return event

    def list_for_run(self, lab_run_id: int) -> list[TelemetryEvent]:
        """Return the ordered protocol trace for a single lab run."""
        stmt = (
            select(TelemetryEvent)
            .where(TelemetryEvent.lab_run_id == lab_run_id)
            .order_by(TelemetryEvent.ts, TelemetryEvent.id)
        )
        return list(self._session.exec(stmt))

    def list_all(self, limit: int = 200) -> list[TelemetryEvent]:
        """Return the most recent telemetry events (for the global console)."""
        stmt = select(TelemetryEvent).order_by(
            TelemetryEvent.ts.desc(), TelemetryEvent.id.desc()
        ).limit(limit)
        return list(self._session.exec(stmt))
