"""Evidence recording (EV-001..003, TDD §23).

Evidence is a first-class, persisted artefact per attack run: what was
triggered, the resulting observable, and the raw signal. It is EVIDENCE, never a
verdict (EV-002): the app emits *what happened*; the FYP decides what it means.

Phase 0 provides the recorder + retrieval. The concrete evidence ``kind`` values
(``metadata_poison``, ``command_injection``, ``context_leak``) are produced by
the lab attack code in later phases; this service stores whatever they emit.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from sqlmodel import Session, select

from ..models import Evidence


class EvidenceService:
    """Recorder + reader around the ``evidence`` table."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(
        self,
        *,
        lab_run_id: int,
        kind: str,
        observable: str,
        raw_signal: Any,
    ) -> Evidence:
        """Persist one evidence record.

        ``raw_signal`` is any JSON-serialisable payload (metadata string,
        constructed command + output, or leaked context record) and is stored as
        a stable JSON string for reproducible comparison (NFR-002).
        """
        evidence = Evidence(
            lab_run_id=lab_run_id,
            kind=kind,
            observable=observable,
            raw_signal=json.dumps(raw_signal, sort_keys=True, default=str),
        )
        self._session.add(evidence)
        self._session.commit()
        self._session.refresh(evidence)
        return evidence

    def list_for_run(self, lab_run_id: int) -> list[Evidence]:
        stmt = (
            select(Evidence)
            .where(Evidence.lab_run_id == lab_run_id)
            .order_by(Evidence.id)
        )
        return list(self._session.exec(stmt))

    def list_all(self, lab_run_id: Optional[int] = None) -> list[Evidence]:
        """List evidence, optionally filtered by run (backs GET /api/evidence)."""
        stmt = select(Evidence)
        if lab_run_id is not None:
            stmt = stmt.where(Evidence.lab_run_id == lab_run_id)
        stmt = stmt.order_by(Evidence.id.desc())
        return list(self._session.exec(stmt))
