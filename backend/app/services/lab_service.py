"""Lab lifecycle service (TDD §7 service layer).

Handles the *infrastructure* side of labs: list, detail, mode toggle, start
(creates a ``LabRun``), and reset orchestration. It emits NO verdict (SEC-006);
``mode`` is a behaviour switch (FR-004), not a statement about exploitability.

Lab-specific attack orchestration (the actual exploit flow) is added per lab in
later phases and will create a ``LabRun`` via :meth:`start_run`, then record
telemetry + evidence against it.
"""
from __future__ import annotations

from typing import Optional

from sqlmodel import Session, select

from ..db.reset import reset_database
from ..models import Lab, LabRun, Vulnerability

VALID_MODES = {"vulnerable", "secure"}


class LabService:
    def __init__(self, session: Session) -> None:
        self._session = session

    # --- read ------------------------------------------------------------
    def list_labs(self) -> list[Lab]:
        stmt = select(Lab).order_by(Lab.order_index)
        return list(self._session.exec(stmt))

    def get_lab(self, lab_id: int) -> Optional[Lab]:
        return self._session.get(Lab, lab_id)

    def get_lab_by_slug(self, slug: str) -> Optional[Lab]:
        return self._session.exec(select(Lab).where(Lab.slug == slug)).first()

    def get_vulnerability_for_lab(self, lab_id: int) -> Optional[Vulnerability]:
        return self._session.exec(
            select(Vulnerability).where(Vulnerability.lab_id == lab_id)
        ).first()

    # --- mode toggle (FR-004) -------------------------------------------
    def set_mode(self, lab_id: int, mode: str) -> Lab:
        """Set a lab's behaviour mode. Validates the enum (infra hardening)."""
        if mode not in VALID_MODES:
            raise ValueError(f"invalid mode: {mode!r}")
        lab = self._session.get(Lab, lab_id)
        if lab is None:
            raise KeyError(lab_id)
        lab.mode = mode
        self._session.add(lab)
        self._session.commit()
        self._session.refresh(lab)
        return lab

    # --- runs ------------------------------------------------------------
    def start_run(
        self,
        lab_id: int,
        *,
        trigger: str = "",
        session_id: Optional[int] = None,
    ) -> LabRun:
        """Create a ``LabRun`` grouping the evidence/telemetry of one attack."""
        lab = self._session.get(Lab, lab_id)
        if lab is None:
            raise KeyError(lab_id)
        run = LabRun(
            lab_id=lab_id,
            session_id=session_id,
            mode=lab.mode,
            trigger=trigger,
            status="completed",
        )
        self._session.add(run)
        self._session.commit()
        self._session.refresh(run)
        return run

    # --- reset (RST-001) -------------------------------------------------
    def reset_lab(self, lab_id: int) -> None:
        """Reset baseline state.

        Phase 0 provides a global baseline reset (clear runtime state + re-seed).
        Per-lab granularity is honoured in later phases; the ``lab_id`` is
        validated here so the API contract is stable from the start.
        """
        lab = self._session.get(Lab, lab_id)
        if lab is None:
            raise KeyError(lab_id)
        reset_database(self._session)
