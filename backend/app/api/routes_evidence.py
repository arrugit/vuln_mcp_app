"""GET /api/evidence (EV-002, TDD §12/§23).

Returns emitted evidence records — evidence produced by the target, NOT a scan
verdict. There is no field saying "vulnerable"; the owner/FYP inspects the raw
signal and decides (SEC-006).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlmodel import Session

from ..services import EvidenceService, MCPService
from .deps import db_session

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("")
def list_evidence(
    lab_run_id: int | None = None, session: Session = Depends(db_session)
) -> list[dict]:
    service = EvidenceService(session)
    return [
        {
            "id": e.id,
            "lab_run_id": e.lab_run_id,
            "kind": e.kind,
            "observable": e.observable,
            "raw_signal": MCPService.parse_json_field(e.raw_signal),
            "created_at": e.created_at.isoformat(),
        }
        for e in service.list_all(lab_run_id)
    ]
