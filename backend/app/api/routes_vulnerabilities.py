"""GET /api/vulnerabilities (TDD §12 anti-oracle rule).

Returns *catalog metadata* (which labs exist, OWASP class, component,
attack-surface) — the same information a scanner could infer from the surface —
but NEVER a boolean "this is currently exploitable" (SEC-006). Whether the target
is vulnerable or secure is observable only through behaviour/evidence.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from ..models import Vulnerability
from .deps import db_session

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("")
def list_vulnerabilities(session: Session = Depends(db_session)) -> list[dict]:
    rows = session.exec(select(Vulnerability)).all()
    return [
        {
            "vuln_code": v.vuln_code,
            "owasp_id": v.owasp_id,
            "component": v.component,
            "attack_surface": v.attack_surface,
            # Deliberately NO "is_present"/"status" field (SEC-006).
        }
        for v in rows
    ]
