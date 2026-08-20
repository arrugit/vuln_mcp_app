"""Lab endpoints (TDD §12): list, detail, start, mode toggle, reset, attack.

All descriptive — no verdicts (SEC-006). Inputs strictly validated (SEC-004).

In Phase 0 the ``/attack`` endpoint is intentionally a NO-OP stub: it creates a
``LabRun`` for contract stability but performs no exploit and emits no evidence,
because no vulnerable behaviour exists yet. Each lab's Phase B replaces the stub
body with its deterministic attack flow.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from ..schemas import AttackRequest, ModeRequest, StartRequest
from ..services import LabService
from .deps import db_session

router = APIRouter(prefix="/labs", tags=["labs"])


def _lab_detail(service: LabService, lab) -> dict:
    """Assemble a descriptive lab-detail payload (component/attack-surface)."""
    vuln = service.get_vulnerability_for_lab(lab.id)
    return {
        "id": lab.id,
        "slug": lab.slug,
        "title": lab.title,
        "owasp_id": lab.owasp_id,
        "severity": lab.severity,
        "difficulty": lab.difficulty,
        "mode": lab.mode,
        "status": lab.status,
        "vulnerability": None
        if vuln is None
        else {
            "vuln_code": vuln.vuln_code,
            "owasp_id": vuln.owasp_id,
            "component": vuln.component,
            "attack_surface": vuln.attack_surface,
        },
    }


@router.get("")
def list_labs(session: Session = Depends(db_session)) -> list[dict]:
    service = LabService(session)
    return [
        {
            "id": lab.id,
            "slug": lab.slug,
            "title": lab.title,
            "owasp_id": lab.owasp_id,
            "severity": lab.severity,
            "difficulty": lab.difficulty,
            "status": lab.status,
            "mode": lab.mode,
        }
        for lab in service.list_labs()
    ]


@router.get("/{lab_id}")
def get_lab(lab_id: int, session: Session = Depends(db_session)) -> dict:
    service = LabService(session)
    lab = service.get_lab(lab_id)
    if lab is None:
        raise HTTPException(status_code=404, detail="lab not found")
    return _lab_detail(service, lab)


@router.post("/{lab_id}/start")
def start_lab(
    lab_id: int,
    body: StartRequest | None = None,
    session: Session = Depends(db_session),
) -> dict:
    service = LabService(session)
    lab = service.get_lab(lab_id)
    if lab is None:
        raise HTTPException(status_code=404, detail="lab not found")
    if body is not None and body.mode is not None:
        lab = service.set_mode(lab_id, body.mode)
    run = service.start_run(lab_id, trigger="start")
    return {"lab_id": lab_id, "mode": lab.mode, "lab_run_id": run.id}


@router.post("/{lab_id}/mode")
def set_mode(
    lab_id: int, body: ModeRequest, session: Session = Depends(db_session)
) -> dict:
    service = LabService(session)
    try:
        lab = service.set_mode(lab_id, body.mode)
    except KeyError:
        raise HTTPException(status_code=404, detail="lab not found")
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid mode")
    return {"mode": lab.mode}


@router.post("/{lab_id}/reset")
def reset_lab(lab_id: int, session: Session = Depends(db_session)) -> dict:
    service = LabService(session)
    try:
        service.reset_lab(lab_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="lab not found")
    return {"status": "reset"}


@router.post("/{lab_id}/attack")
def attack_lab(
    lab_id: int,
    body: AttackRequest,
    session: Session = Depends(db_session),
) -> dict:
    """Run the lab's deterministic attack simulation (FR-020).

    Dispatches to the per-lab orchestrator by slug. MCP03 is implemented
    (Phase A: clean flow, no leak yet); labs without an orchestrator return a
    clear stub. This endpoint emits evidence — never a verdict (SEC-006).
    """
    from ..services.labs import run_lab_attack

    service = LabService(session)
    lab = service.get_lab(lab_id)
    if lab is None:
        raise HTTPException(status_code=404, detail="lab not found")
    return run_lab_attack(session, lab, body.params)


@router.get("/{lab_id}/telemetry")
def lab_telemetry(
    lab_id: int,
    lab_run_id: int | None = None,
    session: Session = Depends(db_session),
) -> list[dict]:
    from ..services import TelemetryService

    service = LabService(session)
    if service.get_lab(lab_id) is None:
        raise HTTPException(status_code=404, detail="lab not found")
    telemetry = TelemetryService(session)
    events = (
        telemetry.list_for_run(lab_run_id)
        if lab_run_id is not None
        else telemetry.list_all()
    )
    return [
        {
            "id": e.id,
            "lab_run_id": e.lab_run_id,
            "ts": e.ts.isoformat(),
            "direction": e.direction,
            "method": e.method,
            "payload": MCPService_parse(e.payload),
            "mode": e.mode,
            "security_event": e.security_event,
        }
        for e in events
    ]


def MCPService_parse(value: str):
    """Local JSON parse helper (kept simple to avoid a cross-import cycle)."""
    import json

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value
