"""Reset tests (RST-001..004)."""
from __future__ import annotations

from backend.app.db.reset import reset_database
from backend.app.models import Evidence, LabRun
from backend.app.services import EvidenceService, LabService


def test_reset_endpoint_ok(client):
    labs = client.get("/api/labs").json()
    resp = client.post(f"/api/labs/{labs[0]['id']}/reset")
    assert resp.status_code == 200
    assert resp.json() == {"status": "reset"}


def test_reset_clears_runtime_state(session):
    """Reset must wipe lab_runs + evidence but keep the catalog (RST-001)."""
    labs = LabService(session)
    lab = labs.list_labs()[0]
    run = labs.start_run(lab.id, trigger="t")
    EvidenceService(session).record(
        lab_run_id=run.id, kind="test", observable="x", raw_signal={"a": 1}
    )
    assert session.get(LabRun, run.id) is not None

    reset_database(session)

    # Runtime tables cleared...
    assert session.get(LabRun, run.id) is None
    assert len(EvidenceService(session).list_all()) == 0
    # ...but the catalog survives (still 3 labs).
    assert len(LabService(session).list_labs()) == 3


def test_reset_is_idempotent(session):
    """RST-002: running reset repeatedly does not duplicate catalog rows."""
    reset_database(session)
    reset_database(session)
    labs = LabService(session).list_labs()
    assert len(labs) == 3
    slugs = [lab.slug for lab in labs]
    assert len(slugs) == len(set(slugs))
