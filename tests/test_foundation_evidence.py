"""Evidence recording tests (EV-001..003)."""
from __future__ import annotations

import json

from backend.app.services import EvidenceService, LabService


def test_evidence_record_and_retrieve(session):
    labs = LabService(session)
    run = labs.start_run(labs.list_labs()[0].id, trigger="t")
    ev = EvidenceService(session)
    ev.record(
        lab_run_id=run.id,
        kind="demo",
        observable="something observable happened",
        raw_signal={"value": "DEMO", "n": 2},
    )
    records = ev.list_for_run(run.id)
    assert len(records) == 1
    stored = records[0]
    assert stored.kind == "demo"
    # raw_signal is stored as a stable JSON string (reproducible; NFR-002).
    assert json.loads(stored.raw_signal) == {"n": 2, "value": "DEMO"}


def test_evidence_endpoint_returns_records(client):
    labs = client.get("/api/labs").json()
    # Directly exercise the read endpoint (empty until a lab emits evidence).
    resp = client.get("/api/evidence")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_evidence_has_no_verdict_field(session):
    labs = LabService(session)
    run = labs.start_run(labs.list_labs()[0].id)
    ev = EvidenceService(session)
    record = ev.record(lab_run_id=run.id, kind="k", observable="o", raw_signal={})
    # Evidence is not a verdict (EV-002): no boolean vuln flag on the model.
    assert not hasattr(record, "is_vulnerable")
