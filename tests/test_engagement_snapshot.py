"""The authorization a run was sent under, recorded with the run.

The engagement file says what is authorized. The platform read it live and then
never recorded what it had read, so a report proved *that* a host was tested and
never *that the host was authorized when it was tested* — and editing the scope
afterwards changed what every earlier run meant, silently and retroactively.
"""

from __future__ import annotations

import json

import pytest

from app.core import snapshot
from app.core.engagement import load_engagement


def _engagement(tmp_path, **overrides):
    cfg = tmp_path / "engagement.json"
    body = {
        "environments": {"dev": "https://dev.example.com"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["dev.example.com"], "blocked_hosts": ["prod.example.com"]},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {"Authorization": "Bearer sekrit-A"},
             "role": "user", "owns": {"customer_id": "1001"}},
            {"name": "agent_B", "auth_headers": {"Authorization": "Bearer sekrit-B"},
             "role": "user", "owns": {"customer_id": "2002"}},
        ],
    }
    body.update(overrides)
    cfg.write_text(json.dumps(body))
    return load_engagement(str(cfg))


def _capture(tmp_path, **overrides):
    eng = _engagement(tmp_path, **overrides)
    return snapshot.capture(eng, base_url="https://dev.example.com", environment="dev")


# -- what it records --------------------------------------------------------


def test_the_snapshot_records_the_authorization_boundary(tmp_path):
    snap = _capture(tmp_path)

    assert snap["base_url"] == "https://dev.example.com"
    assert snap["environment"] == "dev"
    assert snap["scope"]["allowed_hosts"] == ["dev.example.com"]
    assert snap["scope"]["blocked_hosts"] == ["prod.example.com"]
    assert (snap["attacker"], snap["victim"]) == ("agent_A", "agent_B")


def test_the_snapshot_records_which_objects_each_identity_owned(tmp_path):
    """"A read B's record" means nothing without knowing which records were
    B's — the ownership map is the basis of every BOLA verdict, so it is part
    of what the run means."""
    snap = _capture(tmp_path)
    owns = {p["name"]: p["owns"] for p in snap["personas"]}

    assert owns["agent_A"] == {"customer_id": "1001"}
    assert owns["agent_B"] == {"customer_id": "2002"}


def test_the_snapshot_carries_no_credentials(tmp_path):
    """It is meant to be attached to a ticket and read by people who are not
    entitled to the tokens."""
    snap = _capture(tmp_path)
    serialized = json.dumps(snap)

    assert "sekrit-A" not in serialized
    assert "sekrit-B" not in serialized
    # The header NAMES are recorded — which credential was sent is part of what
    # the request was; its value is not.
    names = {p["name"]: p["auth_header_names"] for p in snap["personas"]}
    assert names["agent_A"] == ["Authorization"]


# -- the fingerprint --------------------------------------------------------


def test_the_same_configuration_fingerprints_the_same(tmp_path):
    """Otherwise every run would look like a configuration change, and the
    field would be noise instead of evidence."""
    first = _capture(tmp_path)
    second = _capture(tmp_path)

    assert snapshot.fingerprint(first) == snapshot.fingerprint(second)


@pytest.mark.parametrize("change", [
    {"scope": {"allowed_hosts": ["dev.example.com", "other.example.com"]}},
    {"attacker": "agent_B", "victim": "agent_A"},
    {"scope": {"allowed_hosts": ["dev.example.com"], "allow_private_ranges": True}},
])
def test_changing_the_authorization_changes_the_fingerprint(tmp_path, change):
    before = snapshot.fingerprint(_capture(tmp_path))
    after = snapshot.fingerprint(_capture(tmp_path, **change))

    assert before != after, f"{change} left the fingerprint unchanged"


def test_differences_reads_as_a_sentence(tmp_path):
    before = _capture(tmp_path)
    after = _capture(tmp_path, scope={"allowed_hosts": ["other.example.com"]},
                     attacker="agent_B", victim="agent_A")

    changes = snapshot.differences(before, after)

    assert any("attacker agent_A → agent_B" in c for c in changes)
    assert any("+other.example.com" in c for c in changes)
    assert any("-dev.example.com" in c for c in changes)


# -- binding it to the evidence chain ---------------------------------------


def _sealed(**kwargs):
    from app.execution.evidence import seal
    from app.schemas.enums import Confidence, TestStatus
    from app.schemas.execution import CapturedRequest, Execution, Verdict

    execution = Execution(
        execution_id="E1", test_id="T1", owasp_category="API1:2023",
        scope_validated=True,
        request=CapturedRequest(method="GET", url="https://dev.example.com/1",
                                resolved_ip="1.2.3.4", headers={},
                                timestamp="2026-01-01T00:00:00+00:00"),
        response=None,
        verdict=Verdict(result=TestStatus.BLOCKED, reason="r", confidence=Confidence.HIGH,
                        expected_summary="", actual_summary=""),
        **kwargs,
    )
    return seal(execution, None)


def test_evidence_sealed_before_the_binding_existed_still_verifies():
    """Adding a field to the hash must not make a year of older records read as
    tampered — that is a false accusation, and worse than the gap it closes."""
    from app.execution.evidence import compute_hash, verify_chain

    legacy = _sealed()
    legacy.payload_version = 1
    legacy.engagement_hash = ""
    legacy.evidence_hash = compute_hash(legacy)

    assert verify_chain([legacy])


def test_removing_the_binding_from_a_sealed_record_breaks_the_chain():
    from app.execution.evidence import verify_chain

    record = _sealed(engagement_hash="a" * 64)
    assert verify_chain([record])

    record.engagement_hash = ""
    assert not verify_chain([record]), "the binding is not actually covered"


def test_a_record_cannot_be_downgraded_to_shed_the_binding():
    """The payload version is itself inside the hash, so relabelling a record
    as the older, weaker shape breaks it rather than excusing it."""
    from app.execution.evidence import verify_chain

    record = _sealed(engagement_hash="a" * 64)
    record.payload_version = 1

    assert not verify_chain([record])


# -- end to end -------------------------------------------------------------


@pytest.fixture()
def running(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        # Nothing listens here: this is about what gets recorded, not verdicts.
        "environments": {"dev": "http://127.0.0.1:19198"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {"Authorization": "Bearer SEKRIT-A"},
             "role": "user", "owns": {"customer_id": "1001"}},
            {"name": "agent_B", "auth_headers": {"Authorization": "Bearer SEKRIT-B"},
             "role": "user", "owns": {"customer_id": "2002"}},
        ],
        "runner": {"timeout_s": 1},
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'snap.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from starlette.testclient import TestClient

    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _run(client) -> str:
    from conftest import wait_for_run

    from app.api.main import state

    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")
    ids = [t.test_id for t in state.repo.get_test_cases(aid) if not t.is_destructive][:2]
    client.post(f"/assessment/{aid}/approve", data={"test_ids": ids})
    client.post(f"/assessment/{aid}/execute", follow_redirects=False)
    wait_for_run(client, aid)
    return aid


def test_every_execution_carries_the_authorization_it_ran_under(running):
    from app.api.main import state

    aid = _run(running)
    executions = state.repo.get_executions(aid)

    assert executions
    assert all(x.engagement_hash for x in executions), "a record was sealed without a binding"
    assert len({x.engagement_hash for x in executions}) == 1, "one run, one authorization"

    stored = state.repo.get_run_snapshot(aid, executions[0].engagement_hash)
    assert stored is not None, "the binding resolves to nothing"
    assert snapshot.fingerprint(stored) == executions[0].engagement_hash


def test_the_stored_snapshot_carries_no_credentials(running):
    from app.api.main import state

    aid = _run(running)
    stored = state.repo.latest_run_snapshot(aid)

    assert "SEKRIT" not in json.dumps(stored)


def test_changing_the_scope_does_not_rewrite_what_earlier_runs_meant(running):
    """The whole point. Editing the authorization used to change, silently and
    retroactively, what every earlier run had been authorized by."""
    from conftest import wait_for_run

    from app.api.main import state
    from app.execution.evidence import verify_chain

    aid = _run(running)
    first = [x.engagement_hash for x in state.repo.get_executions(aid)]

    running.post("/config/scope", data={"allowed_hosts": "127.0.0.1\nlater.example.com",
                                        "blocked_hosts": "", "allow_private_ranges": "true"})
    running.post(f"/assessment/{aid}/execute", headers={"Idempotency-Key": "second"},
                 follow_redirects=False)
    wait_for_run(running, aid)

    executions = state.repo.get_executions(aid)
    bindings = [x.engagement_hash for x in executions]

    assert bindings[:len(first)] == first, "an earlier run's authorization was rewritten"
    assert len(set(bindings)) == 2, "the second run recorded no change"
    assert verify_chain(executions), "the chain broke across the change"

    older = state.repo.get_run_snapshot(aid, first[0])
    newer = state.repo.get_run_snapshot(aid, bindings[-1])
    assert snapshot.differences(older, newer) == ["allowed_hosts: +later.example.com"]


def test_a_rerun_records_its_own_authorization(running):
    """A re-run sends packets under whatever the authorization is now — which is
    exactly what a regression diff has to be able to tell apart from a real
    change in the target."""
    from conftest import wait_for_run

    from app.api.main import state

    aid = _run(running)
    r = running.post(f"/assessment/{aid}/rerun", data={"mode": "same"},
                     follow_redirects=False)
    assert r.status_code == 303, r.text
    new_id = r.headers["location"].split("/assessment/")[1].split("?")[0].split("/")[0]
    wait_for_run(running, new_id)

    executions = state.repo.get_executions(new_id)
    assert executions, "the re-run produced nothing"
    assert all(x.engagement_hash for x in executions), "a re-run sealed records with no binding"
    assert state.repo.get_run_snapshot(new_id, executions[0].engagement_hash) is not None
