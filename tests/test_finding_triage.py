"""A reviewer's own false-positive/reopen call on a confirmed finding.

Never touches the sealed verdict, the finding's own fields, or the finding
count reported elsewhere — this is a reviewer's opinion recorded next to the
evidence, the same standing as the AI adjudicator's.
"""

import pytest
from starlette.testclient import TestClient

from app.database.models import init_db, make_engine, make_session_factory
from app.database.repository import Repository
from app.schemas.enums import Confidence, OwaspApiCategory, Severity
from app.schemas.finding import CorrelationEvidence, Finding


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _repo() -> Repository:
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    return Repository(make_session_factory(engine))


def _finding(finding_id: str = "SEC-001") -> Finding:
    return Finding(
        finding_id=finding_id, title="BOLA", owasp_category=OwaspApiCategory.API1,
        severity=Severity.HIGH, confidence=Confidence.HIGH, endpoint="GET /x",
        dedup_key="API1:2023|GET /x|swap_object_id",
        correlation=CorrelationEvidence(baseline_summary="b", attack_summary="a",
                                       expected="e", actual="a"),
        impact="impact", recommendation="fix it",
    )


def test_a_finding_starts_untriaged():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM")
    assert repo.get_finding_triage("A-1") == {}


def test_marking_false_positive_is_recorded_and_readable():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM")
    repo.set_finding_triage("A-1", "SEC-001", "dedup-key", "false_positive",
                           note="shared test account, not a real leak", actor="alice")

    triage = repo.get_finding_triage("A-1")
    assert triage["SEC-001"]["status"] == "false_positive"
    assert triage["SEC-001"]["actor"] == "alice"
    assert "shared test account" in triage["SEC-001"]["note"]


def test_reopening_overwrites_rather_than_accumulates():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM")
    repo.set_finding_triage("A-1", "SEC-001", "k", "false_positive", actor="alice")
    repo.set_finding_triage("A-1", "SEC-001", "k", "open", actor="bob")

    triage = repo.get_finding_triage("A-1")
    assert len(triage) == 1
    assert triage["SEC-001"]["status"] == "open"
    assert triage["SEC-001"]["actor"] == "bob"


def test_triage_is_scoped_to_its_own_assessment():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM")
    repo.create_assessment("A-2", "CRM-2", "CRM")
    repo.set_finding_triage("A-1", "SEC-001", "k", "false_positive")

    assert "SEC-001" in repo.get_finding_triage("A-1")
    assert repo.get_finding_triage("A-2") == {}


def test_finding_triage_never_touches_the_finding_itself():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM")
    repo.replace_findings("A-1", [_finding()])
    before = repo.get_findings("A-1")[0]

    repo.set_finding_triage("A-1", "SEC-001", before.dedup_key, "false_positive")

    after = repo.get_findings("A-1")[0]
    assert after.model_dump() == before.model_dump()


def test_triage_across_the_engagement_is_keyed_by_assessment_and_finding():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM", engagement="acme")
    repo.create_assessment("A-2", "CRM-2", "CRM", engagement="acme")
    repo.set_finding_triage("A-1", "SEC-001", "k", "false_positive")

    across = repo.get_finding_triage_across("acme")
    assert across[("A-1", "SEC-001")]["status"] == "false_positive"
    assert ("A-2", "SEC-001") not in across


def test_a_bad_status_value_is_refused_by_the_route(client):
    """The route validates status before writing, rather than trusting the
    form: a typo'd status value must not silently become a third, undocumented
    triage state."""
    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=False)
    aid = r.headers["location"].split("/assessment/")[1].split("/")[0].split("?")[0]
    resp = client.post(f"/assessment/{aid}/findings/SEC-001/triage",
                       data={"status": "definitely_not_a_real_status"}, follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert "Invalid" in resp.headers["location"].replace("+", " ")
