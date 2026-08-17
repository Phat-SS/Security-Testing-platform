"""Repository — the only place that talks to the ORM.

Converts between Pydantic domain objects and rows. Everything above this layer
works in Pydantic models; everything below is storage detail.
"""

from __future__ import annotations

from app.database.models import (
    Assessment,
    AuditLog,
    ExecutionRow,
    FindingRow,
    TestCaseRow,
)
from app.schemas.analysis import IssueAnalysis
from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.testcase import DESTRUCTIVE_METHODS, TestCase


class Repository:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    # -- assessments --------------------------------------------------------

    def create_assessment(self, assessment_id: str, issue_key: str, project_key: str) -> None:
        with self._sf() as s:
            s.add(Assessment(id=assessment_id, issue_key=issue_key, project_key=project_key))
            s.commit()

    def save_analysis(self, assessment_id: str, analysis: IssueAnalysis) -> None:
        with self._sf() as s:
            a = s.get(Assessment, assessment_id)
            a.analysis_json = analysis.model_dump(mode="json")
            a.status = "ANALYZED"
            s.commit()

    def save_coverage(self, assessment_id: str, coverage: list[dict]) -> None:
        with self._sf() as s:
            a = s.get(Assessment, assessment_id)
            a.coverage_json = coverage
            s.commit()

    def set_target(self, assessment_id: str, base_url: str) -> None:
        with self._sf() as s:
            a = s.get(Assessment, assessment_id)
            a.target_base_url = base_url
            s.commit()

    def get_assessment(self, assessment_id: str) -> Assessment | None:
        with self._sf() as s:
            return s.get(Assessment, assessment_id)

    def list_assessments(self) -> list[Assessment]:
        with self._sf() as s:
            return list(s.query(Assessment).order_by(Assessment.created_at.desc()).all())

    def delete_assessment(self, assessment_id: str) -> None:
        with self._sf() as s:
            a = s.get(Assessment, assessment_id)
            if a:
                s.delete(a)  # cascades to test_cases/executions/findings
                s.commit()

    def previous_assessment_for_issue(self, issue_key: str, exclude_id: str) -> Assessment | None:
        """Most recent *other* assessment of the same issue — the regression baseline."""
        with self._sf() as s:
            return (
                s.query(Assessment)
                .filter(Assessment.issue_key == issue_key, Assessment.id != exclude_id,
                        Assessment.status == "EXECUTED")
                .order_by(Assessment.created_at.desc())
                .first()
            )

    # -- test cases ---------------------------------------------------------

    def save_test_cases(self, assessment_id: str, tests: list[TestCase]) -> None:
        with self._sf() as s:
            for t in tests:
                s.add(TestCaseRow(
                    assessment_id=assessment_id, test_id=t.test_id,
                    owasp_category=t.owasp_category.value,
                    approval_status=t.approval_status.value,
                    data_json=t.model_dump(mode="json"),
                ))
            s.commit()

    def get_test_cases(self, assessment_id: str) -> list[TestCase]:
        with self._sf() as s:
            rows = s.query(TestCaseRow).filter_by(assessment_id=assessment_id).all()
            return [TestCase.model_validate(r.data_json) for r in rows]

    def get_test_case(self, assessment_id: str, test_id: str) -> TestCase | None:
        with self._sf() as s:
            row = (
                s.query(TestCaseRow)
                .filter_by(assessment_id=assessment_id, test_id=test_id)
                .one_or_none()
            )
            return TestCase.model_validate(row.data_json) if row else None

    def update_test_request(self, assessment_id: str, test_id: str, request_json: dict) -> bool:
        """Overwrite a test's request (method/path/headers/query/body/capture)
        and reset approval to PENDING — an edited request has not been
        reviewed, so a prior approval no longer means anything."""
        with self._sf() as s:
            row = (
                s.query(TestCaseRow)
                .filter_by(assessment_id=assessment_id, test_id=test_id)
                .one_or_none()
            )
            if not row:
                return False
            data = dict(row.data_json)
            data["request"] = request_json
            data["approval_status"] = "PENDING"
            # Re-derive destructiveness from the (possibly edited) method:
            # only ever escalate, never downgrade, since a test can also be
            # flagged destructive for reasons other than its current method.
            # Without this, editing a GET test's method to DELETE would keep
            # is_destructive=False and let it run under the default
            # "non-destructive only" execution path, skipping the
            # destructive-action confirmation gate entirely.
            data["is_destructive"] = bool(data.get("is_destructive")) or (
                str(request_json.get("method", "")).upper() in DESTRUCTIVE_METHODS
            )
            row.approval_status = "PENDING"
            row.data_json = data
            s.commit()
            return True

    def set_approval(self, assessment_id: str, test_id: str, status: str) -> None:
        with self._sf() as s:
            row = (
                s.query(TestCaseRow)
                .filter_by(assessment_id=assessment_id, test_id=test_id)
                .one_or_none()
            )
            if not row:
                return
            row.approval_status = status
            data = dict(row.data_json)
            data["approval_status"] = status
            row.data_json = data
            s.commit()

    # -- executions & findings ---------------------------------------------

    def save_executions(self, assessment_id: str, executions: list[Execution]) -> None:
        with self._sf() as s:
            for e in executions:
                s.add(ExecutionRow(
                    assessment_id=assessment_id, execution_id=e.execution_id,
                    test_id=e.test_id, result=e.verdict.result.value,
                    evidence_hash=e.evidence_hash, data_json=e.model_dump(mode="json"),
                ))
            a = s.get(Assessment, assessment_id)
            a.status = "EXECUTED"
            s.commit()

    def get_executions(self, assessment_id: str) -> list[Execution]:
        # Ordered by row id (insertion order): callers rely on this to seed
        # the evidence hash chain from the *last* execution and to verify
        # the chain end-to-end, both of which require a stable order.
        with self._sf() as s:
            rows = (
                s.query(ExecutionRow).filter_by(assessment_id=assessment_id)
                .order_by(ExecutionRow.id).all()
            )
            return [Execution.model_validate(r.data_json) for r in rows]

    def save_findings(self, assessment_id: str, findings: list[Finding]) -> None:
        with self._sf() as s:
            for f in findings:
                s.add(FindingRow(
                    assessment_id=assessment_id, finding_id=f.finding_id,
                    severity=f.severity.value, data_json=f.model_dump(mode="json"),
                ))
            s.commit()

    def get_findings(self, assessment_id: str) -> list[Finding]:
        with self._sf() as s:
            rows = s.query(FindingRow).filter_by(assessment_id=assessment_id).all()
            return [Finding.model_validate(r.data_json) for r in rows]

    # -- audit --------------------------------------------------------------

    def audit(self, action: str, assessment_id: str = "", actor: str = "system", detail: str = "") -> None:
        with self._sf() as s:
            s.add(AuditLog(actor=actor, action=action, assessment_id=assessment_id, detail=detail))
            s.commit()

    def get_audit(self, assessment_id: str) -> list[AuditLog]:
        with self._sf() as s:
            return list(
                s.query(AuditLog).filter_by(assessment_id=assessment_id)
                .order_by(AuditLog.created_at).all()
            )
