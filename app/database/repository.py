"""Repository — the only place that talks to the ORM.

Converts between Pydantic domain objects and rows. Everything above this layer
works in Pydantic models; everything below is storage detail.
"""

from __future__ import annotations

import json

from typing import ClassVar

from pydantic import ValidationError
from sqlalchemy import func

from app.database.models import (
    AgentRecordRow,
    Assessment,
    AuditLog,
    ExecutionRow,
    FindingRow,
    TestCaseRow,
)
from app.schemas.agent import PlanReview, RunAssessment
from app.schemas.analysis import IssueAnalysis
from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.testcase import DESTRUCTIVE_METHODS, TestCase


# Approval states that represent a decision a person made about a specific test.
# PENDING is the absence of one, so it is never carried across a regeneration.
_HUMAN_DECISIONS = {"APPROVED", "REJECTED", "DISABLED"}


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

    def clone_analysis(self, source_id: str, target_id: str) -> None:
        """Copy the analysis and coverage of one assessment onto another.

        Used by a re-run, which is a fresh assessment of the same issue: it must
        start from the endpoint list the tester actually curated, including hand-
        entered rows, rather than from whatever the extractor would find today.
        """
        with self._sf() as s:
            source = s.get(Assessment, source_id)
            target = s.get(Assessment, target_id)
            if source is None or target is None:
                return
            target.analysis_json = source.analysis_json
            target.coverage_json = source.coverage_json
            if source.analysis_json:
                target.status = "ANALYZED"
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

    def assessment_summary(self, assessment_id: str) -> dict:
        """Counts for one assessment, as COUNT queries rather than by loading and
        validating every test case, execution and finding it owns. The dashboard
        needs this for every card it renders."""
        with self._sf() as s:
            n_tests = (s.query(func.count(TestCaseRow.id))
                       .filter_by(assessment_id=assessment_id).scalar() or 0)
            n_approved = (s.query(func.count(TestCaseRow.id))
                          .filter_by(assessment_id=assessment_id,
                                     approval_status="APPROVED").scalar() or 0)
            n_executions = (s.query(func.count(ExecutionRow.id))
                            .filter_by(assessment_id=assessment_id).scalar() or 0)
            severities = dict(
                s.query(FindingRow.severity, func.count(FindingRow.id))
                .filter_by(assessment_id=assessment_id)
                .group_by(FindingRow.severity).all()
            )
        return {
            "id": assessment_id,
            "n_tests": int(n_tests),
            "n_approved": int(n_approved),
            "n_executions": int(n_executions),
            "n_findings": sum(severities.values()),
            "severities": {k: int(v) for k, v in severities.items()},
        }

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

    def replace_test_cases(self, assessment_id: str, tests: list[TestCase]) -> dict:
        """Swap the whole test plan, carrying a prior decision over to a test
        that is byte-identical to the one it replaces.

        `save_test_cases` appends, which is right for adaptive follow-ups but
        wrong for re-designing: two rows then share a `test_id` (they are
        generated deterministically as "API1-001"), and every lookup that uses
        `.one_or_none()` — set_approval, get_test_case, update_test_request —
        raises MultipleResultsFound. Regenerating a plan is a normal thing to do
        after editing the endpoint list, so it has to replace rather than stack.

        Carry-over is deliberately strict: an APPROVED/REJECTED decision only
        survives if every other field of the test is unchanged. An approval
        means "I read what this test does"; if anything about what it does
        changed, the decision no longer applies and the test goes back to
        PENDING.
        """
        with self._sf() as s:
            rows = s.query(TestCaseRow).filter_by(assessment_id=assessment_id).all()
            prior: dict[str, tuple[str, str]] = {}
            for r in rows:
                data = dict(r.data_json)
                status = str(data.pop("approval_status", "PENDING"))
                # Last row wins for a legacy duplicate test_id — it is the one
                # a subsequent read would most likely have shown.
                prior[r.test_id] = (_test_fingerprint(data), status)
                s.delete(r)
            s.flush()

            carried = 0
            for t in tests:
                data = t.model_dump(mode="json")
                status = t.approval_status.value
                previous = prior.get(t.test_id)
                if previous:
                    without_status = {k: v for k, v in data.items() if k != "approval_status"}
                    # Only a decision a human actually made is worth carrying;
                    # never let a stored PENDING overwrite an incoming status.
                    if (previous[1] in _HUMAN_DECISIONS
                            and previous[0] == _test_fingerprint(without_status)):
                        status = previous[1]
                        data["approval_status"] = status
                        carried += 1
                s.add(TestCaseRow(
                    assessment_id=assessment_id, test_id=t.test_id,
                    owasp_category=t.owasp_category.value,
                    approval_status=status,
                    data_json=data,
                ))
            s.commit()
            return {"replaced": len(rows), "total": len(tests), "carried_over": carried}

    def delete_test_cases(self, assessment_id: str) -> int:
        with self._sf() as s:
            n = s.query(TestCaseRow).filter_by(assessment_id=assessment_id).delete()
            s.commit()
            return n

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

    # -- querying a large plan ---------------------------------------------
    #
    # An aggressive design over a handful of endpoints produces several hundred
    # tests, and the page used to render every one of them into a single table
    # with no search, filter, sort or paging. Filtering here rather than in the
    # browser is what makes "approve all 312 matching this filter" mean the same
    # thing the tester just read on screen.
    #
    # Category and approval status are real indexed columns, so they filter in
    # SQL. Severity, destructiveness, source and the title text live inside
    # data_json; those are matched against the raw dict, and only the rows that
    # end up on the page are validated into TestCase objects — a 400-test plan
    # was paying for 400 pydantic validations on every render.

    _SEVERITY_ORDER: ClassVar[dict[str, int]] = {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
    }
    _APPROVAL_ORDER: ClassVar[dict[str, int]] = {
        "PENDING": 0, "APPROVED": 1, "REJECTED": 2, "DISABLED": 3,
    }

    def query_test_cases(
        self,
        assessment_id: str,
        *,
        q: str = "",
        cat: str = "",
        sev: str = "",
        appr: str = "",
        dest: str = "",
        src: str = "",
        sort: str = "id",
        page: int = 1,
        per: int = 25,
    ) -> dict:
        """Filter, sort and page a test plan.

        Returns the page of TestCase objects, the ids of *every* match (so a
        bulk action can act on the whole filtered set, not just what is
        rendered), the total, and facet counts for the filter controls.
        """
        with self._sf() as s:
            query = s.query(TestCaseRow).filter_by(assessment_id=assessment_id)
            if cat:
                query = query.filter(TestCaseRow.owasp_category == cat)
            if appr:
                query = query.filter(TestCaseRow.approval_status == appr)
            rows = query.order_by(TestCaseRow.id).all()
            raw = [(r.test_id, dict(r.data_json)) for r in rows]

            facets, meta = self._facets(assessment_id, s)

        needle = q.strip().lower()
        matched = [
            (test_id, data) for test_id, data in raw
            if self._matches(test_id, data, needle, sev, dest, src)
        ]
        matched = self._sorted(matched, sort)

        per = max(1, min(per, 500))
        pages = max(1, -(-len(matched) // per))
        page = max(1, min(page, pages))
        window = matched[(page - 1) * per: page * per]

        return {
            "tests": [TestCase.model_validate(data) for _tid, data in window],
            "matched_ids": [test_id for test_id, _d in matched],
            "total": len(matched),
            "unfiltered_total": len(raw),
            "page": page,
            "pages": pages,
            "per": per,
            "facets": facets,
            # Plan-wide counts, computed from the same scan the facets need, so
            # the page does not have to load and validate every test again just
            # to say how many are approved.
            "meta": meta,
        }

    @staticmethod
    def _matches(test_id: str, data: dict, needle: str, sev: str, dest: str, src: str) -> bool:
        if sev and str(data.get("severity", "")) != sev:
            return False
        if dest in ("yes", "no") and bool(data.get("is_destructive")) is not (dest == "yes"):
            return False
        if src and str(data.get("source", "")) != src:
            return False
        if needle:
            request = data.get("request") or {}
            haystack = " ".join(str(x) for x in (
                test_id,
                data.get("title", ""),
                data.get("objective", ""),
                (data.get("attack_mutation") or {}).get("kind", ""),
                request.get("method", ""),
                request.get("path", ""),
            )).lower()
            if needle not in haystack:
                return False
        return True

    @classmethod
    def _sorted(cls, matched: list, sort: str) -> list:
        if sort == "sev":
            return sorted(matched, key=lambda item: (
                cls._SEVERITY_ORDER.get(str(item[1].get("severity")), 9), item[0]))
        if sort == "appr":
            return sorted(matched, key=lambda item: (
                cls._APPROVAL_ORDER.get(str(item[1].get("approval_status")), 9), item[0]))
        if sort == "cat":
            return sorted(matched, key=lambda item: (
                str(item[1].get("owasp_category")), item[0]))
        if sort == "endpoint":
            return sorted(matched, key=lambda item: (
                str((item[1].get("request") or {}).get("path", "")), item[0]))
        return matched  # "id" — generation order, which groups by category already

    @staticmethod
    def _facets(assessment_id: str, session) -> tuple[dict, dict]:
        """Counts per filter value over the *unfiltered* plan, so a dropdown can
        say how many rows each option would leave and never offer an option that
        matches nothing — plus the plan-wide totals the page header needs."""
        rows = session.query(TestCaseRow).filter_by(assessment_id=assessment_id).all()
        out: dict[str, dict[str, int]] = {
            "cat": {}, "sev": {}, "appr": {}, "src": {}, "dest": {},
        }
        meta = {"total": len(rows), "approved": 0, "rejected": 0, "pending": 0,
                "approved_destructive": 0}
        for r in rows:
            data = r.data_json
            for key, value in (
                ("cat", r.owasp_category),
                ("sev", str(data.get("severity", ""))),
                ("appr", r.approval_status),
                ("src", str(data.get("source", ""))),
                ("dest", "yes" if data.get("is_destructive") else "no"),
            ):
                if value:
                    out[key][value] = out[key].get(value, 0) + 1
            if r.approval_status == "APPROVED":
                meta["approved"] += 1
                if data.get("is_destructive"):
                    # The count the destructive-run gate is sized from, so it has
                    # to be the intersection and not a product of two facets.
                    meta["approved_destructive"] += 1
            elif r.approval_status == "REJECTED":
                meta["rejected"] += 1
            elif r.approval_status == "PENDING":
                meta["pending"] += 1
        return out, meta

    def set_approval_bulk(self, assessment_id: str, test_ids: list[str], status: str) -> int:
        """One statement instead of one round-trip per test: approving a
        300-test plan through set_approval() was 300 separate transactions."""
        if not test_ids:
            return 0
        with self._sf() as s:
            rows = (
                s.query(TestCaseRow)
                .filter(TestCaseRow.assessment_id == assessment_id,
                        TestCaseRow.test_id.in_(test_ids))
                .all()
            )
            for row in rows:
                row.approval_status = status
                data = dict(row.data_json)
                data["approval_status"] = status
                row.data_json = data
            s.commit()
            return len(rows)

    def set_approval(self, assessment_id: str, test_id: str, status: str) -> None:
        self.set_approval_bulk(assessment_id, [test_id], status)

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

    def execution_verdicts(self, assessment_id: str) -> dict[str, int]:
        """How the runner judged each execution, counted.

        Shown on the assessment page because "0 findings" and "every test came
        back BLOCKED" look identical from the outside, and only one of them means
        the target held up.
        """
        with self._sf() as s:
            return {
                result: int(n) for result, n in
                s.query(ExecutionRow.result, func.count(ExecutionRow.id))
                .filter_by(assessment_id=assessment_id)
                .group_by(ExecutionRow.result).all()
            }

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

    def get_execution(self, assessment_id: str, execution_id: str) -> Execution | None:
        """One execution by its id, for acting on a single row of the log.

        Takes the LAST matching row rather than the first. Execution ids are
        minted to be unique, but a duplicate must resolve to the most recent
        record — silently acting on a superseded copy is the one outcome that
        would make a targeted re-run report on the wrong evidence.
        """
        with self._sf() as s:
            row = (
                s.query(ExecutionRow)
                .filter_by(assessment_id=assessment_id, execution_id=execution_id)
                .order_by(ExecutionRow.id.desc()).first()
            )
            return Execution.model_validate(row.data_json) if row else None

    def save_findings(self, assessment_id: str, findings: list[Finding]) -> None:
        with self._sf() as s:
            for f in findings:
                s.add(FindingRow(
                    assessment_id=assessment_id, finding_id=f.finding_id,
                    severity=f.severity.value, data_json=f.model_dump(mode="json"),
                ))
            s.commit()

    def replace_findings(self, assessment_id: str, findings: list[Finding]) -> None:
        """Findings are derived state — the current read of every execution this
        assessment holds — so a re-run recomputes them rather than appending.

        Appending was silently wrong: `build_findings` numbers findings
        SEC-001.. from scratch each time, so a second run produced a second
        SEC-001 and every report, export and Jira comment counted the same
        finding twice.
        """
        with self._sf() as s:
            s.query(FindingRow).filter_by(assessment_id=assessment_id).delete()
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

    # -- agent records ------------------------------------------------------
    #
    # What a reviewing agent said about a plan, and how a run was assessed.
    # Append-only per kind: a review of the plan as it stood when the tester
    # approved it is evidence about that decision, and overwriting it when the
    # plan is regenerated would leave the approval unexplained.

    def save_agent_record(self, assessment_id: str, kind: str, payload: dict) -> None:
        with self._sf() as s:
            s.add(AgentRecordRow(assessment_id=assessment_id, kind=kind, data_json=payload))
            s.commit()

    def _latest_agent_record(self, assessment_id: str, kind: str) -> dict | None:
        with self._sf() as s:
            row = (
                s.query(AgentRecordRow)
                .filter_by(assessment_id=assessment_id, kind=kind)
                # id, not created_at: SQLite's CURRENT_TIMESTAMP has one-second
                # resolution, so two records written in the same second (a review
                # and its post-revision re-review) order arbitrarily by time and
                # the wrong one wins.
                .order_by(AgentRecordRow.id.desc())
                .first()
            )
            return dict(row.data_json) if row else None

    def get_plan_review(self, assessment_id: str) -> PlanReview | None:
        payload = self._latest_agent_record(assessment_id, "plan_review")
        if payload is None:
            return None
        try:
            return PlanReview.model_validate(payload)
        except ValidationError:
            # A record written by an older schema is history, not a reason to
            # 500 the assessment page it is attached to.
            return None

    def save_plan_review(self, assessment_id: str, review: PlanReview) -> None:
        self.save_agent_record(assessment_id, "plan_review", review.model_dump(mode="json"))

    def get_run_assessment(self, assessment_id: str) -> RunAssessment | None:
        payload = self._latest_agent_record(assessment_id, "run_assessment")
        if payload is None:
            return None
        try:
            return RunAssessment.model_validate(payload)
        except ValidationError:
            return None

    def save_run_assessment(self, assessment_id: str, assessment: RunAssessment) -> None:
        self.save_agent_record(assessment_id, "run_assessment",
                               assessment.model_dump(mode="json"))

    def clone_agent_records(self, source_id: str, target_id: str, kinds=("plan_review",)) -> int:
        """Carry an agent record onto a re-run's new assessment.

        A re-run copies the plan and its approvals, so the review that plan was
        approved against belongs with it. The run assessment deliberately does
        not come along: it describes executions the new assessment has not
        performed.
        """
        copied = 0
        with self._sf() as s:
            for kind in kinds:
                row = (
                    s.query(AgentRecordRow)
                    .filter_by(assessment_id=source_id, kind=kind)
                    .order_by(AgentRecordRow.id.desc())
                    .first()
                )
                if row is None:
                    continue
                s.add(AgentRecordRow(assessment_id=target_id, kind=kind,
                                     data_json=dict(row.data_json)))
                copied += 1
            s.commit()
        return copied

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


def _test_fingerprint(data: dict) -> str:
    """Order-insensitive equality check for a test case's stored JSON."""
    return json.dumps(data, sort_keys=True, default=str)
