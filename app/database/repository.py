"""Repository — the only place that talks to the ORM.

Converts between Pydantic domain objects and rows. Everything above this layer
works in Pydantic models; everything below is storage detail.
"""

from __future__ import annotations

import json
import uuid

from typing import ClassVar

from pydantic import ValidationError
from sqlalchemy import case, func, or_
from sqlalchemy.exc import IntegrityError

from app.database.models import (
    AgentRecordRow,
    Assessment,
    AuditLog,
    ExecutionRow,
    FindingRow,
    JobRow,
    RunSnapshotRow,
    TestCaseRow,
)
from app.schemas.agent import PlanReview, RunAssessment
from app.schemas.analysis import IssueAnalysis
from app.schemas.decision import DerivedVerdictEvent
from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.job import Job
from app.schemas.manifest import ReportManifest
from app.schemas.testcase import DESTRUCTIVE_METHODS, TestCase, is_destructive_mutation


# Approval states that represent a decision a person made about a specific test.
# PENDING is the absence of one, so it is never carried across a regeneration.
_HUMAN_DECISIONS = {"APPROVED", "REJECTED", "DISABLED"}


def _job_from_row(row: JobRow) -> Job:
    return Job(
        job_id=row.job_id, assessment_id=row.assessment_id, kind=row.kind,
        state=row.state, idempotency_key=row.idempotency_key,
        result=dict(row.result_json or {}), error=row.error or "",
        created_at=row.created_at, updated_at=row.updated_at,
    )


def _belongs_to(engagement: str):
    """Rows of the named engagement, plus the ones that were never stamped.

    Assessments created before the engagement was recorded at import — and any
    created by an import path that forgot to pass it — carry an empty string.
    Matching on equality alone made them exist in the database and nowhere in
    the UI: /findings and /activity came up empty on an engagement full of
    work. An unstamped row belongs to whoever is looking, which is the rule the
    single-assessment screens already follow by not filtering at all.
    """
    return or_(Assessment.engagement == engagement,
               Assessment.engagement == "",
               Assessment.engagement.is_(None))


class Repository:
    #: Bounded, and cleared wholesale rather than evicted one at a time: the
    #: entries are a few bytes each and the cost of a miss is one indexed
    #: primary-key lookup.
    _ENGAGEMENT_CACHE_MAX = 512

    def __init__(self, session_factory) -> None:
        self._sf = session_factory
        self._engagement_of: dict[str, str] = {}

    # -- assessments --------------------------------------------------------

    def create_assessment(self, assessment_id: str, issue_key: str, project_key: str,
                          engagement: str = "") -> None:
        with self._sf() as s:
            s.add(Assessment(id=assessment_id, issue_key=issue_key,
                             project_key=project_key, engagement=engagement))
            s.commit()

    def assessment_engagement(self, assessment_id: str) -> str:
        """Which engagement this assessment belongs to, or "" for one created
        before there could be more than one.

        Cached, because the engagement middleware asks on every request under
        `/assessment/...` — including the run panel's poll, which fires every
        1.5 seconds while a run is in flight. The answer is written once at
        import and never changes afterwards, so there is nothing to invalidate;
        a bounded dict keeps a long-lived process from accumulating one entry
        per assessment forever.
        """
        cached = self._engagement_of.get(assessment_id)
        if cached is not None:
            return cached
        with self._sf() as s:
            row = s.get(Assessment, assessment_id)
            if row is None:
                # Not cached: an id that does not exist yet may exist in a
                # moment (a newly created assessment, a racing request), and a
                # cached "" would outlive that.
                return ""
            answer = row.engagement or ""
        if len(self._engagement_of) >= self._ENGAGEMENT_CACHE_MAX:
            self._engagement_of.clear()
        self._engagement_of[assessment_id] = answer
        return answer

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
                data = t.model_dump(mode="json")
                s.add(TestCaseRow(
                    assessment_id=assessment_id, test_id=t.test_id,
                    owasp_category=t.owasp_category.value,
                    approval_status=t.approval_status.value,
                    data_json=data,
                    **_derived_columns(data),
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
                    **_derived_columns(data),
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
            mutation = data.get("attack_mutation") or {}
            data["is_destructive"] = bool(data.get("is_destructive")) or (
                str(request_json.get("method", "")).upper() in DESTRUCTIVE_METHODS
                or is_destructive_mutation(str(mutation.get("kind", "")), mutation.get("detail"))
            )
            row.approval_status = "PENDING"
            row.data_json = data
            for col, value in _derived_columns(data).items():
                setattr(row, col, value)
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
    # category/approval_status/severity/is_destructive/source/path are all real
    # (indexed, for the first four) columns — filter, sort AND pagination run in
    # SQL, and only the one page's rows are ever validated into TestCase objects.
    # A 400-test plan was previously paying for 400 pydantic validations, and a
    # full table scan in Python, on every render.

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
            filtered = (
                s.query(TestCaseRow)
                .filter(TestCaseRow.assessment_id == assessment_id)
            )
            if cat:
                filtered = filtered.filter(TestCaseRow.owasp_category == cat)
            if appr:
                filtered = filtered.filter(TestCaseRow.approval_status == appr)
            if sev:
                filtered = filtered.filter(TestCaseRow.severity == sev)
            if src:
                filtered = filtered.filter(TestCaseRow.source == src)
            if dest in ("yes", "no"):
                filtered = filtered.filter(TestCaseRow.is_destructive == (dest == "yes"))
            needle = q.strip().lower()
            if needle:
                filtered = filtered.filter(TestCaseRow.search_text.contains(needle))

            total = filtered.count()
            matched_ids = [
                tid for (tid,) in
                filtered.with_entities(TestCaseRow.test_id).order_by(TestCaseRow.id).all()
            ]

            per = max(1, min(per, 500))
            pages = max(1, -(-total // per))
            page = max(1, min(page, pages))
            page_rows = (
                self._sorted_query(filtered, sort)
                .offset((page - 1) * per).limit(per).all()
            )

            facets, meta = self._facets(assessment_id, s)

        return {
            "tests": [TestCase.model_validate(r.data_json) for r in page_rows],
            "matched_ids": matched_ids,
            "total": total,
            "unfiltered_total": meta["total"],
            "page": page,
            "pages": pages,
            "per": per,
            "facets": facets,
            # Plan-wide counts, computed once via the same aggregate queries
            # the facets need, so the page does not have to load and validate
            # every test again just to say how many are approved.
            "meta": meta,
        }

    @classmethod
    def _sorted_query(cls, query, sort: str):
        if sort == "sev":
            rank = case(*[(TestCaseRow.severity == k, v) for k, v in cls._SEVERITY_ORDER.items()],
                        else_=len(cls._SEVERITY_ORDER))
            return query.order_by(rank, TestCaseRow.id)
        if sort == "appr":
            rank = case(*[(TestCaseRow.approval_status == k, v) for k, v in cls._APPROVAL_ORDER.items()],
                        else_=len(cls._APPROVAL_ORDER))
            return query.order_by(rank, TestCaseRow.id)
        if sort == "cat":
            return query.order_by(TestCaseRow.owasp_category, TestCaseRow.id)
        if sort == "endpoint":
            return query.order_by(TestCaseRow.path, TestCaseRow.id)
        return query.order_by(TestCaseRow.id)  # "id" — generation order, already grouped by category

    @staticmethod
    def _facets(assessment_id: str, session) -> tuple[dict, dict]:
        """Counts per filter value over the *unfiltered* plan, so a dropdown can
        say how many rows each option would leave and never offer an option that
        matches nothing — plus the plan-wide totals the page header needs.

        Six small GROUP BY/COUNT aggregate queries, run by the database, instead
        of loading and deserializing every row's JSON to count in Python."""

        def counts(column) -> dict[str, int]:
            rows = (
                session.query(column, func.count(TestCaseRow.id))
                .filter(TestCaseRow.assessment_id == assessment_id, column != "")
                .group_by(column)
                .all()
            )
            return {str(value): int(n) for value, n in rows}

        dest_rows = (
            session.query(TestCaseRow.is_destructive, func.count(TestCaseRow.id))
            .filter(TestCaseRow.assessment_id == assessment_id)
            .group_by(TestCaseRow.is_destructive)
            .all()
        )
        out = {
            "cat": counts(TestCaseRow.owasp_category),
            "sev": counts(TestCaseRow.severity),
            "appr": counts(TestCaseRow.approval_status),
            "src": counts(TestCaseRow.source),
            "dest": {("yes" if is_dest else "no"): int(n) for is_dest, n in dest_rows},
        }

        total = (
            session.query(func.count(TestCaseRow.id))
            .filter(TestCaseRow.assessment_id == assessment_id).scalar() or 0
        )
        approved_destructive = (
            session.query(func.count(TestCaseRow.id))
            .filter(TestCaseRow.assessment_id == assessment_id,
                    TestCaseRow.approval_status == "APPROVED",
                    TestCaseRow.is_destructive.is_(True))
            .scalar() or 0
        )
        meta = {
            "total": int(total),
            "approved": out["appr"].get("APPROVED", 0),
            "rejected": out["appr"].get("REJECTED", 0),
            "pending": out["appr"].get("PENDING", 0),
            "approved_destructive": int(approved_destructive),
        }
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

    def get_agent_records(self, assessment_id: str, kind: str) -> list[dict]:
        """All records of a kind in append order, for auditable event streams."""
        with self._sf() as s:
            rows = (
                s.query(AgentRecordRow)
                .filter_by(assessment_id=assessment_id, kind=kind)
                .order_by(AgentRecordRow.id.asc())
                .all()
            )
            return [dict(row.data_json) for row in rows]

    def get_derived_verdicts(self, assessment_id: str) -> list[DerivedVerdictEvent]:
        events: list[DerivedVerdictEvent] = []
        for payload in self.get_agent_records(assessment_id, "derived_verdict"):
            try:
                events.append(DerivedVerdictEvent.model_validate(payload))
            except ValidationError:
                continue
        return events

    def save_derived_verdict(self, assessment_id: str, event: DerivedVerdictEvent) -> bool:
        """Append once; deterministic event ids make repeated review idempotent."""
        existing = {item.event_id for item in self.get_derived_verdicts(assessment_id)}
        if event.event_id in existing:
            return False
        self.save_agent_record(assessment_id, "derived_verdict", event.model_dump(mode="json"))
        return True

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

    def get_report_manifest(self, assessment_id: str) -> ReportManifest | None:
        payload = self._latest_agent_record(assessment_id, "report_manifest")
        if payload is None:
            return None
        try:
            return ReportManifest.model_validate(payload)
        except ValidationError:
            return None

    def save_report_manifest(self, assessment_id: str, manifest: ReportManifest) -> None:
        self.save_agent_record(
            assessment_id, "report_manifest", manifest.model_dump(mode="json")
        )

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

    # -- persistent jobs ---------------------------------------------------

    def create_job(
        self, assessment_id: str, kind: str, idempotency_key: str
    ) -> tuple[Job, bool]:
        """Create QUEUED once; return the existing job on a duplicate request."""
        with self._sf() as s:
            existing = s.query(JobRow).filter_by(
                assessment_id=assessment_id, kind=kind, idempotency_key=idempotency_key
            ).first()
            if existing is not None:
                return _job_from_row(existing), False
            row = JobRow(
                job_id=f"J-{uuid.uuid4().hex}", assessment_id=assessment_id,
                kind=kind, state="QUEUED", idempotency_key=idempotency_key,
                result_json={}, error="",
            )
            s.add(row)
            try:
                s.commit()
            except IntegrityError:
                s.rollback()
                existing = s.query(JobRow).filter_by(
                    assessment_id=assessment_id, kind=kind, idempotency_key=idempotency_key
                ).one()
                return _job_from_row(existing), False
            s.refresh(row)
            return _job_from_row(row), True

    def transition_job(
        self, job_id: str, state: str, *, result: dict | None = None, error: str = ""
    ) -> Job:
        allowed = {
            "QUEUED": {"RUNNING", "FAILED"},
            "RUNNING": {"SUCCEEDED", "FAILED"},
            "SUCCEEDED": set(),
            "FAILED": set(),
        }
        with self._sf() as s:
            row = s.query(JobRow).filter_by(job_id=job_id).one()
            if state not in allowed.get(row.state, set()):
                raise ValueError(f"Invalid job transition {row.state} -> {state}")
            row.state = state
            if result is not None:
                row.result_json = result
            row.error = error
            s.commit()
            s.refresh(row)
            return _job_from_row(row)

    def set_job_progress(self, job_id: str, progress: dict) -> None:
        """Update a RUNNING job's `result` without touching its state.

        Separate from `transition_job` on purpose: progress is written many
        times during one run, and routing it through the state machine would
        mean either a no-op transition (RUNNING -> RUNNING is not allowed) or
        loosening the machine that keeps a SUCCEEDED job from being reopened.
        """
        with self._sf() as s:
            row = s.query(JobRow).filter_by(job_id=job_id).first()
            if row is None or row.state != "RUNNING":
                return
            row.result_json = progress
            s.commit()

    def latest_job(self, assessment_id: str, kind: str) -> Job | None:
        """The most recent job of this kind, which is what the page polls: a
        run started in another tab is still this assessment's run."""
        with self._sf() as s:
            row = (
                s.query(JobRow).filter_by(assessment_id=assessment_id, kind=kind)
                .order_by(JobRow.created_at.desc(), JobRow.id.desc()).first()
            )
            return _job_from_row(row) if row else None

    # -- the authorization a run was sent under -----------------------------

    def save_run_snapshot(self, assessment_id: str, fingerprint: str, data: dict) -> None:
        """Record the context, once per distinct configuration.

        Idempotent on the fingerprint: an unchanged engagement re-run twenty
        times is one authorization, not twenty. Two callers racing the same
        insert is the ordinary case here (a re-run starting while the first run
        finishes), so the duplicate is caught rather than prevented.
        """
        with self._sf() as s:
            existing = s.query(RunSnapshotRow).filter_by(
                assessment_id=assessment_id, fingerprint=fingerprint
            ).first()
            if existing is not None:
                return
            s.add(RunSnapshotRow(assessment_id=assessment_id, fingerprint=fingerprint,
                                 data_json=data))
            try:
                s.commit()
            except IntegrityError:
                s.rollback()

    def get_run_snapshot(self, assessment_id: str, fingerprint: str) -> dict | None:
        if not fingerprint:
            return None
        with self._sf() as s:
            row = s.query(RunSnapshotRow).filter_by(
                assessment_id=assessment_id, fingerprint=fingerprint
            ).first()
            return dict(row.data_json or {}) if row else None

    def latest_run_snapshot(self, assessment_id: str) -> dict | None:
        with self._sf() as s:
            row = (
                s.query(RunSnapshotRow).filter_by(assessment_id=assessment_id)
                .order_by(RunSnapshotRow.created_at.desc(), RunSnapshotRow.id.desc()).first()
            )
            return dict(row.data_json or {}) if row else None

    def fail_orphaned_jobs(self, error: str) -> int:
        """Settle every job left RUNNING by a process that is no longer here.

        A run lives in a background task, so a restart — a deploy, a crash, the
        shutdown button — leaves its row RUNNING with nothing to advance it.
        The page polls that row, so the job would otherwise be reported as in
        flight forever. Called once at startup, where "any RUNNING job belongs
        to a dead process" is true by construction: this process has not
        started one yet.
        """
        with self._sf() as s:
            rows = s.query(JobRow).filter_by(state="RUNNING").all()
            for row in rows:
                row.state = "FAILED"
                row.error = error
            if rows:
                s.commit()
            return len(rows)

    def get_job(self, job_id: str) -> Job | None:
        with self._sf() as s:
            row = s.query(JobRow).filter_by(job_id=job_id).first()
            return _job_from_row(row) if row else None

    # -- audit --------------------------------------------------------------

    def audit(self, action: str, assessment_id: str = "", actor: str = "system", detail: str = "") -> None:
        with self._sf() as s:
            s.add(AuditLog(actor=actor, action=action, assessment_id=assessment_id, detail=detail))
            s.commit()

    def findings_across(self, engagement: str = "", limit: int = 500) -> list[tuple]:
        """Every confirmed finding on this engagement, newest assessment first.

        `(assessment_id, issue_key, finding)`. One query rather than a loop over
        assessments: a findings screen that issues N+1 queries stops being
        openable on the engagement it matters most for.
        """
        with self._sf() as s:
            q = (
                s.query(FindingRow, Assessment)
                .join(Assessment, Assessment.id == FindingRow.assessment_id)
                .order_by(Assessment.created_at.desc(), FindingRow.id.asc())
            )
            if engagement:
                q = q.filter(_belongs_to(engagement))
            return [
                (row.assessment_id, a.issue_key, Finding.model_validate(row.data_json))
                for row, a in q.limit(limit).all()
            ]

    def recent_activity(self, engagement: str = "", limit: int = 200) -> list[tuple]:
        """The audit log, across assessments. `(entry, issue_key)`.

        The log has always recorded who did what; nothing ever showed it. An
        audit trail nobody can read is one nobody checks.
        """
        with self._sf() as s:
            q = (
                s.query(AuditLog, Assessment)
                .outerjoin(Assessment, Assessment.id == AuditLog.assessment_id)
                .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            )
            if engagement:
                # An entry with no assessment (a config change, a quick setup) is
                # engagement-wide by nature. Filtering on the joined assessment
                # alone turned the outer join back into an inner one and dropped
                # every one of them from the log.
                q = q.filter(or_(_belongs_to(engagement), AuditLog.assessment_id == "",
                                 AuditLog.assessment_id.is_(None)))
            return [(entry, a.issue_key if a else "") for entry, a in q.limit(limit).all()]

    def get_audit(self, assessment_id: str) -> list[AuditLog]:
        with self._sf() as s:
            return list(
                s.query(AuditLog).filter_by(assessment_id=assessment_id)
                .order_by(AuditLog.created_at).all()
            )


def _test_fingerprint(data: dict) -> str:
    """Order-insensitive equality check for a test case's stored JSON.

    Normalized through the current schema first, so that ADDING a defaulted field
    to `TestCase` does not silently invalidate every approval in the database.
    Without this, a row written before the field existed lacks the key, the row
    being written has it at its default, the two blobs differ, and the next
    "Regenerate test plan" quietly resets a plan a human had already approved —
    for a schema change that altered nothing about what any test does.

    An unparseable blob (a row from a future schema, a hand-edited one) falls
    back to comparing it raw. That can only ever fail to carry an approval over,
    which is the safe direction: a test goes back to PENDING and someone reads it
    again.
    """
    try:
        normalized = TestCase.model_validate(
            {**data, "approval_status": "PENDING"}
        ).model_dump(mode="json")
        normalized.pop("approval_status", None)
    except Exception:  # noqa: BLE001 - any validation failure means "compare raw"
        normalized = data
    return json.dumps(normalized, sort_keys=True, default=str)


def _search_text(data: dict) -> str:
    """Everything `q` matches against, lowercased once at write time so a
    query never has to lowercase a plan's worth of JSON on every read."""
    request = data.get("request") or {}
    parts = (
        data.get("test_id", ""),
        data.get("title", ""),
        data.get("objective", ""),
        (data.get("attack_mutation") or {}).get("kind", ""),
        request.get("method", ""),
        request.get("path", ""),
    )
    return " ".join(str(part) for part in parts if part).lower()


def _derived_columns(data: dict) -> dict:
    """The queryable projection of a TestCase's JSON — see TestCaseRow's
    docstring. `data` is already the `mode="json"` dump (or an equivalent
    plain dict), so field values are plain strings/bools, not enums."""
    request = data.get("request") or {}
    return {
        "severity": str(data.get("severity", "")),
        "is_destructive": bool(data.get("is_destructive")),
        "source": str(data.get("source", "")),
        "path": str(request.get("path", "")),
        "search_text": _search_text(data),
    }
