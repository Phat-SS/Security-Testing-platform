"""Orchestrator — the end-to-end workflow, wired to persistence.

    import → analyze → design (+ transpile PoCs) → coverage → [approve] →
    scope-validated execution → findings → report → Jira comment

Each state transition is persisted and audited. Nothing executes without
approval; nothing leaves scope. This is the object the API layer and the CLI
both drive.
"""

from __future__ import annotations

import uuid

from app.analysis import TestDesigner, build_analyzer
from app.core.config import Settings
from app.core.scope import ScopeValidator
from app.database.repository import Repository
from app.execution.evidence import verify_chain
from app.execution.http_runner import HttpRunner
from app.owasp.coverage import (
    apply_coverage_to_analysis,
    compute_coverage,
    coverage_summary,
)
from app.pipeline.findings import build_findings, leads
from app.poc.transpiler import to_test_cases, transpile_curl, transpile_python
from app.reporting.html import render_report
from app.schemas.enums import ApprovalStatus
from app.vault.personas import PersonaVault


class Orchestrator:
    def __init__(self, repo: Repository, jira_client, analyzer=None, designer: TestDesigner | None = None):
        self._repo = repo
        self._jira = jira_client
        self._analyzer = analyzer or build_analyzer()
        self._designer = designer or TestDesigner()

    def set_jira_client(self, jira_client) -> None:
        """Swap the Jira client after construction (used when a live MCP server
        turns out to be unreachable and the app falls back to the mock)."""
        self._jira = jira_client

    # 1-2. import + analyze -------------------------------------------------

    async def import_and_analyze(self, issue_key: str) -> str:
        issue = await self._jira.get_issue(issue_key)
        assessment_id = f"A-{uuid.uuid4().hex[:10]}"
        self._repo.create_assessment(assessment_id, issue.issue_key, issue.project_key)
        self._repo.audit("import_issue", assessment_id, detail=issue.issue_key)

        analysis = self._analyzer.analyze(issue)
        self._repo.save_analysis(assessment_id, analysis)
        self._repo.audit("analyze", assessment_id,
                         detail=f"{len(analysis.endpoints)} endpoints, "
                                f"{len(analysis.applicable_categories())} applicable categories")
        return assessment_id

    # 3-4. design tests + transpile PoCs + coverage -------------------------

    def design(self, assessment_id: str, poc_python: str | None = None,
               poc_curl: str | None = None, poc_postman: str | None = None,
               burp_xml: str | None = None, jmeter_xml: str | None = None) -> list:
        from app.schemas.analysis import IssueAnalysis

        assessment = self._repo.get_assessment(assessment_id)
        analysis = IssueAnalysis.model_validate(assessment.analysis_json)

        generated = self._designer.design(analysis)

        # Transpile any provided PoC into scoped, PENDING test cases. Never run.
        poc_tests = []
        if poc_python:
            r = transpile_python(poc_python)
            poc_tests += to_test_cases(r)
            if not r.is_safe:
                self._repo.audit("poc_flagged", assessment_id,
                                 detail=f"dangerous constructs: {r.dangerous_constructs}")
        if poc_curl:
            poc_tests += to_test_cases(transpile_curl(poc_curl))
        if poc_postman:
            from app.poc.postman import postman_to_test_cases

            poc_tests += postman_to_test_cases(poc_postman)
        if burp_xml:
            from app.adapters.burp import burp_to_test_cases

            poc_tests += burp_to_test_cases(burp_xml)
        if jmeter_xml:
            from app.adapters.jmeter import jmeter_to_test_cases

            poc_tests += jmeter_to_test_cases(jmeter_xml)

        all_tests = poc_tests + generated
        self._repo.save_test_cases(assessment_id, all_tests)

        rows = compute_coverage(analysis, existing_poc_tests=poc_tests, generated_tests=generated)
        apply_coverage_to_analysis(analysis, rows)
        self._repo.save_analysis(assessment_id, analysis)
        self._repo.save_coverage(assessment_id, [r.__dict__ | {"category": r.category.value} for r in rows])
        self._repo.audit("design_tests", assessment_id,
                         detail=f"{len(all_tests)} tests ({len(poc_tests)} from PoC)")
        return all_tests

    # 5. approval -----------------------------------------------------------

    def approve(self, assessment_id: str, test_ids: list[str], actor: str = "tester") -> None:
        for tid in test_ids:
            self._repo.set_approval(assessment_id, tid, ApprovalStatus.APPROVED.value)
        self._repo.audit("approve", assessment_id, actor=actor, detail=f"approved {test_ids}")

    def reject(self, assessment_id: str, test_ids: list[str], actor: str = "tester") -> None:
        for tid in test_ids:
            self._repo.set_approval(assessment_id, tid, ApprovalStatus.REJECTED.value)
        self._repo.audit("reject", assessment_id, actor=actor, detail=f"rejected {test_ids}")

    # 6. scope-validated execution -----------------------------------------

    def execute(
        self,
        assessment_id: str,
        base_url: str,
        scope: ScopeValidator,
        vault: PersonaVault,
        settings: Settings | None = None,
        client=None,
        include_destructive: bool = False,
    ) -> list:
        settings = settings or Settings.from_env()
        self._repo.set_target(assessment_id, base_url)
        runner = HttpRunner(base_url, scope, vault, settings, client=client)

        tests = [t for t in self._repo.get_test_cases(assessment_id) if t.is_runnable()]
        if not include_destructive:
            tests = [t for t in tests if not t.is_destructive]

        executions = []
        prev_hash = None
        for t in tests:
            ex = runner.run(t, execution_id=f"{assessment_id}-{t.test_id}", prev_hash=prev_hash)
            prev_hash = ex.evidence_hash
            executions.append(ex)

        self._repo.save_executions(assessment_id, executions)
        chain_ok = verify_chain(executions)
        self._repo.audit("execute", assessment_id,
                         detail=f"{len(executions)} executed; evidence_chain_ok={chain_ok}")

        findings = build_findings({t.test_id: t for t in tests}, executions)
        self._repo.save_findings(assessment_id, findings)
        self._repo.audit("findings", assessment_id,
                         detail=f"{len(findings)} findings, {len(leads({}, executions))} inconclusive")
        return executions

    # 7. report -------------------------------------------------------------

    def build_report_html(self, assessment_id: str) -> str:
        assessment = self._repo.get_assessment(assessment_id)
        tests = {t.test_id: t for t in self._repo.get_test_cases(assessment_id)}
        executions = self._repo.get_executions(assessment_id)
        findings = self._repo.get_findings(assessment_id)
        html = render_report(
            title=f"Security Assessment — {assessment.issue_key}",
            target=assessment.target_base_url or "(not executed)",
            tests=tests, executions=executions, findings=findings,
            coverage_rows=assessment.coverage_json,
        )
        self._repo.audit("report", assessment_id, detail="html report generated")
        return html

    # regression: diff this assessment's findings against the previous run -----

    def regression_diff(self, assessment_id: str):
        """Compare this assessment's findings to the most recent prior run of the
        same issue. Returns (FindingDiff, previous_assessment_id | None)."""
        from app.pipeline.history import diff_findings

        current = self._repo.get_assessment(assessment_id)
        prev = self._repo.previous_assessment_for_issue(current.issue_key, assessment_id)
        curr_findings = self._repo.get_findings(assessment_id)
        if not prev:
            from app.pipeline.history import FindingDiff

            return FindingDiff(new=curr_findings), None
        prev_findings = self._repo.get_findings(prev.id)
        diff = diff_findings(prev_findings, curr_findings)
        self._repo.audit("regression_diff", assessment_id,
                         detail=f"vs {prev.id}: {diff.summary()}")
        return diff, prev.id

    def export_json(self, assessment_id: str) -> str:
        from app.reporting.exports import export_json as _json

        a = self._repo.get_assessment(assessment_id)
        return _json(a.issue_key, a.target_base_url or "(not executed)",
                     self._repo.get_test_cases(assessment_id),
                     self._repo.get_executions(assessment_id),
                     self._repo.get_findings(assessment_id), a.coverage_json)

    def export_xlsx(self, assessment_id: str) -> bytes:
        from app.reporting.exports import export_xlsx as _xlsx

        a = self._repo.get_assessment(assessment_id)
        return _xlsx(a.issue_key, a.target_base_url or "(not executed)",
                     self._repo.get_test_cases(assessment_id),
                     self._repo.get_executions(assessment_id),
                     self._repo.get_findings(assessment_id), a.coverage_json)

    def export_pdf(self, assessment_id: str) -> bytes:
        from app.reporting.pdf import export_pdf as _pdf

        a = self._repo.get_assessment(assessment_id)
        return _pdf(a.issue_key, a.target_base_url or "(not executed)",
                    self._repo.get_test_cases(assessment_id),
                    self._repo.get_executions(assessment_id),
                    self._repo.get_findings(assessment_id), a.coverage_json)

    def export_postman(self, assessment_id: str) -> str:
        from app.adapters.postman_export import export_postman_collection

        a = self._repo.get_assessment(assessment_id)
        approved = [t for t in self._repo.get_test_cases(assessment_id) if t.is_runnable()]
        return export_postman_collection(f"{a.issue_key} security tests", approved or
                                         self._repo.get_test_cases(assessment_id))

    # 8. Jira comment (preview → confirm) -----------------------------------

    def comment_preview(self, assessment_id: str) -> str:
        assessment = self._repo.get_assessment(assessment_id)
        executions = self._repo.get_executions(assessment_id)
        findings = self._repo.get_findings(assessment_id)
        from collections import Counter

        counts = Counter(e.verdict.result.value for e in executions)
        lines = [
            f"*Security Testing Completed — {assessment.issue_key}*",
            f"Tests: {len(executions)} | "
            f"PASS: {counts.get('PASS',0)} | FAIL: {counts.get('FAIL',0)} | "
            f"INCONCLUSIVE: {counts.get('INCONCLUSIVE',0)} | BLOCKED: {counts.get('BLOCKED',0)}",
            "",
            "Findings:",
        ]
        if findings:
            for f in findings:
                lines.append(f"- {f.finding_id} — {f.title} — {f.severity.value} — {f.endpoint}")
        else:
            lines.append("- No confirmed findings.")
        lines.append("\n_Evidence chain verified. Full report attached._")
        return "\n".join(lines)

    async def post_comment(self, assessment_id: str, actor: str = "tester") -> str:
        assessment = self._repo.get_assessment(assessment_id)
        comment = self.comment_preview(assessment_id)
        await self._jira.add_comment(assessment.issue_key, comment)
        self._repo.audit("jira_comment", assessment_id, actor=actor,
                         detail=f"posted to {assessment.issue_key}")
        return comment
