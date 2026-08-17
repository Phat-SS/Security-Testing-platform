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
from app.poc.jira_extract import combined_poc_source, extract_poc_scripts
from app.poc.transpiler import to_test_cases, transpile_curl, transpile_python
from app.reporting.html import render_report
from app.schemas.enums import ApprovalStatus
from app.schemas.testcase import RequestSpec
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

        # A PoC embedded directly in the issue description (filename line +
        # fenced ```python block, as filed by e.g. an automated bounty-hunter
        # tool) is detected and surfaced — pre-filled into the Design step's
        # PoC textarea — but never transpiled/designed automatically. A human
        # still has to look at the extracted code and click "Generate test
        # plan" before it becomes a test case; this is a proposal, not an
        # auto-applied action. Tickets with no embedded PoC are unaffected.
        # Set on `analysis` before the single save below, not as a second
        # write after — a second save_analysis() call would leave a window
        # where a concurrent read sees the row without detected_poc_source.
        poc_source = combined_poc_source(issue.description)
        if poc_source:
            analysis.detected_poc_source = poc_source

        self._repo.save_analysis(assessment_id, analysis)
        self._repo.audit("analyze", assessment_id,
                         detail=f"{len(analysis.endpoints)} endpoints, "
                                f"{len(analysis.applicable_categories())} applicable categories")
        if poc_source:
            self._repo.audit("poc_detected", assessment_id,
                             detail=f"{len(extract_poc_scripts(issue.description))} "
                                    "script(s) found in issue description, pending review")
        return assessment_id

    def delete_assessment(self, assessment_id: str, actor: str = "tester") -> None:
        assessment = self._repo.get_assessment(assessment_id)
        issue_key = assessment.issue_key if assessment else assessment_id
        self._repo.delete_assessment(assessment_id)
        # Deliberately audited *after* the assessment row is gone: AuditLog has
        # no FK to Assessment, so the trail survives the delete it describes.
        self._repo.audit("delete_assessment", assessment_id, actor=actor, detail=issue_key)

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

    def edit_test_request(self, assessment_id: str, test_id: str, request: RequestSpec,
                          actor: str = "tester") -> bool:
        """A human editing a test's request before it runs — still declarative
        data through the same trusted runner, never code, so this doesn't
        touch the transpiler's no-code-execution boundary. Resets approval to
        PENDING (enforced in the repository) since the edited request has not
        itself been reviewed."""
        ok = self._repo.update_test_request(assessment_id, test_id, request.model_dump(mode="json"))
        if ok:
            self._repo.audit("edit_test_request", assessment_id, actor=actor,
                             detail=f"{test_id}: {request.method} {request.path} (approval reset to PENDING)")
        return ok

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

        # Seed the hash chain from the last persisted execution, so the
        # tamper-evident chain spans this assessment's full history, not just
        # this one run — otherwise deleting or rewriting an earlier run's
        # rows verifies fine as an innocent fresh None-rooted chain.
        prior = self._repo.get_executions(assessment_id)
        prev_hash = prior[-1].evidence_hash if prior else None

        executions = []
        for t in tests:
            # run_safe (not run): one test raising an unexpected exception
            # (e.g. a persona missing from the vault) must not discard every
            # execution already computed earlier in this same batch.
            ex = runner.run_safe(t, execution_id=f"{assessment_id}-{t.test_id}", prev_hash=prev_hash)
            prev_hash = ex.evidence_hash
            executions.append(ex)

        self._repo.save_executions(assessment_id, executions)
        chain_ok = verify_chain(prior + executions)
        self._repo.audit("execute", assessment_id,
                         detail=f"{len(executions)} executed; evidence_chain_ok={chain_ok}; "
                                f"include_destructive={include_destructive}")

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
        # Re-verify at the point evidence is actually read, not just once at
        # execute() time: a hash computed correctly during the run says
        # nothing about whether the DB rows were edited afterwards.
        chain_ok = verify_chain(executions)
        html = render_report(
            title=f"Security Assessment — {assessment.issue_key}",
            target=assessment.target_base_url or "(not executed)",
            tests=tests, executions=executions, findings=findings,
            coverage_rows=assessment.coverage_json,
            assessment_id=assessment_id, issue_key=assessment.issue_key,
            evidence_chain_ok=chain_ok,
        )
        self._repo.audit("report", assessment_id, detail=f"html report generated; evidence_chain_ok={chain_ok}")
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

    # Colored-circle emoji instead of a {color} macro: the addCommentToJiraIssue
    # MCP tool converts standard Markdown to ADF, not legacy Jira wiki markup —
    # h2./||tables||/{color} all rendered as dead literal text in practice, while
    # plain CommonMark (_italic_, **bold**, GFM tables, backtick code) works. An
    # emoji renders as a real glyph regardless of markup support, so it's a color
    # cue that can't fail to render the way a markup-dependent macro can.
    _SEV_EMOJI = {
        "CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
        "LOW": "\U0001F7E2", "INFO": "⚪",
    }

    def comment_preview(self, assessment_id: str) -> str:
        """Standard Markdown (CommonMark/GFM) — the addCommentToJiraIssue MCP
        tool renders this, not old Jira wiki markup (see _SEV_EMOJI docstring
        above for how that was confirmed).

        Deliberately does NOT claim a report is "attached": no MCP tool this
        connector calls can upload a file to a Jira issue (get_attachments()
        is a stub that always returns [] — there was never a write-side
        counterpart), so a prior version of this text was simply false. The
        comment is self-contained instead: full result table + a findings
        table, with a plain-language pointer to the platform for raw evidence.
        """
        assessment = self._repo.get_assessment(assessment_id)
        executions = self._repo.get_executions(assessment_id)
        findings = self._repo.get_findings(assessment_id)
        from collections import Counter

        counts = Counter(e.verdict.result.value for e in executions)
        target = assessment.target_base_url or "(not executed)"
        fail_n = counts.get("FAIL", 0)
        lines = [
            f"## Security Testing Completed — {assessment.issue_key}",
            f"Environment tested: `{target}`",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| Total tests | {len(executions)} |",
            f"| PASS | {counts.get('PASS', 0)} |",
            f"| FAIL | {f'**{fail_n}**' if fail_n else fail_n} |",
            f"| INCONCLUSIVE | {counts.get('INCONCLUSIVE', 0)} |",
            f"| BLOCKED | {counts.get('BLOCKED', 0)} |",
            "",
            "### Findings",
        ]
        if findings:
            lines.append("| ID | Title | Severity | Endpoint |")
            lines.append("|---|---|---|---|")
            for f in findings:
                emoji = self._SEV_EMOJI.get(f.severity.value, "")
                lines.append(f"| {f.finding_id} | {f.title} | {emoji} **{f.severity.value}** | `{f.endpoint}` |")
        else:
            lines.append("No confirmed findings.")
        lines.append("")
        if executions and not verify_chain(executions):
            lines.append(
                f"_⚠️ Evidence chain FAILED verification for {len(executions)} execution(s) — "
                "at least one record's hash no longer matches its content. Treat this result "
                "as non-authoritative until investigated in the security testing platform._"
            )
        else:
            lines.append(
                f"_Evidence chain verified — {len(executions)} execution(s) sealed with a "
                "SHA-256 hash chain. Full request/response evidence and reproduction steps "
                "are in the security testing platform's report for this assessment._"
            )
        return "\n".join(lines)

    async def post_comment(self, assessment_id: str, actor: str = "tester") -> str:
        assessment = self._repo.get_assessment(assessment_id)
        comment = self.comment_preview(assessment_id)
        await self._jira.add_comment(assessment.issue_key, comment)
        self._repo.audit("jira_comment", assessment_id, actor=actor,
                         detail=f"posted to {assessment.issue_key}")
        return comment
