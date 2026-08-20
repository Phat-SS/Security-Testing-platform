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
from app.analysis.adjudicator import assess_run, build_adjudicator, triage
from app.analysis.extractor import build_signals, map_owasp, ticket_text
from app.analysis.plan_reviewer import build_reviewer
from app.analysis.requirements import (
    extract_requirements,
    extract_requirements_from_text,
    merge_requirements,
)
from app.core.config import Settings
from app.core.scope import ScopeValidator
from app.database.repository import Repository
from app.execution.evidence import verify_chain
from app.execution.http_runner import HttpRunner
from app.owasp.coverage import (
    apply_coverage_to_analysis,
    compute_coverage,
)
from app.pipeline.findings import build_findings, leads
from app.poc.jira_extract import combined_poc_source, extract_poc_scripts
from app.poc.transpiler import to_test_cases, transpile_curl, transpile_python
from app.reporting.curl import render_curl
from app.reporting.html import render_report
from app.schemas.agent import Adjudication
from app.schemas.enums import ApprovalStatus, TestSource
from app.schemas.testcase import RequestSpec
from app.vault.personas import PersonaVault


class Orchestrator:
    def __init__(self, repo: Repository, jira_client, analyzer=None,
                 designer: TestDesigner | None = None, planner=None,
                 reviewer=None, adjudicator=None):
        self._repo = repo
        self._jira = jira_client
        self._analyzer = analyzer or build_analyzer()
        self._designer = designer or TestDesigner()
        # Optional AI attack planner. Strictly additive: when absent, the
        # deterministic designer's output is the whole plan, exactly as before.
        self._planner = planner
        # The two reviewing agents. Unlike the planner these are never None:
        # both have a deterministic half that costs nothing and needs no key —
        # a structural critique of the plan, and a triage of which undecided
        # results actually need a person. The AI half of each is what USE_AI
        # switches on.
        self._reviewer = reviewer or build_reviewer()
        self._adjudicator = adjudicator or build_adjudicator()

    def set_jira_client(self, jira_client) -> None:
        """Swap the Jira client after construction (used when a live MCP server
        turns out to be unreachable and the app falls back to the mock)."""
        self._jira = jira_client

    def set_reviewer(self, reviewer) -> None:
        """Swap the plan-reviewing agent (used by tests and by a config reload)."""
        self._reviewer = reviewer

    def set_adjudicator(self, adjudicator) -> None:
        self._adjudicator = adjudicator

    def set_planner(self, planner) -> None:
        """Attach the AI planner once the engagement's personas are known — it
        validates proposed persona names against the vault, so it cannot be
        built until the engagement config has been loaded."""
        self._planner = planner

    # 1-2. import + analyze -------------------------------------------------

    async def import_and_analyze(self, issue_key: str) -> str:
        issue = await self._jira.get_issue(issue_key)
        assessment_id = f"A-{uuid.uuid4().hex[:10]}"
        self._repo.create_assessment(assessment_id, issue.issue_key, issue.project_key)
        self._repo.audit("import_issue", assessment_id, detail=issue.issue_key)

        analysis = self._analyzer.analyze(issue)

        # An AI analyzer that fell back to the heuristic path did so silently
        # before: a bad API key, a truncated response or a schema mismatch all
        # produced a perfectly normal-looking analysis, and an operator who had
        # deliberately enabled USE_AI had no way to discover the AI never ran.
        # The reason belongs in the audit trail, where "why is this analysis
        # thinner than expected" is actually answerable.
        fallback_reason = getattr(self._analyzer, "last_fallback_reason", "")
        if fallback_reason:
            self._repo.audit("ai_fallback", assessment_id,
                             detail=f"AI analysis unavailable, used deterministic "
                                    f"analyzer instead: {fallback_reason}")

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

        # Keep the text the analysis was derived from. Editing the endpoint list
        # later has to re-derive the OWASP signals that live in prose ("bulk
        # export", "admin", "JWT") — recomputing them from endpoints alone would
        # quietly drop every one of them.
        analysis.source_text = ticket_text(issue)

        # The requirement list: the discrete things the ticket asks for. It is
        # the denominator of every "% of the ticket covered" figure downstream,
        # and it is extracted deterministically here even when the AI analyzer
        # ran — an AI analyzer that fell back leaves no requirements at all, and
        # a coverage report whose denominator silently becomes zero reads as
        # "nothing to cover" rather than "we could not tell".
        if not analysis.requirements:
            analysis.requirements = extract_requirements(issue)

        self._repo.save_analysis(assessment_id, analysis)
        self._repo.audit("analyze", assessment_id,
                         detail=f"{len(analysis.endpoints)} endpoints, "
                                f"{len(analysis.applicable_categories())} applicable categories, "
                                f"{len(analysis.requirements)} requirement item(s)")
        if poc_source:
            self._repo.audit("poc_detected", assessment_id,
                             detail=f"{len(extract_poc_scripts(issue.description))} "
                                    "script(s) found in issue description, pending review")
        return assessment_id

    async def import_and_plan(self, issue_key: str, depth: str | None = None,
                              max_rounds: int = 1, actor: str = "tester"):
        """Import, analyze, plan, review, revise — one action, ending at approval.

        The whole point of the planning agent: entering a key produces a plan a
        tester can read and approve, rather than an analysis they then have to
        press Design on. Nothing about the approval gate changes — every test
        this produces is PENDING, and nothing runs until a person says so.

        Kept separate from `import_and_analyze` rather than adding a flag to it.
        Callers that want the analysis alone (the endpoint-editing flow, the
        re-import mode, every existing test) get exactly what they always got,
        and the planning pipeline cannot start running as a side effect of a
        default someone forgot to pass.

        Returns (assessment_id, PlanReview | None).
        """
        assessment_id = await self.import_and_analyze(issue_key)
        try:
            _tests, review = self.agent_plan(assessment_id, depth=depth,
                                             max_rounds=max_rounds, actor=actor)
        except Exception as exc:  # noqa: BLE001 - a planning failure must not lose the import
            # The import succeeded and is on the record; a designer, planner or
            # reviewer failure must leave the tester on a normal analyzed
            # assessment they can design by hand, not on an error page with
            # nothing saved.
            self._repo.audit("agent_plan_failed", assessment_id,
                             detail=f"{type(exc).__name__}: {exc}")
            return assessment_id, None
        return assessment_id, review

    async def import_and_run_poc_plan(self, issue_key: str, actor: str = "tester"):
        """Import, then run exactly the PoC embedded in the ticket — nothing else.

        Unlike import_and_plan, neither the AI attack planner nor the
        deterministic rule engine contributes a single test: the plan is
        exactly the requests transpiled from the ticket's own PoC, and
        nothing the ticket's prose might separately imply (an endpoint
        mentioned in passing does not get its own BOLA/broken-auth probe
        here). The transpiled tests are sent verbatim, too (`verbatim=True`):
        no `classify()`-guessed mutation on top of them (e.g. injecting
        `role`/`is_admin` into a body that never had them) and no path
        rewritten to a `{victim_id}` placeholder nothing then fills back in —
        a ticket's PoC is already a complete exploit, not a template to attack
        a second time. The plan reviewer still runs once, read-only, so the
        tester can see whether the ticket's own PoC actually covers what the
        ticket asks for; the result adjudicator still runs at the assess step
        exactly as it does for any other assessment.

        Returns (assessment_id, PlanReview | None, poc_found: bool). poc_found is
        False when the ticket had no embedded PoC script to run — the caller should
        tell the tester to use Auto-plan or paste a PoC by hand instead.
        """
        assessment_id = await self.import_and_analyze(issue_key)
        analysis = self.get_analysis(assessment_id)
        poc = analysis.detected_poc_source if analysis else ""
        if not poc:
            self._repo.audit("ticket_poc_missing", assessment_id, actor=actor,
                             detail="no embedded PoC script found in ticket description")
            return assessment_id, None, False
        try:
            self.design(assessment_id, poc_python=poc, use_planner=False,
                       use_rule_engine=False, verbatim=True,
                       review=True, max_rounds=0, actor=actor)
        except Exception as exc:  # noqa: BLE001 - import already succeeded; must not be lost
            self._repo.audit("ticket_poc_design_failed", assessment_id, actor=actor,
                             detail=f"{type(exc).__name__}: {exc}")
            return assessment_id, None, True
        review = self._repo.get_plan_review(assessment_id)
        # Make the mode's intent explicit on the review itself: unresolved gaps here
        # were never sent to the AI planner, unlike Auto-plan's mode, so the existing
        # "no AI planner configured" note (which only fires when self._planner is
        # None) would otherwise be silent when a planner *is* configured but simply
        # wasn't asked.
        if review is not None and review.unresolved_gaps and self._planner is not None:
            review.notes = (
                f"{review.notes} Ticket PoC mode: only the ticket's own PoC ran as a "
                "test; the AI planner did not add tests to close the gap(s) below. "
                "Switch to Auto-plan or add tests by hand if you need them covered."
            ).strip()
            self._repo.save_plan_review(assessment_id, review)
        return assessment_id, review, True

    def delete_assessment(self, assessment_id: str, actor: str = "tester") -> None:
        assessment = self._repo.get_assessment(assessment_id)
        issue_key = assessment.issue_key if assessment else assessment_id
        self._repo.delete_assessment(assessment_id)
        # Deliberately audited *after* the assessment row is gone: AuditLog has
        # no FK to Assessment, so the trail survives the delete it describes.
        self._repo.audit("delete_assessment", assessment_id, actor=actor, detail=issue_key)

    # 2b. editing the attack surface ---------------------------------------
    #
    # The endpoint list is the single input everything downstream is derived
    # from: the designer builds one test set per endpoint, and the OWASP mapping
    # is computed from these parameters. The extractor is a regex over ticket
    # prose, so it misses endpoints written in a table, marks every endpoint
    # auth_required, and only ever finds object ids that appear in a path. Until
    # this existed, the only way to correct any of that was to edit the Jira
    # ticket and re-import — which threw away the plan and the approvals with it.

    class EndpointConflict(ValueError):
        """Raised when a write would produce two endpoints with one signature."""

    def get_analysis(self, assessment_id: str):
        from app.schemas.analysis import IssueAnalysis

        assessment = self._repo.get_assessment(assessment_id)
        if not assessment or not assessment.analysis_json:
            return None
        return IssueAnalysis.model_validate(assessment.analysis_json)

    def upsert_endpoint(self, assessment_id: str, endpoint, replaces: str = "",
                        actor: str = "tester") -> None:
        """Add an endpoint, or replace the one whose signature is `replaces`.

        Signature (METHOD PATH) is the identity, because that is what the
        extractor dedupes on and what a tester recognises. Editing method or
        path therefore changes the identity, so the caller passes the old
        signature in the URL and the new values in the body.
        """
        analysis = self.get_analysis(assessment_id)
        if analysis is None:
            raise ValueError("assessment has no analysis to edit")

        kept = [ep for ep in analysis.endpoints if ep.signature != replaces]
        if any(ep.signature == endpoint.signature for ep in kept):
            raise self.EndpointConflict(
                f"{endpoint.signature} is already in the list"
            )
        if replaces:
            # Keep the tester's ordering stable: an edited row stays where it
            # was rather than jumping to the bottom of the table.
            at = next((i for i, ep in enumerate(analysis.endpoints)
                       if ep.signature == replaces), len(kept))
            kept.insert(min(at, len(kept)), endpoint)
            action = "edit_endpoint"
            detail = f"{replaces} -> {endpoint.signature}"
        else:
            kept.append(endpoint)
            action = "add_endpoint"
            detail = endpoint.signature

        analysis.endpoints = kept
        self._refresh_mappings(analysis)
        self._repo.save_analysis(assessment_id, analysis)
        self._repo.audit(action, assessment_id, actor=actor, detail=detail)

    def delete_endpoint(self, assessment_id: str, signature: str,
                        actor: str = "tester") -> bool:
        analysis = self.get_analysis(assessment_id)
        if analysis is None:
            return False
        kept = [ep for ep in analysis.endpoints if ep.signature != signature]
        if len(kept) == len(analysis.endpoints):
            return False
        analysis.endpoints = kept
        self._refresh_mappings(analysis)
        self._repo.save_analysis(assessment_id, analysis)
        self._repo.audit("delete_endpoint", assessment_id, actor=actor, detail=signature)
        return True

    async def reanalyze(self, assessment_id: str, keep_manual: bool = True,
                        actor: str = "tester") -> None:
        """Re-read the ticket and rebuild the analysis from scratch.

        The escape hatch from the additive-only mapping rule below: this is the
        one operation allowed to drop a category the analyzer no longer sees.
        Hand-entered endpoints are carried across by default — they exist
        precisely because the extractor could not find them, so rebuilding
        would delete them every time.
        """
        assessment = self._repo.get_assessment(assessment_id)
        issue = await self._jira.get_issue(assessment.issue_key)
        analysis = self._analyzer.analyze(issue)
        analysis.source_text = ticket_text(issue)

        if not analysis.requirements:
            analysis.requirements = extract_requirements(issue)

        carried = 0
        if keep_manual:
            previous = self.get_analysis(assessment_id)
            if previous:
                have = {ep.signature for ep in analysis.endpoints}
                for ep in previous.endpoints:
                    if ep.manual and ep.signature not in have:
                        analysis.endpoints.append(ep)
                        carried += 1
                if carried:
                    self._refresh_mappings(analysis)
                # Same rule for requirement items as for endpoints: a re-read of
                # the ticket must not be the operation that deletes the item a
                # human added because the extractor could not see it.
                analysis.requirements = merge_requirements(
                    analysis.requirements, previous.requirements
                )

        poc_source = combined_poc_source(issue.description)
        if poc_source:
            analysis.detected_poc_source = poc_source
        self._repo.save_analysis(assessment_id, analysis)
        self._repo.audit("reanalyze", assessment_id, actor=actor,
                         detail=f"{len(analysis.endpoints)} endpoints "
                                f"({carried} hand-entered kept), "
                                f"{len(analysis.applicable_categories())} applicable categories")

    def _refresh_mappings(self, analysis) -> None:
        """Bring the OWASP mapping in line with a changed endpoint list —
        additively.

        Deliberately never downgrades an APPLICABLE category to NOT_APPLICABLE.
        The mapping may have come from the Claude analyzer, which reads the
        ticket's intent; recomputing it wholesale from the heuristic rules would
        silently replace that with something weaker every time a tester fixed a
        typo in a path. So a new endpoint can *add* a category or explain an
        existing one, and only `reanalyze()` — which a human asks for
        explicitly — is allowed to take one away.
        """
        from app.schemas.enums import Applicability

        signals = build_signals(analysis.source_text or "", analysis.endpoints)
        fresh = {m.category: m for m in map_owasp(signals)}
        existing = {m.category: m for m in analysis.owasp_mappings}

        for category, mapping in fresh.items():
            if mapping.applicability != Applicability.APPLICABLE:
                continue
            current = existing.get(category)
            if current is None:
                analysis.owasp_mappings.append(mapping)
            elif current.applicability != Applicability.APPLICABLE:
                current.applicability = Applicability.APPLICABLE
                current.reason = mapping.reason
                current.matched_signals = mapping.matched_signals

    # 3-4. design tests + transpile PoCs + coverage -------------------------

    def design(self, assessment_id: str, poc_python: str | None = None,
               poc_curl: str | None = None, poc_postman: str | None = None,
               burp_xml: str | None = None, jmeter_xml: str | None = None,
               depth: str | None = None, use_planner: bool = True,
               use_rule_engine: bool = True, verbatim: bool = False,
               review: bool = False, max_rounds: int = 1,
               actor: str = "tester") -> list:
        from app.schemas.analysis import IssueAnalysis

        assessment = self._repo.get_assessment(assessment_id)
        analysis = IssueAnalysis.model_validate(assessment.analysis_json)

        # Strictly additive, like use_planner: when off, the deterministic
        # rule engine contributes nothing and the plan is exactly whatever
        # the PoC/AI planner produced — "run only the ticket's PoC" (Option
        # 1) means only the ticket's PoC, not the PoC plus a full rule-engine
        # sweep of every endpoint the ticket happens to mention.
        designer = self._designer.with_depth(depth) if depth else self._designer
        generated = designer.design(analysis) if use_rule_engine else []

        # Transpile any provided PoC into scoped, PENDING test cases. Never run.
        poc_tests = []
        if poc_python:
            r = transpile_python(poc_python)
            poc_tests += to_test_cases(r, verbatim=verbatim)
            if not r.is_safe:
                self._repo.audit("poc_flagged", assessment_id,
                                 detail=f"dangerous constructs: {r.dangerous_constructs}")
        if poc_curl:
            poc_tests += to_test_cases(transpile_curl(poc_curl), verbatim=verbatim)
        if poc_postman:
            from app.poc.postman import postman_to_test_cases

            poc_tests += postman_to_test_cases(poc_postman)
        if burp_xml:
            from app.adapters.burp import burp_to_test_cases

            poc_tests += burp_to_test_cases(burp_xml)
        if jmeter_xml:
            from app.adapters.jmeter import jmeter_to_test_cases

            poc_tests += jmeter_to_test_cases(jmeter_xml)

        # AI planner runs LAST and sees everything already planned, so it adds
        # depth rather than duplicating the deterministic backbone. Its output
        # is schema-validated, mutation-allowlisted and PENDING like any other
        # test — it proposes, the approval gate still disposes.
        ai_tests = []
        if use_planner and self._planner is not None:
            plan = self._planner.plan(analysis, existing=poc_tests + generated)
            ai_tests = plan.tests
            self._repo.audit("ai_plan", assessment_id, detail=plan.summary())
            for rejection in plan.rejected:
                # Rejections are audited individually: "the AI proposed 12 and 9
                # disappeared" should never be something an operator has to
                # infer from a count.
                self._repo.audit("ai_plan_rejected", assessment_id, detail=rejection)

        all_tests = poc_tests + generated + ai_tests

        # The reviewing agent runs here: after everything that proposes tests,
        # before anything is persisted. It sees the whole plan (PoC + rules +
        # planner), says what the ticket asks for that the plan does not cover,
        # and its gaps are fed back to the planner for a bounded number of
        # revision rounds. The revised batch passes exactly the same
        # constraints as the first - allowlisted mutation, relative path, known
        # persona, PENDING approval - so a review round can only ever add tests
        # a human still has to approve.
        plan_review = None
        if review:
            plan_review, revision_tests = self._review_and_revise(
                assessment_id, analysis, all_tests, max_rounds=max_rounds
            )
            if revision_tests:
                ai_tests = ai_tests + revision_tests
                all_tests = poc_tests + generated + ai_tests

        # Replace, not append: test ids are deterministic ("API1-001"), so a
        # second design on the same assessment used to create a duplicate row
        # per id and break every `.one_or_none()` lookup below it (approval,
        # test detail, request edits). An approval already given to an
        # unchanged test is carried across the swap.
        swap = self._repo.replace_test_cases(assessment_id, all_tests)

        rows = compute_coverage(analysis, existing_poc_tests=poc_tests,
                                generated_tests=generated + ai_tests)
        apply_coverage_to_analysis(analysis, rows)
        # Records which endpoint list this plan was built from, so the UI can
        # say "these tests no longer match your endpoints" instead of letting
        # a stale plan be approved and run.
        analysis.plan_fingerprint = analysis.endpoints_fingerprint()
        self._repo.save_analysis(assessment_id, analysis)
        self._repo.save_coverage(assessment_id, [r.__dict__ | {"category": r.category.value} for r in rows])
        detail = (f"{len(all_tests)} tests ({len(poc_tests)} from PoC, "
                  f"{len(generated)} from rules at depth '{depth or 'default'}', "
                  f"{len(ai_tests)} from AI planner)")
        if swap["replaced"]:
            detail += (f"; replaced {swap['replaced']} test(s) from a previous design, "
                       f"{swap['carried_over']} kept their approval")
        self._repo.audit("design_tests", assessment_id, detail=detail)

        if plan_review is not None:
            # Persisted after the plan it describes, so a review can never be on
            # the record for a plan that failed to save.
            plan_review.tests_after = len(all_tests)
            self._repo.save_plan_review(assessment_id, plan_review)
            self._repo.audit(
                "plan_review", assessment_id, actor=f"{plan_review.reviewer}_reviewer",
                detail=(f"{plan_review.verdict}: coverage {plan_review.coverage_score}%, "
                        f"decidable {plan_review.quality_score}%, "
                        f"{len(plan_review.gaps)} gap(s) found, "
                        f"{len(plan_review.tests_added)} test(s) added over "
                        f"{plan_review.rounds} revision round(s), "
                        f"{len(plan_review.unresolved_gaps)} unresolved"
                        + (f"; degraded: {plan_review.degraded_reason}"
                           if plan_review.degraded_reason else "")),
            )
        return all_tests

    # 4b. the planning agent -------------------------------------------------

    def _review_and_revise(self, assessment_id: str, analysis, tests: list,
                           max_rounds: int = 1):
        """Critique the plan, then let the planner answer the critique.

        Bounded on purpose. Each round is another LLM call and another batch of
        tests a human has to read, and a reviewer that is never satisfied would
        otherwise loop until the batch cap swallowed the plan. Two stopping
        conditions besides the round cap: the reviewer says APPROVE, or a round
        produces no accepted tests - a planner that cannot close a gap will not
        close it by being asked again.

        Returns (PlanReview, new tests). The review's `gaps` are what the first
        pass found; `unresolved_gaps` are what survived the last one, which is
        the list a tester actually has to act on.
        """
        requirements = list(analysis.requirements)
        first = self._reviewer.review(analysis, tests, requirements)
        final = first
        current = list(tests)
        added: list = []
        rounds = 0

        while (
            rounds < max_rounds
            and final.verdict != "APPROVE"
            and final.gaps
            and self._planner is not None
        ):
            rounds += 1
            result = self._planner.plan_for_gaps(
                analysis, final.gaps, existing=current, id_prefix=f"AIR{rounds}"
            )
            self._repo.audit(
                "plan_revision", assessment_id, actor="ai_planner",
                detail=f"round {rounds} answering {len(final.gaps)} gap(s): {result.summary()}",
            )
            for rejection in result.rejected:
                self._repo.audit("plan_revision_rejected", assessment_id, detail=rejection)
            if not result.tests:
                break
            added += result.tests
            current = current + result.tests
            final = self._reviewer.review(analysis, current, requirements)

        out = final.model_copy(deep=True)
        out.gaps = first.gaps
        out.unresolved_gaps = final.gaps if final.verdict != "APPROVE" else []
        out.rounds = rounds
        out.tests_before = len(tests)
        out.tests_after = len(current)
        out.tests_added = [t.test_id for t in added]
        if out.unresolved_gaps and self._planner is None:
            out.notes = (
                f"{out.notes} No AI planner is configured (set USE_AI=true with the "
                "claude CLI installed and logged in), so the gaps below were not answered automatically - "
                "they are listed for you to close by editing the endpoint list, importing "
                "a PoC that covers them, or adding a test by hand."
            ).strip()
        return out, added

    def agent_plan(self, assessment_id: str, depth: str | None = None,
                   max_rounds: int = 1, use_detected_poc: bool = True,
                   actor: str = "tester"):
        """Design -> AI planner -> review -> revise -> re-review, in one call.

        What "press Import and get a plan to approve" runs. The PoC the importer
        found embedded in the ticket is fed in by default: at this point a human
        has asked for a plan for this ticket, and the PoC is part of what the
        ticket says. It is still only ever *parsed* - `transpile_python` reads an
        AST and never executes, and every test it produces lands PENDING like
        any other.

        Returns (tests, PlanReview).
        """
        analysis = self.get_analysis(assessment_id)
        poc = (analysis.detected_poc_source or None) if (analysis and use_detected_poc) else None
        tests = self.design(assessment_id, poc_python=poc, depth=depth,
                            review=True, max_rounds=max_rounds, actor=actor)
        return tests, self._repo.get_plan_review(assessment_id)

    # 5. approval -----------------------------------------------------------

    def approve(self, assessment_id: str, test_ids: list[str], actor: str = "tester") -> int:
        return self._decide(assessment_id, test_ids, ApprovalStatus.APPROVED, "approve", actor)

    def reject(self, assessment_id: str, test_ids: list[str], actor: str = "tester") -> int:
        return self._decide(assessment_id, test_ids, ApprovalStatus.REJECTED, "reject", actor)

    def reset_approval(self, assessment_id: str, test_ids: list[str],
                       actor: str = "tester") -> int:
        """Back to PENDING — the undo for a decision.

        Unchecking a box used to do nothing at all: the approve handler only
        ever read the ids that *were* checked, so the checkbox looked like a
        two-way toggle and was not one. Withdrawing an approval has to be
        something a tester can actually do, and separately from rejecting.
        """
        return self._decide(assessment_id, test_ids, ApprovalStatus.PENDING, "reset_approval", actor)

    def _decide(self, assessment_id: str, test_ids: list[str], status: ApprovalStatus,
                action: str, actor: str) -> int:
        n = self._repo.set_approval_bulk(assessment_id, test_ids, status.value)
        # The ids are audited, not just the count: "12 tests approved" is not an
        # answer to "which 12?" six weeks later. Long lists are summarised so one
        # bulk action over 300 tests does not become a 300-id audit row.
        if len(test_ids) <= 12:
            detail = f"{status.value.lower()}: {', '.join(sorted(test_ids))}"
        else:
            shown = ", ".join(sorted(test_ids)[:12])
            detail = f"{status.value.lower()}: {n} test(s) incl. {shown}, ..."
        self._repo.audit(action, assessment_id, actor=actor, detail=detail)
        return n

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
        adaptive=None,
    ) -> list:
        """`adaptive`: an AdaptiveBudget to enable the bounded exploitation loop.

        None (the default) keeps the original one-shot behaviour exactly. The
        loop only ever runs when an operator asks for it AND a planner is
        configured — two independent switches, because it is the one path where
        a request is sent that no human read first.
        """
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
        # Executions accumulate across runs (that is what makes the evidence
        # chain span an assessment's whole history), so a second run must not
        # mint an execution_id the first run already used — the id is hashed
        # into the chain, and a duplicate makes two distinct runs
        # indistinguishable in the evidence. len(prior) grows every round, so
        # it is a sufficient disambiguator; the first round deliberately keeps
        # the original un-tagged format so existing hashes still verify.
        run_tag = "" if not prior else f"#{len(prior)}"

        if adaptive is not None and self._planner is not None:
            executions, extra_tests = self._execute_adaptive(
                assessment_id, runner, tests, adaptive, prev_hash,
                execution_prefix=f"{assessment_id}{run_tag}",
            )
            # Adaptive follow-ups are real test cases and must be persisted, or
            # the report renders executions whose test_id resolves to nothing
            # and findings silently drop them (build_findings skips unknown ids).
            if extra_tests:
                self._repo.save_test_cases(assessment_id, extra_tests)
                tests = tests + extra_tests
        else:
            if adaptive is not None:
                self._repo.audit("adaptive_skipped", assessment_id,
                                 detail="adaptive execution requested but no AI planner is "
                                        "configured; ran the approved tests one-shot instead")
            executions = []
            for t in tests:
                # run_safe (not run): one test raising an unexpected exception
                # (e.g. a persona missing from the vault) must not discard every
                # execution already computed earlier in this same batch.
                ex = runner.run_safe(t, execution_id=f"{assessment_id}{run_tag}-{t.test_id}",
                                     prev_hash=prev_hash)
                prev_hash = ex.evidence_hash
                executions.append(ex)

        self._repo.save_executions(assessment_id, executions)
        chain_ok = verify_chain(prior + executions)
        self._repo.audit("execute", assessment_id,
                         detail=f"{len(executions)} executed; evidence_chain_ok={chain_ok}; "
                                f"include_destructive={include_destructive}")

        # Findings describe the current state of the target as of everything
        # this assessment has ever executed, so they are recomputed over the
        # full execution history and replace the previous set. Appending was
        # silently wrong: build_findings numbers findings SEC-001.. from
        # scratch, so a second run produced a second SEC-001 and every report,
        # export and Jira comment counted the same finding twice.
        all_executions = prior + executions
        all_tests = {t.test_id: t for t in self._repo.get_test_cases(assessment_id)}
        findings = build_findings(all_tests, all_executions)
        self._repo.replace_findings(assessment_id, findings)
        self._repo.audit("findings", assessment_id,
                         detail=f"{len(findings)} findings over {len(all_executions)} execution(s), "
                                f"{len(leads({}, executions))} inconclusive this run")
        return executions

    def _execute_adaptive(self, assessment_id: str, runner, tests: list, budget, prev_hash,
                          execution_prefix: str | None = None):
        """Drive the bounded exploitation loop and audit exactly what it did.

        Every follow-up here ran without a human reading it first, so the audit
        entries are not decoration: they are the record of what the platform
        chose to do on the operator's behalf, including what it declined.
        """
        from app.execution.adaptive import AdaptiveExecutor
        from app.schemas.analysis import IssueAnalysis

        assessment = self._repo.get_assessment(assessment_id)
        analysis = IssueAnalysis.model_validate(assessment.analysis_json)

        executor = AdaptiveExecutor(runner, self._planner, analysis, budget)
        result = executor.run(tests, execution_prefix=execution_prefix or assessment_id,
                              prev_hash=prev_hash)

        self._repo.audit("adaptive_execute", assessment_id, actor="adaptive_policy",
                         detail=result.summary())
        for followup in result.followups:
            self._repo.audit("adaptive_auto_approved", assessment_id, actor="adaptive_policy",
                             detail=f"{followup.test_id}: {followup.attack_mutation.kind} on "
                                    f"{followup.request.method} {followup.request.path}")
        for rejection in result.rejected:
            self._repo.audit("adaptive_rejected", assessment_id, actor="adaptive_policy",
                             detail=rejection)
        for error in result.planner_errors:
            self._repo.audit("adaptive_planner_error", assessment_id, detail=error)

        return result.executions, result.followups

    # re-running ONE execution ----------------------------------------------
    #
    # An INCONCLUSIVE verdict is the runner refusing to guess: the positive
    # control failed, the server 500'd, or the attack was accepted but no
    # protected marker was available to prove disclosure. Several of those are
    # transient, and the answer to a transient undecided result is to send the
    # request again — not to re-run a 200-test plan to settle one row.
    #
    # It is a re-run of the TEST, not a replay of the stored capture, and the
    # difference is not cosmetic. `CapturedRequest.headers`/`body` are redacted
    # before they are stored (that is the whole point of redaction.py), so the
    # evidence record's Authorization header is literally "********". Replaying
    # those bytes would send a request no server would authenticate and call the
    # resulting 401 a result. Re-running the TestCase reproduces the same
    # method, path, query, headers and body through the same trusted runner,
    # with the persona's real credential resolved from the vault at send time —
    # which is what "the request as it was run" actually means here.
    #
    # The original record is never touched. The re-run is appended as a new
    # execution, chained onto the current head of the evidence chain, so the log
    # shows both attempts and an auditor can see the verdict changed and why.

    class RerunRefused(ValueError):
        """A single-execution re-run the platform will not perform.

        Carries a sentence fit to show a tester verbatim; every raise site
        states what was wrong and what to do about it.
        """

    def rerun_execution(
        self,
        assessment_id: str,
        execution_id: str,
        scope: ScopeValidator,
        vault: PersonaVault,
        settings: Settings | None = None,
        base_url: str = "",
        client=None,
        confirm_destructive: bool = False,
        actor: str = "tester",
    ):
        """Re-send one execution's request and append the result.

        Returns (original, replay). `base_url` defaults to the target this
        assessment actually ran against, so "run it again" means the same
        environment unless the caller deliberately says otherwise.
        """
        assessment = self._repo.get_assessment(assessment_id)
        if assessment is None:
            raise self.RerunRefused(f"Assessment {assessment_id} does not exist.")

        original = self._repo.get_execution(assessment_id, execution_id)
        if original is None:
            raise self.RerunRefused(
                f"No execution {execution_id} in this assessment."
            )

        test = self._repo.get_test_case(assessment_id, original.test_id)
        if test is None:
            raise self.RerunRefused(
                f"The test case behind this execution ({original.test_id}) is no longer "
                "in the plan, so there is nothing to send. The stored evidence stands "
                "on its own; re-design the plan to test this again."
            )

        # Approval is a statement about the test as it reads NOW. Editing a
        # request resets approval to PENDING, so a test that ran an hour ago
        # may since have been changed — re-running it here would send something
        # nobody reviewed, from a button that says "run this again".
        if not test.is_runnable():
            raise self.RerunRefused(
                f"{test.test_id} is {test.approval_status.value}. It was approved when it "
                "first ran; approve it again on the assessment page before re-running it."
            )

        # Same gate the batch runner applies, for the same reason: approving a
        # write probe once, for a run you watched, is not consent to it firing
        # again from a button in a report.
        if test.is_destructive and not confirm_destructive:
            raise self.RerunRefused(
                f"{test.test_id} is destructive — it sends a real "
                f"{test.request.method}. Confirm explicitly before re-running it."
            )

        target = base_url or assessment.target_base_url
        if not target:
            raise self.RerunRefused(
                "No target base URL is recorded for this assessment; configure an "
                "environment and run the plan before re-running a single request."
            )

        settings = settings or Settings.from_env()
        self._repo.set_target(assessment_id, target)
        runner = HttpRunner(target, scope, vault, settings, client=client)

        prior = self._repo.get_executions(assessment_id)
        prev_hash = prior[-1].evidence_hash if prior else None
        # "-rerun-" is not decoration: the id is hashed into the evidence chain
        # and is what a reader sees in the log, so a targeted single re-run must
        # be distinguishable from a batch round at a glance. It also guarantees
        # the id cannot collide with the batch format (`{aid}#{n}-{test_id}`).
        replay_id = f"{assessment_id}#{len(prior)}-rerun-{test.test_id}"

        replay = runner.run_safe(test, execution_id=replay_id, prev_hash=prev_hash)
        self._repo.save_executions(assessment_id, [replay])

        # Findings describe the target as of everything this assessment has
        # executed. A re-run that resolves INCONCLUSIVE into FAIL has to mint
        # the finding it just proved, and one that resolves into PASS must not
        # leave a finding standing on evidence that no longer supports it.
        all_executions = prior + [replay]
        all_tests = {t.test_id: t for t in self._repo.get_test_cases(assessment_id)}
        self._repo.replace_findings(assessment_id, build_findings(all_tests, all_executions))

        chain_ok = verify_chain(all_executions)
        self._repo.audit(
            "rerun_execution", assessment_id, actor=actor,
            detail=f"{execution_id} ({original.verdict.result.value}) re-run as {replay_id} "
                   f"-> {replay.verdict.result.value}; target={target}; "
                   f"evidence_chain_ok={chain_ok}",
        )
        return original, replay

    # -- copying one execution as a curl command -----------------------------
    #
    # Same redaction problem as re-running (see the block comment above
    # rerun_execution), different resolution: a "copy" action must not send
    # anything, so it cannot re-run the test's setup/baseline steps to
    # re-derive a request the way rerun_execution does — that would fire real,
    # possibly state-changing requests at the target just to produce a string.
    # Instead this takes the exact recorded request (the actual attack that was
    # sent) and patches back only the attacker persona's auth header(s),
    # resolved live from the vault, into render_curl. Everything else in the
    # recorded request — including anything else that happened to be redacted
    # — is left exactly as captured.

    def build_curl(self, assessment_id: str, execution_id: str,
                    vault: PersonaVault, actor: str = "tester") -> str:
        execution = self._repo.get_execution(assessment_id, execution_id)
        if execution is None:
            raise self.RerunRefused(f"No execution {execution_id} in this assessment.")

        test = self._repo.get_test_case(assessment_id, execution.test_id)
        persona = None
        if test is not None:
            try:
                persona = vault.get(test.auth_context.persona)
            except KeyError:
                persona = None

        curl = render_curl(execution.request, persona)
        # This hands the caller a live, currently-valid credential — worth a
        # line in the same audit trail rerun_execution writes to.
        self._repo.audit(
            "build_curl", assessment_id, actor=actor,
            detail=f"{execution_id} curl command generated for {test.test_id if test else execution.test_id} "
                   f"(includes a live credential from the persona vault)",
        )
        return curl

    # re-running an assessment ---------------------------------------------
    #
    # A re-run is a NEW assessment of the same issue, not a second pass over the
    # old one. Two reasons it has to work that way:
    #
    #  * Regression only exists between assessments. `previous_assessment_for_issue`
    #    is the baseline lookup, so cloning is what makes "what changed since last
    #    time" answerable at all — a second run inside one assessment has nothing
    #    to diff against.
    #  * The old run's evidence stays exactly as it was. Findings are derived from
    #    every execution an assessment holds, so re-running in place would rewrite
    #    the conclusions attached to evidence that was already reported.

    def clone_for_rerun(self, assessment_id: str, actor: str = "tester") -> str:
        """Copy an assessment's analysis and plan into a fresh assessment.

        Approvals come across. An approval is a statement about a specific test —
        "I read what this does and it may run" — and the cloned test is byte-for-
        byte that test, so making the tester re-approve an identical plan would be
        ceremony, not review. What does *not* come across is anything derived from
        a run: executions, findings, the target URL.
        """
        source = self._repo.get_assessment(assessment_id)
        if source is None:
            raise ValueError(f"assessment {assessment_id} does not exist")

        new_id = f"A-{uuid.uuid4().hex[:10]}"
        self._repo.create_assessment(new_id, source.issue_key, source.project_key)
        self._repo.clone_analysis(assessment_id, new_id)
        # The plan review comes across with the plan it reviewed - it is part of
        # why the carried-over approvals were given. The run assessment does not:
        # it describes executions this new assessment has not performed.
        self._repo.clone_agent_records(assessment_id, new_id, kinds=("plan_review",))

        tests = self._repo.get_test_cases(assessment_id)
        # Adaptive follow-ups were auto-approved by policy during a run rather
        # than reviewed by a person, so they are not carried into a plan a human
        # is about to run again. They will be proposed again if the loop is asked
        # for again.
        carried = [t for t in tests if t.source != TestSource.ADAPTIVE_PLANNER]
        if carried:
            self._repo.replace_test_cases(new_id, carried)

        approved = sum(1 for t in carried if t.approval_status == ApprovalStatus.APPROVED)
        self._repo.audit("clone_for_rerun", new_id, actor=actor,
                         detail=f"cloned from {assessment_id}: {len(carried)} test(s), "
                                f"{approved} already approved")
        self._repo.audit("rerun_started", assessment_id, actor=actor,
                         detail=f"new run is {new_id}")
        return new_id

    # 6b. reviewing the results ---------------------------------------------
    #
    # INCONCLUSIVE is the runner declining to guess, and the bill for that
    # honesty is paid by a person reading response bodies. Most of what they do
    # is not judgement: a failed positive control is a test-data problem, a 500
    # is transient, and an accepted attack with a body sitting right there is a
    # reading task. So the results are triaged first (deterministic, always) and
    # only the reading tasks are handed to an agent.
    #
    # Nothing here writes `execution.verdict`. The sealed verdict is what the
    # evidence hash covers and the only thing `build_findings` reads, so an
    # adjudication is stored beside it, marked advisory, with the sealed value
    # carried alongside its opinion. An agent that reads a result as FAIL does
    # not create a finding and does not change what this platform reports as
    # confirmed - it changes what a tester has to read, and says what it thinks.

    def latest_executions(self, assessment_id: str) -> list:
        """One row per test: the most recent attempt.

        Executions accumulate - a re-run of a single undecided row appends
        rather than overwrites - so the question "what is true about this test
        now" has to be answered by the last attempt. Findings deliberately still
        span the whole history (a break that was observed was observed); this is
        the current-state view the run assessment is computed over.
        """
        latest: dict[str, object] = {}
        for execution in self._repo.get_executions(assessment_id):
            latest[execution.test_id] = execution
        return list(latest.values())

    def triage_results(self, assessment_id: str, executions: list | None = None,
                       tests: list | None = None) -> list[tuple]:
        """(execution, class, reason) for every current execution. No AI, no writes.

        Exposed on its own so the UI can say "4 of these need you, 2 just need
        re-running" before anyone spends a token or a minute. `executions` and
        `tests` may be passed by a caller that has already loaded them — the
        assessment page has, and reading every execution twice to render one line
        is a cost that grows with exactly the assessments where it hurts.
        """
        rows = self._repo.get_test_cases(assessment_id) if tests is None else tests
        by_id = {t.test_id: t for t in rows}
        if executions is None:
            current = self.latest_executions(assessment_id)
        else:
            latest: dict[str, object] = {}
            for execution in executions:
                latest[execution.test_id] = execution
            current = list(latest.values())
        return [
            (execution, *triage(by_id.get(execution.test_id), execution))
            for execution in current
        ]

    def triage_counts(self, assessment_id: str, executions: list | None = None,
                      tests: list | None = None) -> dict[str, int]:
        """How many results fall into each triage class, decided ones omitted."""
        counts: dict[str, int] = {}
        for _execution, klass, _reason in self.triage_results(
            assessment_id, executions=executions, tests=tests
        ):
            if klass == "decided":
                continue
            counts[klass] = counts.get(klass, 0) + 1
        return counts

    # How many results one review pass may hand to the model. An aggressive-depth
    # run is hundreds of tests and can leave dozens undecided; without a bound,
    # one click is dozens of API calls and a bill nobody agreed to. The cap is
    # announced rather than applied silently — a result that was never read must
    # not be indistinguishable from one that was read and found unclear.
    MAX_AI_ADJUDICATIONS = 40

    def adjudicate(self, assessment_id: str, actor: str = "tester",
                   max_ai_calls: int | None = None):
        """Review every undecided result, then answer the run-level question.

        Returns a `RunAssessment`: passed / failed / incomplete, the share of the
        ticket's requirements a decided test covered, and one advisory
        `Adjudication` per result the runner left open.

        Triage runs over *every* undecided result — it is free and it is most of
        the value. Only the reading tasks reach the model, and only up to
        `max_ai_calls` of them; the rest are returned as needing a person, saying
        so.
        """
        analysis = self.get_analysis(assessment_id)
        if analysis is None:
            raise ValueError("This assessment has no analysis to assess against.")

        # An assessment imported before requirement items existed has none, and
        # would report its coverage as permanently unmeasured. The stored ticket
        # text is still there, so back-fill from it rather than making the tester
        # re-import — which would discard the plan and every approval on it.
        if not analysis.requirements and analysis.source_text:
            analysis.requirements = extract_requirements_from_text(analysis.source_text)
            if analysis.requirements:
                self._repo.save_analysis(assessment_id, analysis)
                self._repo.audit(
                    "requirements_backfilled", assessment_id, actor=actor,
                    detail=(f"{len(analysis.requirements)} item(s) read from the stored "
                            "ticket text; re-analyzing from the ticket reads it better"),
                )

        tests = self._repo.get_test_cases(assessment_id)
        by_id = {t.test_id: t for t in tests}
        executions = self.latest_executions(assessment_id)

        budget = self.MAX_AI_ADJUDICATIONS if max_ai_calls is None else max(0, max_ai_calls)
        adjudications = []
        capped = 0
        for execution in executions:
            test = by_id.get(execution.test_id)
            klass, reason = triage(test, execution)
            if klass == "decided":
                # The runner already decided it from correlated evidence. Asking
                # an agent to re-read a sealed PASS/FAIL would spend a call to
                # produce an opinion that cannot change anything, and would put
                # a second, differently-derived verdict next to the one the
                # evidence chain covers.
                continue
            if klass == "agent" and self._adjudicator.ai_enabled:
                if budget <= 0:
                    capped += 1
                    adjudications.append(Adjudication(
                        execution_id=execution.execution_id,
                        test_id=execution.test_id,
                        sealed_result=execution.verdict.result,
                        needs_manual_review=True,
                        triage_reason=reason,
                        rationale=execution.verdict.reason,
                        recommended_action=(
                            "Read this one yourself, or review again to spend a fresh "
                            "budget on it."
                        ),
                        degraded_reason=(
                            f"Not read: this pass reached its cap of "
                            f"{self.MAX_AI_ADJUDICATIONS} reviewed result(s)."
                        ),
                    ))
                    continue
                budget -= 1
            adjudications.append(
                self._adjudicator.adjudicate(analysis, test, execution)
            )
        if capped:
            self._repo.audit(
                "adjudicate_capped", assessment_id, actor=actor,
                detail=(f"{capped} reading task(s) were not sent to the model: the pass "
                        f"cap is {self.MAX_AI_ADJUDICATIONS}. They are reported as needing "
                        "a person rather than as read-and-unclear."),
            )

        # The run-level note prefers a reason that is not the cap: hitting the cap
        # is expected behaviour under load, while an unusable key or a rate limit
        # is a broken configuration, and surfacing the former would hide the
        # latter behind something that looks like a setting working as intended.
        reasons = [a.degraded_reason for a in adjudications if a.degraded_reason]
        degraded = next((r for r in reasons if "reached its cap" not in r),
                        reasons[0] if reasons else "")
        run = assess_run(
            analysis, tests, executions, adjudications,
            assessment_id=assessment_id,
            reviewer="ai" if self._adjudicator.ai_enabled else "deterministic",
            degraded_reason=degraded,
        )
        self._repo.save_run_assessment(assessment_id, run)
        self._repo.audit(
            "adjudicate", assessment_id, actor=f"{run.reviewer}_adjudicator",
            detail=(f"{run.overall}: coverage {run.coverage_pct}%, decided {run.decided_pct}%, "
                    f"{run.n_auto_resolved} undecided result(s) settled by the agent, "
                    f"{run.n_manual_review} still need a person, "
                    f"{run.n_rerun} need a re-run"
                    + (f", {capped} over the review cap" if capped else "")
                    + (f"; degraded: {degraded}" if degraded else "")),
        )
        return run

    def report_url(self, assessment_id: str) -> str:
        """An absolute link to this assessment's report, when one can be built.

        Jira readers are not on this machine, so a link is only useful if
        somebody has said where the platform is reachable from
        (`PLATFORM_BASE_URL`). Unset means no link rather than a localhost URL
        that 404s for every reader but its author — a broken link in a ticket
        costs more trust than an absent one.
        """
        import os

        base = (os.getenv("PLATFORM_BASE_URL", "") or "").strip().rstrip("/")
        if not base or not base.startswith(("http://", "https://")):
            return ""
        return f"{base}/assessment/{assessment_id}/report"

    def run_assessment(self, assessment_id: str):
        """The stored run assessment, or None if nobody has asked for one."""
        return self._repo.get_run_assessment(assessment_id)

    def plan_review(self, assessment_id: str):
        return self._repo.get_plan_review(assessment_id)

    # 7. report -------------------------------------------------------------

    def build_report_html(self, assessment_id: str, lang: str = "en") -> str:
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
            # The report is now where the per-test explanation lives: the Jira
            # comment carries the summary and the results table, and everything
            # that explains a row - expected versus observed, the mutation's
            # parameters, the agents' reasoning - is here, where there is room
            # for it and where the raw evidence it refers to already is.
            plan_review=self._repo.get_plan_review(assessment_id),
            run_assessment=self._repo.get_run_assessment(assessment_id),
            lang=lang,
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
                     self._repo.get_findings(assessment_id), a.coverage_json,
                     plan_review=self._repo.get_plan_review(assessment_id),
                     run_assessment=self._repo.get_run_assessment(assessment_id))

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
        """Build the Jira comment. Rendering lives in `reporting.jira_comment`.

        Deliberately does NOT claim a report is "attached": no MCP tool this
        connector calls can upload a file to a Jira issue (get_attachments()
        is a stub that always returns [] — there was never a write-side
        counterpart), so a prior version of this text was simply false.

        The comment carries the summary and the full results table, and points
        at the report for everything that explains a row. It used to carry the
        explanation too — per test, the attack, the exact request, expected
        versus observed, the verdict's reasoning — which made a 60-test run a
        wall of text nobody scrolled, in the one place where being read matters
        most. The explanation did not disappear: `reporting/html.py` renders it
        beside the request/response evidence it refers to, which is where a
        reader who wants that depth is going anyway.
        """
        from app.reporting.jira_comment import build_comment

        assessment = self._repo.get_assessment(assessment_id)
        executions = self._repo.get_executions(assessment_id)
        return build_comment(
            issue_key=assessment.issue_key,
            target=assessment.target_base_url or "(not executed)",
            tests={t.test_id: t for t in self._repo.get_test_cases(assessment_id)},
            executions=executions,
            findings=self._repo.get_findings(assessment_id),
            # The one-line answer a stakeholder reading the ticket wants:
            # passed or failed, and how much of the ticket it covered. Absent
            # until somebody runs the adjudicator, and the comment simply omits
            # the row rather than inventing a percentage.
            run_assessment=self._repo.get_run_assessment(assessment_id),
            report_url=self.report_url(assessment_id),
            # Re-verified at the moment the comment is written, not reused from
            # execute() time: a hash computed correctly during the run says
            # nothing about whether the rows were edited afterwards, and this
            # comment is about to assert the chain is intact.
            evidence_chain_ok=verify_chain(executions),
        )

    async def post_comment(self, assessment_id: str, actor: str = "tester") -> str:
        assessment = self._repo.get_assessment(assessment_id)
        comment = self.comment_preview(assessment_id)
        await self._jira.add_comment(assessment.issue_key, comment)
        self._repo.audit("jira_comment", assessment_id, actor=actor,
                         detail=f"posted to {assessment.issue_key}")
        return comment
