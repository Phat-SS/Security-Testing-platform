"""The Jira comment — the one artefact most stakeholders will ever read.

Almost nobody opens the HTML report. They read the ticket. So this has to carry
enough for a developer to act without leaving Jira: what was sent, what the
attack actually did, what came back, and why that is or is not a finding.

Three constraints shape every decision here.

**It leaves the platform.** Everything below is written to a system with a
different audience and a different access-control model than the evidence
store. Only fields that are redacted at capture time (`request.url`,
`response.body`) or narrative fields that are marker-free by construction (see
`execution.verdict`) may appear, and every string still passes `redact_text` on
the way out — belt and braces, because the cost of being wrong once is an
incident.

**It is rendered by an ADF converter, not by Jira wiki markup.** The
`addCommentToJiraIssue` MCP tool converts standard CommonMark/GFM: tables,
`**bold**`, backtick code and emoji all work; `h2.`, `||headers||` and
`{color}` render as dead literal text. Hence GFM throughout and emoji rather
than colour macros.

**It is a summary, not the report.** This used to carry a block per test — the
attack, the exact request, expected versus observed, the verdict's reasoning,
the supporting exchanges — and a block per finding with impact and reproduction
steps. On a 60-test run that is thousands of words in a ticket comment, and the
practical result was that the thing worth reading (what failed) sat below
several screens of things that did not fail. Length is not thoroughness in a
place people skim.

So the comment now carries exactly two things: **the summary** (what was run,
what the verdict counts were, whether the run passed, how much of the ticket it
covered, and one row per finding) and **the full results table** (one row per
test, every test). Everything that *explains* a row — the mutation's parameters,
what a secure system was expected to return, the verdict's reasoning, the
baseline and read-back exchanges, a finding's impact and reproduction steps —
lives in the HTML report, next to the request/response evidence it refers to.
`reporting/html.py` owns that, and this module deliberately does not duplicate
it: two renderings of the same explanation drift, and the one in the ticket is
the copy nobody updates.

A length cap still applies, and anything dropped is announced rather than
silently truncated.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from app.core.redaction import redact_text
from app.schemas.enums import TestStatus
from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.testcase import TestCase

# Colour cues that cannot fail to render. A {color} macro depends on markup
# support the ADF converter does not provide; an emoji is a glyph either way.
SEVERITY_EMOJI = {
    "CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
    "LOW": "\U0001F7E2", "INFO": "⚪",
}
RESULT_EMOJI = {
    "FAIL": "\U0001F534", "INCONCLUSIVE": "\U0001F7E1", "PASS": "\U0001F7E2",
    "BLOCKED": "⚪", "ERROR": "⚠️", "TIMEOUT": "⏱️",
    "SKIPPED": "⚪", "NOT_RUN": "⚪",
}

# Most-actionable first. A reader who stops after the first screen should have
# seen the confirmed breaks, not a list of passes.
_RESULT_ORDER = {
    TestStatus.FAIL: 0, TestStatus.INCONCLUSIVE: 1, TestStatus.ERROR: 2,
    TestStatus.TIMEOUT: 3, TestStatus.BLOCKED: 4, TestStatus.PASS: 5,
}

_MAX_CELL = 70
_MAX_DETAIL_VALUE = 300


# --- formatting primitives ---------------------------------------------------


def _safe(text: object) -> str:
    """Redact, flatten and bound any string on its way into the comment.

    Newlines are collapsed because a stray one inside a GFM table cell ends the
    row and silently corrupts every column after it.
    """
    if text is None:
        return ""
    flattened = " ".join(str(text).split())
    return redact_text(flattened) or ""


def _cell(text: object, limit: int = _MAX_CELL) -> str:
    """A table cell. Pipes are escaped, not stripped: a path really can contain
    one, and an unescaped pipe would shift every following column by one."""
    value = _safe(text).replace("|", "\\|")
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    return value or "—"


def _code(text: object, limit: int = _MAX_DETAIL_VALUE) -> str:
    """Inline code. Backticks are removed rather than escaped — a backtick
    inside a span terminates it, and no path legitimately needs one."""
    value = _safe(text).replace("`", "")
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    return f"`{value}`" if value else "—"


# The runner stores these placeholders as the URL when it never got as far as
# building a real one. Rendering them verbatim reads as a bizarre request having
# been sent to a host called "(error)"; a reader needs to be told plainly that
# nothing left the machine.
_UNSENT_URLS = {"(blocked)": "not sent — blocked before the request was built",
                "(error)": "not sent — the runner failed before sending"}


def _short_request(execution: Execution) -> str:
    url = execution.request.url
    if url in _UNSENT_URLS:
        return "(not sent)"
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return f"{execution.request.method} {path}"


# --- sections ----------------------------------------------------------------


def _findings_table(findings: list[Finding], limit: int) -> list[str]:
    """One row per finding: what broke, where, how badly.

    A row, not a block. Impact, reproduction steps, recommendation and the
    correlated evidence are what a developer needs in order to *fix* it, and
    those are in the report — where they sit beside the captured request and
    response that prove them, rather than being retyped into a ticket comment
    that cannot show either.
    """
    lines = [
        "| Finding | Severity | OWASP | Endpoint | Confirmed by |",
        "|---|---|---|---|---|",
    ]
    for finding in findings[:limit]:
        emoji = SEVERITY_EMOJI.get(finding.severity.value, "")
        lines.append(
            f"| **{_cell(finding.finding_id, 16)}** — {_cell(finding.title, 44)} "
            f"| {emoji} **{finding.severity.value}** "
            f"| {_cell(finding.owasp_category.value, 12)} "
            f"| {_cell(finding.endpoint, 52)} "
            f"| {_cell(', '.join(finding.affected_tests), 30)} |"
        )
    if len(findings) > limit:
        lines.append(f"| … | | | | {len(findings) - limit} more not shown |")
    return lines


def _assessment_rows(run) -> list[str]:
    """The agent-reviewed answer, as summary rows.

    Two numbers a stakeholder reading the ticket actually asks for: did this
    pass, and how much of what the ticket asked for did it cover. Both are
    computed by the platform over the requirement list, never asserted by a
    model - and the advisory readings are labelled as advisory here too, because
    "the runner sealed this as a break" and "an agent read this as a break" are
    different claims and must not print alike.
    """
    if run is None:
        return []
    verdict_emoji = {"PASSED": RESULT_EMOJI["PASS"], "FAILED": RESULT_EMOJI["FAIL"],
                     "INCOMPLETE": RESULT_EMOJI["INCONCLUSIVE"]}.get(run.overall, "")
    workings = (f"{run.n_items_decided}/{run.n_items_scored} requirement item(s) "
                f"decided by a test"
                + (f", {run.n_items_partial} tested but undecided"
                   if run.n_items_partial else "")) if run.n_items_scored else \
               "no testable requirement item was extracted from the ticket"
    rows = [
        f"| Overall assessment | {verdict_emoji} **{run.overall}** |",
        (f"| Ticket requirements covered | **{run.coverage_pct}%** "
         f"— {_safe(workings)} |"),
        f"| Executions with a decisive result | {run.decided_pct}% |",
    ]
    if run.n_auto_resolved:
        # How it was settled, in the cell. A ticket reader cannot open the
        # evidence, so "settled" without saying by what invites them to read a
        # model's opinion and a reproducible measurement as the same claim.
        how = []
        if getattr(run, "n_measured", 0):
            how.append(f"{run.n_measured} by measuring the evidence")
        if getattr(run, "n_consensus", 0):
            how.append(f"{run.n_consensus} read and challenged")
        if getattr(run, "n_propagated", 0):
            how.append(f"{run.n_propagated} carried from an identical result")
        detail = f" — {', '.join(how)}" if how else ""
        rows.append(
            f"| Undecided results settled by review | {run.n_auto_resolved}{detail} "
            f"(advisory — not counted as confirmed findings) |"
        )
    if run.n_manual_review:
        rows.append(f"| Still needs manual review | **{run.n_manual_review}** |")
    if run.n_rerun:
        rows.append(f"| Needs a re-run (server error / tooling) | {run.n_rerun} |")
    if getattr(run, "n_reran", 0):
        rows.append(
            f"| Transient failures re-sent during review | {run.n_reran} "
            "(their result below is the re-run's) |"
        )
    return rows


def _review_cell(adjudication) -> str:
    """What the reviewing agent made of an undecided row.

    Deliberately says *who* decided, in the cell itself. A reader scanning a
    column of results must not have to remember that some of these came from a
    hashed, rule-derived verdict and some are an agent's reading — so the
    advisory ones carry the word, every time, in the same place.
    """
    if adjudication is None:
        return "—"
    if adjudication.needs_manual_review:
        return "needs a person"
    result = adjudication.assessed_result
    if result == "INCONCLUSIVE":
        return "re-run"
    emoji = RESULT_EMOJI.get(result, "")
    # "measured" and "agent" are different assurances: the first reproduces on
    # the same evidence with no model involved, the second is a reading. The
    # word is the only thing distinguishing them for a reader who cannot open
    # the report, so it goes in the cell.
    who = "measured" if getattr(adjudication, "resolution", "") == "measured" else "agent"
    return f"{emoji} {result} ({who}, advisory)"


def _results_table(executions: list[Execution], tests: dict[str, TestCase],
                   limit: int, adjudications: dict | None = None) -> list[str]:
    """Every test, one row. The whole point of the comment now.

    The `Review` column only appears when somebody has run the adjudicating
    agent — an empty column of dashes would suggest a review happened and found
    nothing to say.
    """
    adjudications = adjudications or {}
    review_head = " Review |" if adjudications else ""
    review_rule = "---|" if adjudications else ""
    lines = [
        f"| Test | OWASP | Attack | Request sent | Status | Result |{review_head}",
        f"|---|---|---|---|---|---|{review_rule}",
    ]
    for execution in executions[:limit]:
        test = tests.get(execution.test_id)
        kind = test.attack_mutation.kind if test else ""
        status = f"HTTP {execution.response.status_code}" if execution.response else "not sent"
        emoji = RESULT_EMOJI.get(execution.verdict.result.value, "")
        review = (f" {_cell(_review_cell(adjudications.get(execution.execution_id)), 28)} |"
                  if adjudications else "")
        lines.append(
            f"| {_cell(execution.test_id, 24)} "
            f"| {_cell(execution.owasp_category, 12)} "
            f"| {_cell(kind, 26)} "
            f"| {_cell(_short_request(execution), 60)} "
            f"| {_cell(status, 14)} "
            f"| {emoji} {execution.verdict.result.value} |{review}"
        )
    if len(executions) > limit:
        trailing = " |" if adjudications else ""
        lines.append(
            f"| … | | | | | {len(executions) - limit} more row(s) omitted |{trailing}"
        )
    return lines


# --- entry point -------------------------------------------------------------


def build_comment(
    issue_key: str,
    target: str,
    tests: dict[str, TestCase],
    executions: list[Execution],
    findings: list[Finding],
    evidence_chain_ok: bool,
    *,
    run_assessment=None,
    report_url: str = "",
    max_finding_rows: int = 20,
    max_table_rows: int = 60,
    max_chars: int = 30_000,
    plan_stale: bool = False,
    uncovered_endpoints: list[str] | None = None,
) -> str:
    """Summary + the full results table. Explanation lives in the report.

    `run_assessment` is the agent-reviewed run verdict (passed/failed plus
    requirement coverage). It is optional: absent, the comment omits those rows
    rather than inventing a number.

    `plan_stale` says the tests below were designed from an endpoint list that
    has since been edited on the platform. The ticket is often the only place a
    stakeholder ever looks, so this warning has to travel here too — the
    dashboard's own staleness banner never reaches a reader who only opens Jira.

    `uncovered_endpoints` names endpoint signatures a PoC-derived test actually
    hits that never made the endpoint list at all — a gap present from the
    first design, not from any later edit (see
    `app.owasp.coverage.uncovered_poc_endpoints`).

    The old `max_detail_blocks` parameter is gone along with the blocks it
    bounded. Callers passing it will fail loudly rather than silently getting a
    comment that ignores the limit they asked for.
    """
    counts = Counter(e.verdict.result.value for e in executions)
    fail_n = counts.get("FAIL", 0)
    ordered = sorted(executions, key=lambda e: (_RESULT_ORDER.get(e.verdict.result, 9), e.test_id))

    lines = [
        f"## Security Testing Completed — {_safe(issue_key)}",
        "",
        f"**Environment tested:** {_code(target, 120)}",
        "",
    ]
    if plan_stale:
        lines += [
            "_⚠️ The endpoint list for this assessment was edited after this test plan "
            "was designed. The results below may not reflect the current attack surface — "
            "re-run Design before relying on this as a final answer._",
            "",
        ]
    if uncovered_endpoints:
        lines += [
            "_⚠️ The following test(s) target an endpoint that was never added to this "
            f"assessment's endpoint list: {', '.join(_cell(s, 60) for s in uncovered_endpoints)}. "
            "Review whether that endpoint belongs on the list before treating these results "
            "as covering it._",
            "",
        ]
    lines += [
        "| Metric | Value |",
        "|---|---|",
        f"| Tests executed | {len(executions)} |",
        f"| {RESULT_EMOJI['FAIL']} FAIL (confirmed) | {f'**{fail_n}**' if fail_n else fail_n} |",
        f"| {RESULT_EMOJI['INCONCLUSIVE']} INCONCLUSIVE (needs review) | {counts.get('INCONCLUSIVE', 0)} |",
        f"| {RESULT_EMOJI['PASS']} PASS (control held) | {counts.get('PASS', 0)} |",
        f"| {RESULT_EMOJI['BLOCKED']} BLOCKED (not sent) | {counts.get('BLOCKED', 0)} |",
        f"| {RESULT_EMOJI['ERROR']} ERROR (tooling) | {counts.get('ERROR', 0)} |",
    ]
    lines += _assessment_rows(run_assessment)
    lines.append("")

    # 1. Confirmed findings, one row each. A reader who stops after the first
    #    screen has to have seen what broke.
    lines.append(f"### {RESULT_EMOJI['FAIL']} Confirmed findings ({len(findings)})")
    lines.append("")
    if findings:
        lines += _findings_table(findings, max_finding_rows)
        lines.append("")
        lines.append(
            "_Impact, reproduction steps and the recommended fix for each finding are in "
            "the report, beside the captured request and response that prove it._"
        )
        lines.append("")
    else:
        lines += [("No confirmed findings. A confirmed finding requires correlated "
                   "evidence (disclosed data, or a verified state change) — an "
                   "unexpected success status alone remains INCONCLUSIVE unless "
                   "the audited derived-verdict policy accepts independent proof."), ""]

    # 2. Everything, one row per test. Passes are coverage evidence: "we tested
    #    this and the control held" is the other half of the report.
    if executions:
        lines += ["### All test results", ""]
        lines += _results_table(ordered, tests, max_table_rows,
                                adjudications=_by_execution(run_assessment))
        lines.append("")

    undecided = sum(1 for e in executions if e.verdict.result in
                    (TestStatus.INCONCLUSIVE, TestStatus.ERROR, TestStatus.BLOCKED))
    lines += _where_the_detail_is(undecided, report_url)
    lines.append(_evidence_footer(executions, evidence_chain_ok))
    comment = "\n".join(lines)

    if len(comment) > max_chars:
        # Cut on a line boundary so the truncation cannot land mid-table and
        # leave a half-rendered row.
        head = comment[:max_chars].rsplit("\n", 1)[0]
        comment = (
            f"{head}\n\n_⚠️ This comment was truncated to fit Jira's length limit. "
            "The complete result set, including full request/response evidence, is in "
            "the security testing platform's report for this assessment._"
        )
    return comment


def _by_execution(run) -> dict:
    """Adjudications keyed by execution id, or {} when none were made."""
    if run is None:
        return {}
    return {a.execution_id: a for a in run.adjudications}


def _where_the_detail_is(undecided: int, report_url: str) -> list[str]:
    """Say what is in the report and why it is not here.

    Without this the comment reads as if it were the whole result. It is not,
    and a reader who wants "what exactly was sent, and why was that a break"
    needs to be told where that is — with a link when the platform has been told
    what URL it is reachable at, and by name when it has not, because a
    localhost link that 404s for every reader costs more than an absent one.
    """
    where = (f"[the report]({report_url})" if report_url
             else "the security testing platform's report for this assessment")
    lines = ["### Full detail", ""]
    body = (
        f"Per test, {where} carries the attack performed and its parameters, the exact "
        "request as sent, what a secure system was expected to return versus what came "
        "back, the verdict's reasoning, and the positive-control and read-back exchanges "
        "the verdict leaned on — alongside the captured request and response themselves."
    )
    if undecided:
        body += (
            f" {undecided} result(s) here are undecided; the report explains what each one "
            "was missing and offers a single-row re-run for the ones that only need sending "
            "again."
        )
    lines += [body, ""]
    return lines


def _evidence_footer(executions: list[Execution], chain_ok: bool) -> str:
    if executions and not chain_ok:
        return (
            f"_⚠️ Evidence chain FAILED verification for {len(executions)} execution(s) — "
            "at least one record's hash no longer matches its content. Treat this result "
            "as non-authoritative until investigated in the security testing platform._"
        )
    return (
        f"_Evidence chain verified — {len(executions)} execution(s) sealed with a "
        "SHA-256 hash chain. Full request/response evidence and reproduction steps "
        "are in the security testing platform's report for this assessment. Values "
        "disclosed by a failing test are deliberately not reproduced here; they are "
        "in the captured response body evidence._"
    )
