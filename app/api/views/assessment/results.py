"""Phase 4 — Results: verdicts, confirmed findings, and what still needs a
person.

A verdict that needs a human is surfaced, never rounded to PASS.
"""

from __future__ import annotations

import json

from app.api import ui
from app.api.ui import attr, e, info
from .state import TIP, _State
from app.core.i18n import VI, tt as _t

_VERDICT_ORDER = ("FAIL", "INCONCLUSIVE", "PASS", "BLOCKED", "ERROR")


def _verdict_strip(verdicts: dict) -> str:
    """"0 findings" and "every test came back BLOCKED" look identical from the
    outside, and only one of them means the target held up."""
    if not verdicts:
        return ""
    pills = "".join(
        f'<span style="margin-right:8px">{ui.pill(f"{name} {verdicts[name]}", ui.VERDICT_CLASS.get(name, "info"))}</span>'
        for name in _VERDICT_ORDER if verdicts.get(name)
    )
    others = "".join(
        f'<span style="margin-right:8px">{ui.pill(f"{name} {n}", "info")}</span>'
        for name, n in sorted(verdicts.items()) if name not in _VERDICT_ORDER
    )
    return (f'<div class="row" style="gap:0;margin:0 0 14px;align-items:center">'
            f'<span class="glabel" style="margin:0 10px 0 0">{_t("Verdicts")}'
            f'{info(TIP["verdict"], _t("Verdicts"))}</span>{pills}{others}</div>')


_OVERALL_TONE = {"PASSED": "ok", "FAILED": "crit", "INCOMPLETE": "med"}


def _triage_summary(triage: dict) -> str:
    """"4 need you, 2 just need re-running" — before anyone spends a minute or a
    token. The counts come from the deterministic triage, so this is available
    whether or not an AI reviewer is configured."""
    if not triage:
        return ""
    parts = []
    for key, label in (("manual", _t("need a person")), ("agent", _t("are a reading task")),
                       ("rerun", _t("need only a re-run"))):
        if triage.get(key):
            parts.append(f"<b>{triage[key]}</b> {label}")
    if not parts:
        return ""
    intro = _t("Of the undecided results, {parts}.").format(parts=", ".join(parts))
    return f"<p class='muted' style='margin:0 0 10px'>{intro}</p>"


def _assessment_panel(aid: str, run, st: _State, triage: dict) -> str:
    """Passed or failed, how much of the ticket was covered, and what is left.

    The button is deliberately separate from Execute: reviewing results is a
    read-only pass over evidence that already exists, it costs API calls, and a
    tester should be able to run it, disagree with it and run it again without
    re-sending a single request to the target.
    """
    if not st.n_executions:
        return ""
    if run is None:
        not_reviewed_note = _t(
            "The reviewing agent triages every undecided result — which need you, which "
            "only need re-running, which can be settled by reading the captured response "
            "— then answers whether this run passed and how much of the ticket it "
            "covered. It never overwrites a sealed verdict; strong proof may be "
            "recorded separately by the audited promotion policy."
        )
        return (
            "<div class='card pad' style='margin-bottom:14px'>"
            f"<p style='margin:0 0 8px'><b>{_t('These results have not been reviewed.')}</b> "
            f"<span class='muted'>{not_reviewed_note}</span></p>"
            + _triage_summary(triage) +
            f"<form method='post' action='/assessment/{attr(aid)}/adjudicate' "
            "class='js-busy' style='margin:0'>"
            f"<button class='btn sec'>{_t('Review Results')}</button></form></div>"
        )

    tone = _OVERALL_TONE.get(run.overall, "info")
    manual = run.manual_review_items
    manual_html = _blocker_groups(manual) + _manual_table(manual)

    resolved = run.auto_resolved
    resolved_html = ""
    if resolved:
        advisory_word = _t("advisory")
        rows = "".join(
            f'<tr><td class="mono">{e(a.test_id)}</td>'
            f'<td>{ui.pill(_t(a.assessed_result), ui.VERDICT_CLASS.get(a.assessed_result, "info"))}'
            f' <span class="muted">{advisory_word}</span></td>'
            f'<td class="muted">{_resolution_label(a)}</td>'
            f'<td>{e(a.rationale)}</td></tr>'
            for a in resolved[:12]
        )
        settled_note = _t(
            "(advisory — the sealed verdict and the finding count are unchanged directly; "
            "derived promotion is audited separately)"
        )
        resolved_html = (
            f'<div class="glabel" style="margin-top:12px">{_t("Settled by Review")} '
            f'<span class="muted">{settled_note}</span></div>'
            + ui.table([_t("Test"), _t("Read as"), _t("How"), _t("Why")], rows, cls="compact",
                       scroll=len(resolved) > 8)
            + _how_settled_line(run)
        )

    degraded = (f"<p class='muted' style='margin:6px 0 0'>&#9888; {e(run.degraded_reason)}</p>"
                if run.degraded_reason else "")
    who = _t("AI Reviewer") if run.reviewer == "ai" else _t("deterministic triage only")
    header_meta = _t("· {decided}% of executions decided · reviewed by {who}").format(
        decided=run.decided_pct, who=e(who))
    coverage_label = _t("{pct}% of the ticket covered").format(pct=run.coverage_pct)
    return (
        f"<div class='card pad' style='margin-bottom:14px'>"
        f"<div class='row' style='gap:10px;align-items:center;margin:0 0 6px'>"
        f"{ui.pill(_t(run.overall), tone)}"
        f"<b>{coverage_label}</b>"
        f"<span class='muted'>{header_meta}</span></div>"
        f"<p style='margin:0'>{e(run.summary)}</p>{degraded}"
        f"{manual_html}{resolved_html}"
        f"<form method='post' action='/assessment/{attr(aid)}/adjudicate' class='js-busy' "
        f"style='margin:12px 0 0'>"
        f"<button class='btn ghost'>&#8635; {_t('Review Again')}</button>"
        + _rerun_transient_control(run) +
        "</form></div>"
    )


def _rerun_transient_control(run) -> str:
    """The one part of a review pass that sends traffic, behind its own checkbox.

    Only offered when there is actually something to re-send. A checkbox rather
    than a second button because the re-run is part of the same pass — re-sending
    the transient failures and then not reviewing them would leave the run in a
    state nobody asked for.
    """
    if not run.n_rerun:
        return ""
    label = _t(
        "also re-send the {n} result(s) that need only another attempt (a server "
        "error or a runner failure) — this sends real requests"
    ).format(n=run.n_rerun)
    return (
        "<label class='muted' style='display:inline-flex;gap:6px;align-items:center;"
        "margin-left:12px'>"
        "<input type='checkbox' name='rerun_transient' value='1'>"
        f"<span>{label}</span></label>"
    )


# What kind of thing is in the way, and therefore what clears it. Grouping the
# queue by this is the difference between "14 results need you" (a wall) and
# "9 of them are one stale object id" (a first move).
_BLOCKER_LABEL = {
    "test_data": ("Test data", "A stale object id or a persona without the entitlement — "
                              "the positive control failed, so nothing about the attack's "
                              "rejection means anything yet. Fix the data and re-run."),
    "config": ("Configuration", "Scope, policy or the network stopped the request before it "
                                "was sent. Nothing ran, so there is nothing to read."),
    "no_evidence": ("No Evidence Captured", "It ran, but captured nothing readable either "
                                            "way. Add a secret marker on the target persona "
                                            "or a verification read-back, then re-run."),
    "ambiguous": ("Genuinely ambiguous", "There is readable evidence and it does not settle "
                                         "the question. This is the bucket that actually "
                                         "needs your judgement."),
    "unread": ("Not Read", "No reader was available — the AI adjudicator is not configured, "
                           "or this pass ran out of its review budget."),
}


def _blocker_groups(manual: list) -> str:
    """"What would clear these" as counts, above the row-by-row list."""
    if not manual:
        return ""
    counts: dict[str, int] = {}
    for adjudication in manual:
        counts[adjudication.blocker or "ambiguous"] = counts.get(
            adjudication.blocker or "ambiguous", 0) + 1
    if len(counts) <= 1 and len(manual) < 3:
        return ""
    chips = ""
    for key, (label, why) in _BLOCKER_LABEL.items():
        if not counts.get(key):
            continue
        chips += (
            f"<span class='pill info' title='{attr(_t(why))}'>"
            f"<b>{counts[key]}</b> {_t(label)}</span> "
        )
    if not chips:
        return ""
    intro = _t("What Is in the Way")
    return (f"<div class='glabel' style='margin-top:12px'>{intro}</div>"
            f"<div class='row' style='gap:6px;flex-wrap:wrap;margin:0 0 4px'>{chips}</div>")


def _manual_table(manual: list) -> str:
    if not manual:
        return ""
    rows = ""
    for adjudication in manual[:12]:
        note = adjudication.challenge_note or adjudication.recommended_action
        rows += (
            f'<tr><td class="mono">{e(adjudication.test_id)}</td>'
            f'<td>{e(adjudication.triage_reason)}</td>'
            f'<td class="muted">{e(note)}</td></tr>'
        )
    html = (
        f'<div class="glabel" style="margin-top:8px">{_t("Still Needs You")}'
        f'{info(TIP["review"], _t("Review"))}</div>'
        + ui.table([_t("Test"), _t("Why It Is Undecided"), _t("What Would Settle It")],
                   rows, cls="compact", scroll=len(manual) > 8)
    )
    if len(manual) > 12:
        more_label = _t("{n} more in the report.").format(n=len(manual) - 12)
        html += f"<p class='muted' style='margin:6px 0 0'>{more_label}</p>"
    return html


def _resolution_label(adjudication) -> str:
    """How this row was settled — never left for the reader to guess.

    "Measured" and "read by the agent" are different assurances: the first
    reproduces on the same evidence with no model involved, the second is an
    opinion that survived a challenge. Collapsing them into one "settled" column
    would be the most misleading thing on the page.
    """
    resolution = getattr(adjudication, "resolution", "")
    if resolution == "measured":
        rule = getattr(adjudication, "rule", "")
        measured = _t("measured")
        return f"{measured}<span class='muted'> · {e(rule)}</span>" if rule else measured
    if resolution == "ai_consensus":
        return _t("read, then challenged")
    if resolution == "propagated":
        source = getattr(adjudication, "read_from", "")
        carried = _t("carried from an identical result")
        return f"{carried}<span class='muted'> · {e(source)}</span>" if source else carried
    if resolution == "ai":
        return _t("read by the agent")
    return _t("settled")


def _how_settled_line(run) -> str:
    parts = []
    if run.n_measured:
        parts.append(_t("{n} by measuring the evidence (no model involved)").format(
            n=run.n_measured))
    if run.n_consensus:
        parts.append(_t("{n} read and then challenged by a second pass").format(
            n=run.n_consensus))
    if run.n_propagated:
        parts.append(_t("{n} carried from an identical reading task").format(
            n=run.n_propagated))
    if not parts:
        return ""
    return f"<p class='muted' style='margin:6px 0 0'>{', '.join(parts)}.</p>"


_DECISION_SOURCE_LABEL = {
    "sealed_runner": ("Runner-Sealed", "ok"),
    "measured": ("measured", "ok"),
    "ai_consensus": ("AI-Adjudicated", "med"),
}


def _finding_provenance_pill(decision_source: str) -> str:
    label, tone = _DECISION_SOURCE_LABEL.get(decision_source, (decision_source, "info"))
    return ui.pill(_t(label), tone)


def _finding_triage_controls(aid: str, finding_id: str, state: dict | None, back: str) -> str:
    """Mark-as-false-positive / reopen — never touches the sealed verdict or
    the finding's own fields, just a reviewer's own opinion recorded beside it."""
    is_fp = bool(state) and state.get("status") == "false_positive"
    if is_fp:
        note = e(state.get("note", "")) if state.get("note") else ""
        badge = ui.pill(_t("False Positive"), "med") + (
            f'<div class="muted" style="font-size:11px;margin-top:2px">{note}</div>' if note else ""
        )
        return (
            f'{badge}<form method="post" style="margin-top:4px" '
            f'action="/assessment/{attr(aid)}/findings/{attr(finding_id)}/triage">'
            f'<input type="hidden" name="status" value="open">'
            f'<input type="hidden" name="back" value="{attr(back)}">'
            f'<button class="btn sec" style="font-size:11px;padding:2px 8px">{_t("Reopen")}</button></form>'
        )
    return (
        f'<form method="post" action="/assessment/{attr(aid)}/findings/{attr(finding_id)}/triage">'
        f'<input type="hidden" name="status" value="false_positive">'
        f'<input type="hidden" name="back" value="{attr(back)}">'
        f'<input type="text" name="note" placeholder="{attr(_t("Why? (optional)"))}" '
        f'style="font-size:11px;width:110px;margin-right:4px">'
        f'<button class="btn sec" style="font-size:11px;padding:2px 8px">{_t("Mark FP")}</button></form>'
    )


def _results_section(aid: str, issue_key: str, st: _State, findings, verdicts: dict,
                     opened: bool, run=None, triage: dict | None = None,
                     finding_triage: dict | None = None) -> str:
    finding_triage = finding_triage or {}
    back = f"/assessment/{attr(aid)}?phase=results"
    rows = ""
    for f in findings:
        tone = ui.SEV_CLASS.get(f.severity.value, "info")
        rows += (
            f'<tr><td class="mono"><b>{e(f.finding_id)}</b></td>'
            f"<td>{e(f.title)}</td>"
            f'<td class="mono">{e(f.owasp_category.value.split(":")[0])}</td>'
            f"<td>{ui.pill(f.severity.value, tone)}</td>"
            f'<td>{_finding_provenance_pill(f.decision_source)}</td>'
            f'<td class="mono"><span class="trunc">{e(f.endpoint)}</span></td>'
            f'<td class="mono muted">{e(", ".join(f.affected_tests))}</td>'
            f'<td>{_finding_triage_controls(aid, f.finding_id, finding_triage.get(f.finding_id), back)}</td>'
            "</tr>"
        )
    findings_table = ui.table(
        [_t("ID"), _t("Title"), "OWASP", _t("Severity"), _t("Source"), _t("Endpoint"),
         _t("Tests"), _t("Triage")],
        rows,
        empty=_t(
            "No confirmed findings. An inconclusive result is not a finding — "
            "open the report to see what was undecided and why."
        ),
        scroll=len(findings) > 12,
        cls="compact",
    )
    rerun = ""
    if st.n_executions:
        # A re-run is a new assessment of the same issue, not a second pass over
        # this one: regression only exists between assessments, and re-running in
        # place would rewrite the conclusions attached to evidence already
        # reported.
        rerun_note = _t(
            "Both create a <b>new</b> assessment of {issue} and leave this run intact as "
            "the regression baseline. Re-running copies this plan and its approvals and "
            "sends the approved <b>non-destructive</b> tests &mdash; approving a write "
            "probe once, for a run you watched, is not consent to it firing again from a "
            "button. Re-importing re-reads the ticket and generates nothing."
        ).format(issue=e(issue_key))
        reimport_confirm = _t(
            "Re-import {issue} from Jira?\n\nCreates a new assessment from the ticket "
            "as it reads now. No tests are generated and nothing runs."
        ).format(issue=e(issue_key))
        rerun_confirm = _t(
            "Re-run {issue}?\n\nCreates a new assessment with this plan and its "
            "approvals, then runs the approved non-destructive tests against the "
            "default environment. This run is kept as the baseline."
        ).format(issue=e(issue_key))
        working_label = _t("Working…")
        rerun = f"""<div class="glabel" style="margin-top:16px">{_t("Run Again")}</div>
<div class="actionrow">
<form method="post" action="/assessment/{attr(aid)}/rerun" class="rerun-form" style="margin:0"
 data-kind="same">
<input type="hidden" name="mode" value="same">
<button class="btn sec">&#8635; {_t("Re-run This Plan")}</button></form>
<form method="post" action="/assessment/{attr(aid)}/rerun" class="rerun-form" style="margin:0"
 data-kind="reimport">
<input type="hidden" name="mode" value="reimport">
<button class="btn ghost">{_t("Re-import from Jira")}</button></form>
</div>
<p class="muted" style="margin:8px 0 0;font-size:12.5px">{rerun_note}</p>
<script>
document.querySelectorAll('.rerun-form').forEach(function (f) {{
  f.addEventListener('submit', function (ev) {{
    var msg = f.dataset.kind === 'reimport'
      ? {json.dumps(reimport_confirm)}
      : {json.dumps(rerun_confirm)};
    if (!stpConfirmSubmit(f, ev, msg)) return;
    var btn = f.querySelector('button');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> ' + {json.dumps(working_label)};
  }});
}});
</script>"""

    body = f"""{_verdict_strip(verdicts)}
{_assessment_panel(aid, run, st, triage or {})}
{findings_table}{rerun}
<div class="glabel" style="margin-top:16px">{_t("View")}</div>
<div class="actionrow">
<a class="btn sec" href="/assessment/{attr(aid)}/report" target="_blank">{_t("HTML Report")} ↗</a>
<a class="btn sec" href="/assessment/{attr(aid)}/regression">{_t("Regression Diff")}</a>
<a class="btn sec" href="/assessment/{attr(aid)}/comment">{_t("Preview Jira Comment")}</a>
</div>
<div class="glabel">{_t("Export")}</div>
<div class="actionrow">
<a class="btn sec" href="/assessment/{attr(aid)}/export.html" title="{_t('Full report: findings, coverage, and every captured request/response with copy-cURL replay.')}">HTML</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.pdf" title="{_t('Findings and coverage only — no request/response evidence, for a quick print/share.')}">PDF</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.md" title="{_t('Findings and coverage as Markdown — paste straight into a GitHub/GitLab issue, wiki, or PR description.')}">Markdown</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.xlsx" title="{_t('Everything in sortable/filterable spreadsheet form — summary, coverage, test cases, executions, findings.')}">XLSX</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.json" title="{_t('The full machine-readable record — everything the other formats are rendered from.')}">JSON</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.postman" title="{_t('Approved tests as a Postman collection, for replay with Newman outside this platform.')}">Postman (Newman)</a>
</div>"""
    summary = _t("{n} Finding(s)").format(n=len(findings)) if st.n_executions else _t("Not Run Yet")
    if run is not None:
        summary = _t("{overall} · {pct}% Covered · ").format(
            overall=_t(run.overall), pct=run.coverage_pct) + summary
    return ui.section(
        "s-results", "", _t("Results"), body,
        summary=summary,
        open=opened,
        tip=_t(
            "A finding requires either a sealed runner FAIL or a hash-bound derived "
            "decision accepted by the conservative promotion policy."
        ),
    )


# -- flash ------------------------------------------------------------------


VI.update({
    "Verdicts": "Kết Luận",
    "need a person": "cần người xem", "are a reading task": "cần đọc lại",
    "need only a re-run": "chỉ cần chạy lại",
    "Of the undecided results, {parts}.": "Trong các kết quả chưa rõ, {parts}.",
    "These results have not been reviewed.": "Các kết quả này chưa được đánh giá.",
    "The reviewing agent triages every undecided result — which need you, which "
    "only need re-running, which can be settled by reading the captured response "
    "— then answers whether this run passed and how much of the ticket it "
    "covered. It never overwrites a sealed verdict and never creates a finding.":
        "Agent đánh giá phân loại từng kết quả chưa rõ — cái nào cần bạn, cái nào chỉ "
        "cần chạy lại, cái nào giải quyết được bằng cách đọc phản hồi đã ghi lại — rồi "
        "trả lời lượt chạy này có đạt không và đã phủ bao nhiêu phần ticket. Nó không "
        "bao giờ ghi đè kết luận đã niêm phong và không tạo finding.",
    "Review Results": "Đánh Giá Kết Quả",
    "Still Needs You": "Vẫn Cần Bạn", "Review": "Đánh Giá",
    "Test": "Test", "Why It Is Undecided": "Vì Sao Chưa Rõ",
    "What Would Settle It": "Cần Gì Để Giải Quyết",
    "{n} more in the report.": "{n} mục nữa trong báo cáo.",
    "advisory": "tham khảo", "Settled by Review": "Đã Giải Quyết Qua Đánh Giá",
    "(advisory — the sealed verdict and the finding count are unchanged)":
        "(chỉ tham khảo — kết luận đã niêm phong và số finding không đổi)",
    "(sealed verdict unchanged; derived promotion is audited separately)":
        "(kết luận niêm phong không đổi; việc nâng cấp dẫn xuất được audit riêng)",
    "(advisory — the sealed verdict and the finding count are unchanged directly; "
    "derived promotion is audited separately)":
        "(chỉ tham khảo — kết luận niêm phong và số finding không đổi trực tiếp; "
        "việc nâng cấp dẫn xuất được audit riêng)",
    "Read as": "Đọc Là", "Why": "Vì Sao",
    "AI Reviewer": "AI Reviewer", "deterministic triage only": "chỉ phân loại tất định",
    "· {decided}% of executions decided · reviewed by {who}":
        "· {decided}% lượt thực thi đã quyết · người đánh giá {who}",
    "{pct}% of the ticket covered": "{pct}% Ticket Đã Được Phủ",
    "ID": "ID", "Title": "Tiêu Đề", "Endpoint": "Endpoint", "Tests": "Test",
    "No confirmed findings. An inconclusive result is not a finding — "
    "open the report to see what was undecided and why.":
        "Không có phát hiện nào được xác nhận. Kết quả chưa rõ không phải là finding — "
        "mở báo cáo để xem điều gì chưa rõ và vì sao.",
    "Both create a <b>new</b> assessment of {issue} and leave this run intact as "
    "the regression baseline. Re-running copies this plan and its approvals and "
    "sends the approved <b>non-destructive</b> tests &mdash; approving a write "
    "probe once, for a run you watched, is not consent to it firing again from a "
    "button. Re-importing re-reads the ticket and generates nothing.":
        "Cả hai đều tạo một assessment <b>mới</b> cho {issue} và giữ nguyên lượt chạy "
        "này làm mốc so sánh regression. Chạy lại sẽ sao chép kế hoạch này cùng các "
        "duyệt hiện có và gửi các test <b>không phá huỷ</b> đã duyệt &mdash; duyệt một "
        "phép thử ghi dữ liệu một lần, cho một lượt chạy bạn đã xem, không phải là đồng "
        "ý cho nó chạy lại từ một nút bấm. Nhập lại sẽ đọc lại ticket và không tạo gì cả.",
    "Re-import {issue} from Jira?\n\nCreates a new assessment from the ticket "
    "as it reads now. No tests are generated and nothing runs.":
        "Nhập lại {issue} từ Jira?\n\nTạo một assessment mới từ nội dung ticket hiện "
        "tại. Không tạo test nào và không chạy gì cả.",
    "Re-run {issue}?\n\nCreates a new assessment with this plan and its "
    "approvals, then runs the approved non-destructive tests against the "
    "default environment. This run is kept as the baseline.":
        "Chạy lại {issue}?\n\nTạo một assessment mới với kế hoạch này và các duyệt hiện "
        "có, rồi chạy các test không phá huỷ đã duyệt trên môi trường mặc định. Lượt "
        "chạy này được giữ làm mốc so sánh.",
    "Working…": "Đang Xử Lý…",
    "Run Again": "Chạy Lại", "Re-run This Plan": "Chạy Lại Kế Hoạch Này",
    "Re-import from Jira": "Nhập Lại Từ Jira",
    "View": "Xem", "HTML Report": "Báo Cáo HTML", "Regression Diff": "So Sánh Regression",
    "Preview Jira Comment": "Xem Trước Comment Jira", "Export": "Xuất",
    "{n} Finding(s)": "{n} Phát Hiện", "Not Run Yet": "Chưa Chạy",
    "{overall} · {pct}% Covered · ": "{overall} · Phủ {pct}% · ",
    "PASSED": "ĐẠT", "FAILED": "LỖI", "INCOMPLETE": "CHƯA HOÀN TẤT",
    "Results": "Kết Quả",
    "A finding is only minted from a test the runner judged FAIL — a confirmed "
    "control break with disclosure in the response.":
        "Một finding chỉ được tạo từ test mà runner đánh giá là LỖI — control thực sự bị "
        "phá vỡ và phản hồi có để lộ điều đó.",
    "A finding requires either a sealed runner FAIL or a hash-bound derived "
    "decision accepted by the conservative promotion policy.":
        "Finding cần runner niêm phong FAIL hoặc một quyết định dẫn xuất gắn hash "
        "được policy nâng cấp thận trọng chấp nhận.",
    "Open Ticket": "Mở Ticket",
})
