"""Phase 2 — Plan: importing a PoC, generating the tests, and approving them.

The table filters, sorts and pages server-side, which is what makes "approve
all 312 matching this filter" mean the same thing you just read on screen.
"""

from __future__ import annotations


from app.api import ui
from app.api.ui import attr, e, info
from .state import TIP
from app.core.i18n import VI, tt as _t
from app.schemas.testcase import TestCase

def _poc_files_notice(scripts: list, unreachable: list) -> str:
    """Which PoC files the ticket carried, named, before anything is generated.

    A ticket with two PoC scripts is the normal case for an automated intake
    tool, and the textarea below shows them as one banner-separated blob because
    that is what an editable field can hold. That is exactly the presentation
    that used to hide the second file: nothing on the page said how many there
    were or where each came from, so a tester scrolling a textarea had no way to
    notice a script was missing. This says it explicitly, and it names the
    attachments the connector could not download so the gap is visible rather
    than absent.
    """
    if not scripts and not unreachable:
        return ""
    out = ""
    if scripts:
        chips = ""
        for script in scripts:
            filename = script.get("filename", "") if isinstance(script, dict) else ""
            origin = script.get("origin", "") if isinstance(script, dict) else ""
            inferred = bool(script.get("inferred")) if isinstance(script, dict) else False
            hint = _t("found in {origin}").format(origin=origin) if origin else ""
            if inferred:
                hint += " · " + _t("no language tag — read as Python because it parses "
                                   "as Python and calls an HTTP library; give this one a "
                                   "closer look")
            chips += (f"<span class='pill info' title='{attr(hint)}'>"
                      f"<span class='mono'>{e(filename)}</span></span> ")
        headline = _t("{n} PoC script(s) found in this ticket").format(n=len(scripts))
        out += (
            f"<p style='margin:0 0 6px'>\U0001F7E1 <b>{headline}</b> "
            f"<span class='muted'>" + _t(
                "— pre-filled below, one banner-separated block per file. Each file is "
                "transpiled on its own, so two scripts cannot resolve each other's "
                "variables. <b>Review them</b>, then click Generate test plan. Nothing "
                "runs automatically."
            ) + "</span></p>"
            f"<div class='row' style='gap:6px;flex-wrap:wrap;margin:0 0 10px'>{chips}</div>"
        )
    if unreachable:
        names = ", ".join(e(str(n)) for n in unreachable)
        out += (
            "<p class='muted' style='margin:0 0 10px'>\u26A0 " + _t(
                "This ticket also attaches {names}, which the Jira connector cannot "
                "download. Open the attachment in Jira and paste it in below, or the "
                "plan will cover only the script(s) above."
            ).format(names=names) + "</p>"
        )
    return out


def _design_section(aid: str, detected_poc: str, has_tests: bool, opened: bool,
                    poc_scripts: list | None = None,
                    unreachable_pocs: list | None = None) -> str:
    notice = _poc_files_notice(poc_scripts or [], unreachable_pocs or [])
    if detected_poc and not notice:
        notice = (
            "<p class='muted' style='margin:0 0 10px'>"
            "\U0001F7E1 " + _t(
                "A PoC was found embedded in the Jira description and is pre-filled "
                "below — <b>review it</b>, then click Generate test plan to transpile it. "
                "Nothing runs automatically."
            ) + "</p>"
        )
    regen = ""
    if has_tests:
        regen = (
            "<p class='muted' style='margin:0 0 10px'>" + _t(
                "Regenerating replaces the current plan. An approval already given to a "
                "test that comes back unchanged is kept; anything whose request or "
                "mutation differs returns to PENDING."
            ) + "</p>"
        )
    parse_note = _t(
        "Parsed statically — dangerous constructs are flagged and the PoC is never executed."
    )
    depth_note = _t(
        "Aggressive generates several times more tests. Nothing runs until you approve "
        "it, so the cost is review time, not risk."
    )
    generate_label = _t("Regenerate test plan") if has_tests else _t("Generate test plan")
    return ui.section(
        "s-design", "", _t("Design test plan"), f"""
<div class="tabbar" role="tablist" aria-label="Proof-of-concept format">
<button class="active" role="tab" aria-selected="true" data-tab="t-py-{attr(aid)}">{_t("Python PoC")}</button>
<button role="tab" aria-selected="false" data-tab="t-pm-{attr(aid)}">Postman</button>
<button role="tab" aria-selected="false" data-tab="t-burp-{attr(aid)}">Burp XML</button>
<button role="tab" aria-selected="false" data-tab="t-jm-{attr(aid)}">JMeter</button>
</div>
<div style="padding-top:12px">
<form method="post" action="/assessment/{attr(aid)}/design" class="js-busy">
<p class="muted" style="margin:0 0 10px">{parse_note}</p>
{notice}{regen}
<div class="tabpane active" id="t-py-{attr(aid)}">
<label class="field"><span>{_t("Python PoC")}</span>
<textarea name="poc_python" rows="5" class="mono"
 placeholder="import requests&#10;requests.get(BASE + '/customers/2002', ...)">{e(detected_poc)}</textarea></label>
</div>
<div class="tabpane" id="t-pm-{attr(aid)}">
<label class="field"><span>{_t("Postman collection (v2.1) JSON")}</span>
<textarea name="poc_postman" rows="5" class="mono" placeholder="Paste exported collection JSON"></textarea></label>
</div>
<div class="tabpane" id="t-burp-{attr(aid)}">
<label class="field"><span>{_t("Burp Suite XML export")}</span>
<textarea name="burp_xml" rows="5" class="mono" placeholder="Paste raw-HTTP XML export"></textarea></label>
</div>
<div class="tabpane" id="t-jm-{attr(aid)}">
<label class="field"><span>{_t("JMeter .jmx test plan")}</span>
<textarea name="jmeter_xml" rows="5" class="mono" placeholder="Paste .jmx XML"></textarea></label>
</div>
<label class="field" style="margin-top:12px;max-width:520px"><span>{_t("Test depth")}</span>
<select name="depth">
<option value="standard" selected>{_t("Standard — the highest-value probe per applicable category")}</option>
<option value="aggressive">{_t("Aggressive — full variant matrix (every id placement, whole JWT suite, race windows)")}</option>
</select></label>
<p class="muted" style="margin:6px 0 0">{depth_note}</p>
<div style="margin-top:12px"><button class="btn">
{generate_label}</button></div>
</form>
</div>""",
        summary=_t("PoC import + depth"),
        open=opened,
        tip=_t(
            "A PoC is transpiled into declarative test cases — the code itself is never "
            "run. Leave every box empty to generate from the rules alone."
        ),
    )


# -- 3. coverage ------------------------------------------------------------


_REVIEW_TONE = {"APPROVE": "low", "REVISE": "med", "INSUFFICIENT": "crit"}


def _review_panel(aid: str, review, has_tests: bool) -> str:
    """The reviewing agent's critique, above the plan a tester is about to approve.

    Placed here rather than in a report because this is the moment it changes a
    decision. The failure mode it exists for is a tester approving what is in
    front of them without noticing what is not — so the unresolved gaps are shown
    at the point of approval, and the button that asks the planner to try again is
    right beside them.
    """
    if review is None:
        if not has_tests:
            return ""
        not_reviewed_note = _t(
            "The reviewing agent reads the ticket's requirements against the plan and "
            "names what is missing, then asks the planner to close the gaps. It adds "
            "tests; it never approves one."
        )
        return (
            "<div class='card pad' style='margin-bottom:14px'>"
            f"<p style='margin:0 0 8px'><b>{_t('This plan has not been reviewed.')}</b> "
            f"<span class='muted'>{not_reviewed_note}</span></p>"
            f"<form method='post' action='/assessment/{attr(aid)}/agent-plan' "
            "class='js-busy' style='margin:0'>"
            f"<button class='btn sec'>{_t('Review this plan')}</button></form></div>"
        )

    tone = _REVIEW_TONE.get(review.verdict, "info")
    unresolved = review.unresolved_gaps or []
    gap_items = "".join(
        f"<li><b>{_t(g.severity)}</b> &mdash; {e(g.label())}</li>" for g in unresolved
    )
    gaps_html = (
        f"<div class='glabel' style='margin-top:10px'>{_t('Still not covered')}"
        f"{info(TIP['gap'], _t('Gaps'))}</div>"
        f"<ul style='margin:4px 0 0;padding-left:18px' class='muted'>{gap_items}</ul>"
        if gap_items else ""
    )
    added = (
        "<p class='muted' style='margin:6px 0 0'>"
        + _t(
            "{n} test(s) were added to close gaps found at review time, over {rounds} "
            "revision round(s). They are PENDING like every other test."
        ).format(n=len(review.tests_added), rounds=review.rounds)
        + "</p>"
        if review.tests_added else ""
    )
    degraded = (
        f"<p class='muted' style='margin:6px 0 0'>&#9888; {e(review.degraded_reason)}</p>"
        if review.degraded_reason else ""
    )
    who = _t("AI reviewer") if review.reviewer == "ai" else _t("structural review (no AI)")
    review_meta = _t(
        "Coverage {cov}% · decidable {qual}% · reviewed by {who} · {n} test(s) reviewed"
    ).format(cov=review.coverage_score, qual=review.quality_score, who=e(who),
              n=review.tests_before)
    digest = getattr(review, "requirement_digest", None) or []
    digest_items = "".join(
        f"<li><span class='mono' style='font-size:12px'>{e(d.item_id)}</span> "
        f"{e(d.requirement)}<br><span class='muted'>{_t('Expect')}: {e(d.expected)}</span></li>"
        for d in digest
    )
    digest_html = (
        f"<div class='glabel' style='margin-top:10px'>{_t('What the ticket requires')}"
        f"{info(TIP['req_digest'], _t('Requirements'))}</div>"
        f"<ul style='margin:4px 0 0;padding-left:18px'>{digest_items}</ul>"
        if digest_items else ""
    )
    return (
        f"<div class='card pad' style='margin-bottom:14px'>"
        f"<div class='row' style='gap:10px;align-items:center;margin:0 0 6px'>"
        f"{ui.pill(_t(review.verdict), tone)}"
        f"<b>{e(review.headline())}</b></div>"
        f"<p class='muted' style='margin:0'>{review_meta}</p>"
        f"{digest_html}"
        f"{added}{degraded}{gaps_html}"
        f"<form method='post' action='/assessment/{attr(aid)}/agent-plan' class='js-busy' "
        f"style='margin:10px 0 0'>"
        f"<button class='btn ghost'>&#8635; {_t('Review again')}</button></form>"
        f"</div>"
    )


VI.update({
    "A PoC was found embedded in the Jira description and is pre-filled "
    "below — <b>review it</b>, then click Generate test plan to transpile it. "
    "Nothing runs automatically.":
        "Tìm thấy một PoC nhúng trong mô tả Jira và đã điền sẵn bên dưới — "
        "<b>xem lại</b>, rồi bấm Tạo kế hoạch test để chuyển đổi. Không có gì tự chạy.",
    "Regenerating replaces the current plan. An approval already given to a "
    "test that comes back unchanged is kept; anything whose request or "
    "mutation differs returns to PENDING.":
        "Tạo lại sẽ thay thế kế hoạch hiện tại. Một lượt duyệt đã có cho test không đổi "
        "sẽ được giữ nguyên; bất kỳ test nào có request hoặc mutation khác đi sẽ về "
        "PENDING.",
    "Parsed statically — dangerous constructs are flagged and the PoC is never executed.":
        "Phân tích tĩnh — các cấu trúc nguy hiểm được gắn cờ và PoC không bao giờ được "
        "thực thi.",
    "Aggressive generates several times more tests. Nothing runs until you approve "
    "it, so the cost is review time, not risk.":
        "Nâng cao tạo ra nhiều test hơn hẳn. Không có gì chạy cho tới khi bạn duyệt, "
        "nên cái giá phải trả là thời gian xem lại, không phải rủi ro.",
    "Regenerate test plan": "Tạo lại kế hoạch test", "Generate test plan": "Tạo kế hoạch test",
    "Design test plan": "Thiết kế kế hoạch test",
    "Python PoC": "Python PoC",
    "Postman collection (v2.1) JSON": "Postman collection (v2.1) JSON",
    "Burp Suite XML export": "Burp Suite XML export",
    "JMeter .jmx test plan": "JMeter .jmx test plan",
    "Test depth": "Độ sâu test",
    "Standard — the highest-value probe per applicable category":
        "Tiêu chuẩn — phép thử giá trị cao nhất cho mỗi danh mục áp dụng được",
    "Aggressive — full variant matrix (every id placement, whole JWT suite, race windows)":
        "Nâng cao — ma trận biến thể đầy đủ (mọi vị trí id, toàn bộ JWT suite, race window)",
    "PoC import + depth": "Nhập PoC + độ sâu",
    "A PoC is transpiled into declarative test cases — the code itself is never "
    "run. Leave every box empty to generate from the rules alone.":
        "Một PoC được chuyển đổi thành các test case khai báo — bản thân code không "
        "bao giờ được chạy. Để trống mọi ô để tạo chỉ từ rule engine.",
    "{n} test(s) →": "{n} test →",
    "{pct}% of this category comes from the imported PoC":
        "{pct}% của danh mục này đến từ PoC đã nhập",
    "{existing} PoC · {generated} gen": "{existing} PoC · {generated} gen",
    "Category": "Danh mục", "From PoC": "Từ PoC",
    "Generate a plan to compute coverage.": "Tạo kế hoạch để tính độ phủ.",
    "Show {n} category(ies) the analyzer judged not applicable":
        "Hiện {n} danh mục mà bộ phân tích cho là không áp dụng",
    "{n} applicable · {c} covered": "{n} áp dụng được · {c} đã phủ",
    "not computed yet": "chưa tính",
    "OWASP Coverage": "Độ phủ OWASP",
    "What this ticket needs tested, versus what the plan actually tests. The "
    "point of the tool is the gap between those two.":
        "Những gì ticket này cần được test, so với những gì kế hoạch thực sự test. "
        "Trọng tâm của công cụ này chính là khoảng cách giữa hai điều đó.",
    "This plan has not been reviewed.": "Kế hoạch này chưa được đánh giá.",
    "The reviewing agent reads the ticket's requirements against the plan and "
    "names what is missing, then asks the planner to close the gaps. It adds "
    "tests; it never approves one.":
        "Agent đánh giá đọc yêu cầu của ticket đối chiếu với kế hoạch và nêu ra những "
        "gì còn thiếu, sau đó yêu cầu planner lấp các lỗ hổng. Nó thêm test; không bao "
        "giờ tự duyệt test nào.",
    "Review this plan": "Đánh giá kế hoạch này",
    "Still not covered": "Vẫn chưa phủ", "Gaps": "Lỗ hổng",
    "What the ticket requires": "Yêu cầu của ticket", "Expect": "Kỳ vọng",
    "{n} test(s) were added to close gaps found at review time, over {rounds} "
    "revision round(s). They are PENDING like every other test.":
        "{n} test đã được thêm để lấp các lỗ hổng phát hiện lúc đánh giá, qua {rounds} "
        "vòng chỉnh sửa. Chúng ở trạng thái PENDING như mọi test khác.",
    "AI reviewer": "AI reviewer", "structural review (no AI)": "đánh giá cấu trúc (không AI)",
    "Coverage {cov}% · decidable {qual}% · reviewed by {who} · {n} test(s) reviewed":
        "Độ phủ {cov}% · có thể quyết {qual}% · người đánh giá {who} · đã xem {n} test",
    "Review again": "Đánh giá lại",
    "Test plan & approval": "Kế hoạch test & duyệt",
    "No tests yet. Generate a plan above — or add the endpoint it should be built "
    "against under Scope first.":
        "Chưa có test nào. Tạo kế hoạch ở trên — hoặc thêm endpoint cần dựng test "
        "trước ở phần Phạm vi.",
    "nothing to approve": "chưa có gì để duyệt",
})


def _plan_section(aid: str, plan: dict, filters: dict, opened: bool, review=None,
                  stale: bool = False) -> str:
    tests: list[TestCase] = plan["tests"]
    facets: dict = plan.get("facets") or {}
    meta: dict = plan.get("meta") or {}
    total = int(plan.get("total", len(tests)))
    unfiltered = int(plan.get("unfiltered_total", total))
    page = int(plan.get("page", 1))
    pages = int(plan.get("pages", 1))
    per = int(plan.get("per", 25))
    filtered = total != unfiltered

    if not unfiltered:
        no_tests_note = _t(
            "No tests yet. Generate a plan above — or add the endpoint it should be built "
            "against under Scope first."
        )
        return ui.section(
            "s-plan", "", _t("Test plan & approval"),
            f"<p class='muted' style='margin:0'>{no_tests_note}</p>",
            summary=_t("nothing to approve"), open=opened,
        )

    rows = ""
    for t in tests:
        sev = ui.SEV_CLASS.get(t.severity.value, "info")
        appr = ui.APPROVAL_CLASS.get(t.approval_status.value, "info")
        dest = f' {ui.pill("WRITE", "crit", TIP["destructive"])}' if t.is_destructive else ""
        endpoint = f"{t.request.method} {t.request.path}"
        detail_id = f"d-{t.test_id}"
        rows += (
            f'<tr>'
            f'<td><input type="checkbox" class="tsel" name="test_ids" value="{attr(t.test_id)}"'
            f' aria-label="Select {attr(t.test_id)}"></td>'
            f'<td><button type="button" class="btn ghost trow" aria-expanded="false" '
            f'aria-controls="{attr(detail_id)}" style="padding:0 4px">'
            f'<b class="mono">{e(t.test_id)}</b></button>{dest}<br>'
            f'<span class="muted">{e(t.title)}</span></td>'
            f'<td class="mono">{e(t.owasp_category.value.split(":")[0])}</td>'
            f'<td>{ui.pill(t.severity.value, sev)}</td>'
            f'<td>{ui.pill(t.approval_status.value, appr)}</td>'
            f'<td class="mono muted"><span class="trunc" data-tip="{attr(endpoint)}">'
            f'{e(endpoint)}</span></td>'
            f'<td class="mono muted">{e(t.attack_mutation.kind)}</td>'
            f'<td class="rowact"><a class="btn sec" style="padding:4px 10px" '
            f'href="/assessment/{attr(aid)}/test/{attr(t.test_id)}">{_t("Edit")}</a></td></tr>'
            # The expanded row answers "what does this test actually do?" without
            # a round-trip to the detail page and back for every row reviewed.
            f'<tr class="tdet" id="{attr(detail_id)}" hidden><td></td><td colspan="7">'
            f'<div class="muted" style="padding:2px 0 8px">{e(t.objective)}</div>'
            f'<div class="row" style="gap:20px;font-size:12.5px">'
            f'<div><div class="glabel" style="margin:0">{_t("Persona")}</div>'
            f'<span class="mono">{e(t.auth_context.persona)}'
            f'{" &rarr; " + e(t.auth_context.target_persona) if t.auth_context.target_persona else ""}'
            f'</span></div>'
            f'<div><div class="glabel" style="margin:0">{_t("Expected status")}</div>'
            f'<span class="mono">{e(", ".join(str(s) for s in t.expected.status_in))}</span></div>'
            f'<div><div class="glabel" style="margin:0">{_t("Source")}</div>'
            f'<span class="mono">{e(t.source.value)}'
            # Which artefact, not just what kind. A ticket with two PoC scripts
            # produces two groups of tests, and "which script is this replaying"
            # is the first thing a reviewer needs before approving either group.
            f'{" &middot; " + e(getattr(t, "source_ref", "")) if getattr(t, "source_ref", "") else ""}'
            f'</span></div>'
            f'</div></td></tr>'
        )

    table = ui.table(
        ['<input type="checkbox" id="select-all-tests" aria-label="Select every test on this page">',
         _t("Test"), "OWASP", _t("Severity") + info(TIP["severity"], _t("Severity")),
         _t("Approval") + info(TIP["approval"], _t("Approval")),
         _t("Endpoint"),
         _t("Mutation") + info(TIP["mutation"], _t("Mutation")), ""],
        rows,
        empty=_t("Nothing matches this filter."),
        scroll=len(tests) > 12,
        cls="compact",
    )

    body = f"""{_review_panel(aid, review, True)}
{_plan_toolbar(aid, filters, facets, total, unfiltered, page, pages)}
<form method="post" action="/assessment/{attr(aid)}/plan" id="plan-form">
{_plan_hidden_filters(filters, page)}
{_plan_selbar(total, filtered)}
{table}
{_pager(aid, filters, page, pages, per, total)}
</form>
{_PLAN_JS}"""

    approved = int(meta.get("approved", 0))
    pending = int(meta.get("pending", 0))
    summary = _t("{approved} of {total} approved").format(approved=approved, total=unfiltered)
    if review is not None:
        summary = _t("review: {verdict} · ").format(verdict=review.verdict) + summary
    if pending:
        summary += " · " + _t("{n} pending").format(n=pending)
    if filtered:
        summary += " · " + _t("showing {n}").format(n=total)
    if stale:
        # The plan's own heading admits it: this is the reader the warning is
        # for, and "18 of 64 approved" beside a plan built for a different
        # endpoint list is a number that means less than it looks like.
        summary += " · " + _t("plan is stale")
    return ui.section(
        "s-plan", "", _t("Test plan & approval"), body,
        summary=summary,
        open=opened,
        tip=_t(
            "Nothing runs until it is approved here. Filter, then act on the whole "
            "filtered set — a plan generated at aggressive depth is hundreds of tests, "
            "and reviewing it one checkbox at a time is not review."
        ),
    )


_PER_CHOICES = (25, 50, 100, 250)


def _select(name: str, current: str, options: list[tuple[str, str]], label: str,
            width: str = "auto") -> str:
    opts = "".join(
        f'<option value="{attr(value)}"{" selected" if value == current else ""}>{text}</option>'
        for value, text in options
    )
    return (f'<label class="field"><span>{e(label)}</span>'
            f'<select name="{attr(name)}" form="plan-filter" style="width:{width}">{opts}'
            f"</select></label>")


def _facet_options(facet: dict, blank: str, pretty=None) -> list[tuple[str, str]]:
    """Only values the plan actually contains, each with its count — a filter
    option that matches nothing is a dead end the tester has to discover."""
    out = [("", blank)]
    for value in sorted(facet):
        text = pretty(value) if pretty else value
        out.append((value, f"{text} ({facet[value]})"))
    return out


def _plan_toolbar(aid: str, filters: dict, facets: dict, total: int, unfiltered: int,
                  page: int, pages: int) -> str:
    cat = _facet_options(facets.get("cat") or {}, _t("All categories"),
                         lambda v: v.split(":")[0])
    sev = _facet_options(facets.get("sev") or {}, _t("Any severity"))
    appr = _facet_options(facets.get("appr") or {}, _t("Any approval"))
    src = _facet_options(facets.get("src") or {}, _t("Any source"))
    count = (_t("{n} of {total} tests").format(n=total, total=unfiltered)
             if total != unfiltered else _t("{n} tests").format(n=unfiltered))
    if pages > 1:
        count += " · " + _t("page {page}/{pages}").format(page=page, pages=pages)
    return f"""<form method="get" action="/assessment/{attr(aid)}" id="plan-filter" class="toolbar">
<label class="field grow"><span>{_t("Search")} <span class="kbd">/</span></span>
<input name="q" value="{attr(filters.get("q", ""))}" style="width:100%"
 placeholder="id, title, mutation, path"></label>
{_select("cat", filters.get("cat", ""), cat, "OWASP")}
{_select("sev", filters.get("sev", ""), sev, _t("Severity"))}
{_select("appr", filters.get("appr", ""), appr, _t("Approval"))}
{_select("dest", filters.get("dest", ""), [("", _t("All")), ("yes", _t("Write only")), ("no", _t("Read only"))],
         _t("Destructive"))}
{_select("src", filters.get("src", ""), src, _t("Source"))}
{_select("sort", filters.get("sort", "id") or "id",
         [("id", _t("Generation order")), ("sev", _t("Severity")), ("cat", _t("Category")),
          ("appr", _t("Approval")), ("endpoint", _t("Endpoint"))], _t("Sort"))}
{_select("per", str(filters.get("per", 25)), [(str(n), str(n)) for n in _PER_CHOICES], _t("Per page"))}
<div class="row" style="gap:6px;align-items:flex-end">
<button class="btn sec">{_t("Apply")}</button>
<a class="btn ghost" href="/assessment/{attr(aid)}?phase=plan">{_t("Clear")}</a>
</div>
<span class="count" style="align-self:flex-end;padding-bottom:8px">{count}</span>
</form>"""


def _plan_hidden_filters(filters: dict, page: int) -> str:
    """The bulk-action form carries the filter, so "all matching" is resolved
    server-side against the same query the page was rendered from."""
    keep = {**filters, "page": page}
    return "".join(
        f'<input type="hidden" name="{attr(k)}" value="{attr(v)}">'
        for k, v in keep.items() if v not in ("", None)
    )


def _plan_selbar(total: int, filtered: bool) -> str:
    scope = _t("matching this filter") if filtered else _t("in the plan")
    reset_tip = _t(
        "Back to PENDING. Withdrawing an approval is a thing you can do; unchecking a "
        "box never was — the handler only ever read the boxes that were ticked."
    )
    apply_label = _t("apply to all {n} {scope}, not just the page").format(n=total, scope=e(scope))
    return f"""<div class="selbar off" id="selbar" aria-live="polite">
<b><span id="selcount">0</span> {_t("selected")}</b>
<button class="btn" name="action" value="approve" style="padding:5px 12px">{_t("Approve")}</button>
<button class="btn sec" name="action" value="reject" style="padding:5px 12px">{_t("Reject")}</button>
<button class="btn ghost" name="action" value="reset" style="padding:5px 12px"
 data-tip="{attr(reset_tip)}">{_t("Reset")}</button>
<button type="button" class="btn ghost" id="selclear" style="padding:5px 12px">{_t("Clear")}</button>
<label class="row" style="gap:6px;margin:0 0 0 auto;align-items:center">
<input type="checkbox" name="select_all" value="true" id="selall" style="width:auto">
<span class="muted">{apply_label}</span></label>
</div>"""


def _pager(aid: str, filters: dict, page: int, pages: int, per: int, total: int) -> str:
    if pages <= 1:
        return ""
    base = f"/assessment/{attr(aid)}?" + "&amp;".join(
        f"{attr(k)}={attr(v)}" for k, v in filters.items() if v not in ("", None)
    )
    joiner = "&amp;" if base.endswith("?") is False else ""

    def link(n: int, text: str = "", cls: str = "") -> str:
        if n == page:
            return f'<span class="on">{e(text or n)}</span>'
        return (f'<a class="{e(cls)}" href="{base}{joiner}page={n}&phase=plan">'
                f"{e(text or n)}</a>")

    # First, last, and a window around the current page: a 40-page plan should
    # not render 40 links.
    window = {1, pages, page}
    window.update(range(max(1, page - 2), min(pages, page + 2) + 1))
    out = []
    if page > 1:
        out.append(link(page - 1, "‹"))
    previous = 0
    for n in sorted(window):
        if previous and n > previous + 1:
            out.append('<span class="gap">…</span>')
        out.append(link(n))
        previous = n
    if page < pages:
        out.append(link(page + 1, "›"))
    return (f'<div class="pager">{"".join(out)}'
            f'<span class="count" style="margin-left:10px">{_t("{n} test(s)").format(n=total)}</span></div>')


_PLAN_JS = """
<script>
(function () {
  var form = document.getElementById('plan-form');
  if (!form) return;
  var boxes = Array.prototype.slice.call(form.querySelectorAll('.tsel'));
  var all = document.getElementById('select-all-tests');
  var bar = document.getElementById('selbar');
  var count = document.getElementById('selcount');
  var selAll = document.getElementById('selall');

  function selected() { return boxes.filter(function (b) { return b.checked; }); }
  function sync() {
    var n = selected().length;
    count.textContent = n;
    // The bar stays up when "apply to all" is ticked: that action does not need
    // any row selected, and hiding its own checkbox would be a trap.
    bar.classList.toggle('off', n === 0 && !(selAll && selAll.checked));
    if (all) all.checked = n > 0 && n === boxes.length;
  }
  boxes.forEach(function (b) { b.addEventListener('change', sync); });
  if (all) all.addEventListener('change', function () {
    boxes.forEach(function (b) { b.checked = all.checked; });
    sync();
  });
  if (selAll) selAll.addEventListener('change', sync);
  document.getElementById('selclear').addEventListener('click', function () {
    boxes.forEach(function (b) { b.checked = false; });
    if (selAll) selAll.checked = false;
    sync();
  });

  // Expandable rows: what a test does, without leaving the plan.
  form.querySelectorAll('.trow').forEach(function (b) {
    b.addEventListener('click', function () {
      var row = document.getElementById(b.getAttribute('aria-controls'));
      var open = row.hidden;
      row.hidden = !open;
      b.setAttribute('aria-expanded', String(open));
    });
  });

  // Keyboard: reviewing hundreds of rows with a mouse is the thing being fixed.
  document.addEventListener('keydown', function (ev) {
    if (ev.target.matches('input, textarea, select')) return;
    if (ev.key === '/') {
      var q = document.querySelector('#plan-filter input[name="q"]');
      if (q) { ev.preventDefault(); q.focus(); q.select(); }
    } else if (ev.key === 'Escape') {
      boxes.forEach(function (b) { b.checked = false; });
      sync();
    }
  });
  sync();
})();
</script>
"""
