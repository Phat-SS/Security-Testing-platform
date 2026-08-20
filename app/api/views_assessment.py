"""The assessment page — the screen where an imported ticket becomes a run.

Ordered as the work is actually done: what the plan is derived from first
(endpoints, then the PoC to import), then what was derived from it (coverage,
the plan), then the run, then the results. The previous order put two sections
that are *empty until you design* above the one control that designs, so the
only button that did anything on a freshly analyzed ticket sat below two screens
of placeholders.

Each step is collapsible and opens according to where the assessment actually
is, which is what keeps a 300-test plan from turning the page into a mile of
scrolling: a finished step folds to one line that still states what it produced.
"""

from __future__ import annotations

import json
import re

from app.api import ui
from app.api.ui import attr, e, info
from app.core.i18n import VI, tt as _t
from app.database.models import Assessment
from app.owasp.api_top10_2023 import CONTROLS
from app.schemas.enums import OwaspApiCategory
from app.schemas.testcase import TestCase


class _TipDict(dict):
    """Translates on access instead of at module-load time — TIP's values are
    looked up per-request (`TIP["auth"]`), same as every other UI string here,
    but keeping them in one place under their original short names is worth
    more than saving a `_t()` at each of the ~20 call sites below."""

    def __getitem__(self, key):
        return _t(super().__getitem__(key))

# -- column and control explanations ---------------------------------------
#
# Every one of these was a term a reader had to open the source to understand.
# They live together so the vocabulary stays consistent between the endpoints
# table, the coverage table and the plan.

TIP = _TipDict({
    "auth": "Whether the endpoint requires a credential. Drives the API2 "
            "(broken authentication) probes: a public endpoint has no "
            "credential to drop, so those tests are pointless there.",
    "expected_public": "This endpoint is intentionally public — a 200 without a "
                       "credential is the correct, expected result, not a finding. "
                       "Generates a confirmation test instead of a vulnerability "
                       "probe; a 401/403 there would flag a regression.",
    "object_ids": "Path, query or body parameters that name an object — the "
                  "BOLA/BOPLA surface. Each one becomes an id the attacker "
                  "persona swaps for the victim's. Miss one here and the whole "
                  "category goes untested.",
    "writes": "The request carries a body whose properties could be tampered "
              "with. Drives API3 (mass assignment / excessive data exposure).",
    "url_fields": "Body or query fields holding a URL the server fetches "
                  "itself. Drives API7 (SSRF) — without one, there is nothing "
                  "for the server to be coerced into requesting.",
    "manual": "Added or edited by hand rather than extracted from the ticket. "
              "Re-analyzing the ticket keeps these rows.",
    "category": "OWASP API Security Top 10 (2023). Only categories the "
                "analyzer judged applicable to this ticket are shown by "
                "default — the rest are listed under the disclosure below.",
    "state": "COVERED — your imported PoC already tests this and the designer "
             "found no gap. PARTIAL — the PoC touches it but the designer "
             "added tests for what it missed. MISSING — applicable, and "
             "nothing tests it yet. NOT APPLICABLE — the analyzer found no "
             "signal for this category in this ticket.",
    "from_poc": "How much of this category's coverage came from the PoC you "
                "imported, as PoC tests / (PoC + generated). It is NOT a "
                "measure of how secure the endpoint is — it says where the "
                "tests came from.",
    "tests": "PoC = transpiled from the proof-of-concept you imported. "
             "gen = written by the rule engine and the AI planner to fill the "
             "gaps the PoC left.",
    "severity": "The severity a confirmed break of this control would carry, "
                "taken from the OWASP control's default and the endpoint's "
                "exposure. Not a measure of how likely the test is to pass.",
    "approval": "Nothing runs until it is APPROVED. Editing a test's request, "
                "or regenerating a plan in a way that changes what a test "
                "does, resets it to PENDING — an approval means you read what "
                "the test does.",
    "mutation": "The one security-relevant change made to an otherwise "
                "legitimate request. It is what classifies a result: a finding "
                "is described by what was changed, not guessed from a status "
                "code.",
    "destructive": "Sends a real POST/PUT/PATCH/DELETE. Excluded from an "
                   "ordinary run and gated behind a separate confirmation, "
                   "because a broken control means the write actually "
                   "happened.",
    "source": "Where the test came from: the PoC you imported, the "
              "deterministic rule engine, or the AI planner. AI-proposed tests "
              "go through the same approval gate as every other test.",
    "coverage_kpi": "Applicable categories that are covered, counting a "
                    "PARTIAL as a half. A low number here means the plan has "
                    "gaps, not that the API is safe.",
    "requirement": "One discrete thing the ticket asks for, read out of its "
                   "acceptance criteria and security-relevant bullets. This list is "
                   "the denominator of the coverage percentage, so an item missing "
                   "here is a percentage that flatters the run.",
    "req_state": "COVERED — a test for this item ran and reached a decisive result. "
                 "PARTIAL — a test ran but decided nothing. NOT COVERED — a test "
                 "exists but has not run. NOT TESTED — nothing in the plan "
                 "addresses it. An item with no security-relevant reading is "
                 "excluded from the score rather than counted against it.",
    "req_digest": "The AI reviewer's restatement of each security-relevant "
                  "requirement as the concrete behaviour a test result can be "
                  "checked against — a specific status code, who may act, what "
                  "must never happen — rather than the ticket's own, often "
                  "vaguer, wording. Only appears when the AI reviewer ran.",
    "review": "What the reviewing agent made of a result the runner left "
              "undecided. Advisory: it never overwrites the sealed verdict and "
              "never creates a finding — it tells you whether you still have to "
              "read this one yourself.",
    "gap": "Something the reviewing agent says the plan does not cover. A "
           "blocking gap is a security-relevant requirement with no test at all. "
           "Gaps are fed back to the planner for a bounded revision round; what "
           "is left is listed for you.",
    "verdict": "FAIL — the control broke and the response disclosed it. PASS — "
               "the control held. INCONCLUSIVE — the test never exercised the "
               "control (a stale object id, say), which is honest rather than "
               "useful. BLOCKED — refused by scope before anything was sent. "
               "ERROR — the test itself could not run.",
})

VI.update({
    "Whether the endpoint requires a credential. Drives the API2 "
    "(broken authentication) probes: a public endpoint has no "
    "credential to drop, so those tests are pointless there.":
        "Endpoint có yêu cầu thông tin xác thực hay không. Quyết định các test API2 "
        "(broken authentication): endpoint công khai không có credential để bỏ đi, nên "
        "các test đó vô nghĩa ở đấy.",
    "Path, query or body parameters that name an object — the "
    "BOLA/BOPLA surface. Each one becomes an id the attacker "
    "persona swaps for the victim's. Miss one here and the whole "
    "category goes untested.":
        "Tham số path, query hoặc body định danh một object — bề mặt BOLA/BOPLA. Mỗi "
        "cái sẽ trở thành một id mà persona kẻ tấn công đổi sang của nạn nhân. Bỏ sót "
        "một cái ở đây là cả danh mục không được test.",
    "The request carries a body whose properties could be tampered "
    "with. Drives API3 (mass assignment / excessive data exposure).":
        "Request mang theo body có các thuộc tính có thể bị can thiệp. Quyết định "
        "API3 (mass assignment / lộ dữ liệu thừa).",
    "Body or query fields holding a URL the server fetches "
    "itself. Drives API7 (SSRF) — without one, there is nothing "
    "for the server to be coerced into requesting.":
        "Trường body hoặc query chứa URL mà server tự gọi tới. Quyết định API7 (SSRF) "
        "— không có trường này thì không có gì để ép server phải gọi tới.",
    "Added or edited by hand rather than extracted from the ticket. "
    "Re-analyzing the ticket keeps these rows.":
        "Được thêm hoặc sửa bằng tay thay vì trích xuất từ ticket. Phân tích lại "
        "ticket vẫn giữ nguyên các dòng này.",
    "OWASP API Security Top 10 (2023). Only categories the "
    "analyzer judged applicable to this ticket are shown by "
    "default — the rest are listed under the disclosure below.":
        "OWASP API Security Top 10 (2023). Mặc định chỉ hiện các danh mục mà bộ phân "
        "tích cho là áp dụng được với ticket này — phần còn lại nằm trong mục mở rộng "
        "bên dưới.",
    "COVERED — your imported PoC already tests this and the designer "
    "found no gap. PARTIAL — the PoC touches it but the designer "
    "added tests for what it missed. MISSING — applicable, and "
    "nothing tests it yet. NOT APPLICABLE — the analyzer found no "
    "signal for this category in this ticket.":
        "ĐÃ PHỦ — PoC bạn nhập đã test cái này và designer không thấy lỗ hổng nào. "
        "MỘT PHẦN — PoC có chạm tới nhưng designer đã thêm test cho phần còn thiếu. "
        "THIẾU — áp dụng được, nhưng chưa có gì test. KHÔNG ÁP DỤNG — bộ phân tích "
        "không thấy dấu hiệu nào của danh mục này trong ticket.",
    "How much of this category's coverage came from the PoC you "
    "imported, as PoC tests / (PoC + generated). It is NOT a "
    "measure of how secure the endpoint is — it says where the "
    "tests came from.":
        "Bao nhiêu phần độ phủ của danh mục này đến từ PoC bạn nhập, dạng test PoC / "
        "(PoC + đã tạo). Đây KHÔNG phải thước đo độ an toàn của endpoint — chỉ nói "
        "test đến từ đâu.",
    "PoC = transpiled from the proof-of-concept you imported. "
    "gen = written by the rule engine and the AI planner to fill the "
    "gaps the PoC left.":
        "PoC = được chuyển đổi từ proof-of-concept bạn nhập. gen = do rule engine và "
        "AI planner viết để lấp lỗ hổng PoC còn để lại.",
    "The severity a confirmed break of this control would carry, "
    "taken from the OWASP control's default and the endpoint's "
    "exposure. Not a measure of how likely the test is to pass.":
        "Mức độ nghiêm trọng nếu control này thực sự bị phá vỡ, lấy theo mặc định của "
        "control OWASP và mức độ phơi nhiễm của endpoint. Không phải thước đo khả năng "
        "test sẽ đạt.",
    "Nothing runs until it is APPROVED. Editing a test's request, "
    "or regenerating a plan in a way that changes what a test "
    "does, resets it to PENDING — an approval means you read what "
    "the test does.":
        "Không có gì chạy cho tới khi được DUYỆT. Sửa request của test, hoặc tạo lại "
        "kế hoạch theo cách làm thay đổi hành vi của test, sẽ đưa nó về PENDING — một "
        "lượt duyệt nghĩa là bạn đã đọc test đó làm gì.",
    "The one security-relevant change made to an otherwise "
    "legitimate request. It is what classifies a result: a finding "
    "is described by what was changed, not guessed from a status "
    "code.":
        "Thay đổi duy nhất liên quan bảo mật được áp vào một request vốn hợp lệ. Đây "
        "là thứ phân loại kết quả: một finding được mô tả bằng thứ đã bị thay đổi, "
        "không phải đoán từ mã trạng thái.",
    "Sends a real POST/PUT/PATCH/DELETE. Excluded from an "
    "ordinary run and gated behind a separate confirmation, "
    "because a broken control means the write actually "
    "happened.":
        "Gửi một POST/PUT/PATCH/DELETE thật. Bị loại khỏi lượt chạy thông thường và "
        "cần một xác nhận riêng, vì control bị phá vỡ nghĩa là dữ liệu đã thực sự bị "
        "ghi đè.",
    "Where the test came from: the PoC you imported, the "
    "deterministic rule engine, or the AI planner. AI-proposed tests "
    "go through the same approval gate as every other test.":
        "Test đến từ đâu: PoC bạn nhập, rule engine tất định, hay AI planner. Test do "
        "AI đề xuất đi qua đúng cổng duyệt như mọi test khác.",
    "Applicable categories that are covered, counting a "
    "PARTIAL as a half. A low number here means the plan has "
    "gaps, not that the API is safe.":
        "Số danh mục áp dụng được đã phủ, tính MỘT PHẦN là nửa điểm. Số thấp ở đây "
        "nghĩa là kế hoạch còn lỗ hổng, không phải API an toàn.",
    "One discrete thing the ticket asks for, read out of its "
    "acceptance criteria and security-relevant bullets. This list is "
    "the denominator of the coverage percentage, so an item missing "
    "here is a percentage that flatters the run.":
        "Một điều cụ thể ticket yêu cầu, đọc ra từ acceptance criteria và các gạch "
        "đầu dòng liên quan bảo mật. Danh sách này là mẫu số của tỷ lệ phủ, nên thiếu "
        "một mục ở đây là tỷ lệ đang tâng bốc lượt chạy.",
    "COVERED — a test for this item ran and reached a decisive result. "
    "PARTIAL — a test ran but decided nothing. NOT COVERED — a test "
    "exists but has not run. NOT TESTED — nothing in the plan "
    "addresses it. An item with no security-relevant reading is "
    "excluded from the score rather than counted against it.":
        "ĐÃ PHỦ — có test cho mục này và đã ra kết quả dứt khoát. MỘT PHẦN — có test "
        "chạy nhưng không quyết được gì. CHƯA PHỦ — có test nhưng chưa chạy. CHƯA "
        "TEST — không có gì trong kế hoạch đề cập tới. Mục không mang ý nghĩa bảo mật "
        "được loại khỏi điểm số thay vì bị tính là điểm trừ.",
    "What the reviewing agent made of a result the runner left "
    "undecided. Advisory: it never overwrites the sealed verdict and "
    "never creates a finding — it tells you whether you still have to "
    "read this one yourself.":
        "Agent đánh giá nghĩ gì về một kết quả mà runner để ngỏ. Chỉ mang tính tham "
        "khảo: không bao giờ ghi đè kết luận đã niêm phong và không tạo finding — nó "
        "chỉ cho bạn biết bạn có còn phải tự đọc cái này không.",
    "Something the reviewing agent says the plan does not cover. A "
    "blocking gap is a security-relevant requirement with no test at all. "
    "Gaps are fed back to the planner for a bounded revision round; what "
    "is left is listed for you.":
        "Điều mà agent đánh giá nói kế hoạch chưa phủ. Một lỗ hổng chặn là yêu cầu "
        "liên quan bảo mật mà không có test nào cả. Lỗ hổng được đưa lại cho planner "
        "trong một vòng chỉnh sửa có giới hạn; phần còn lại được liệt kê cho bạn.",
    "FAIL — the control broke and the response disclosed it. PASS — "
    "the control held. INCONCLUSIVE — the test never exercised the "
    "control (a stale object id, say), which is honest rather than "
    "useful. BLOCKED — refused by scope before anything was sent. "
    "ERROR — the test itself could not run.":
        "LỖI — control bị phá vỡ và phản hồi để lộ điều đó. ĐẠT — control đứng vững. "
        "CHƯA RÕ — test chưa thực sự chạm vào control (ví dụ object id đã cũ), trung "
        "thực hơn là hữu ích. BỊ CHẶN — bị scope từ chối trước khi gửi đi. LỖI HỆ "
        "THỐNG — bản thân test không chạy được.",
})


# -- readiness --------------------------------------------------------------


def readiness_banner(readiness, href: str = "/config") -> str:
    """The compact verdict shown right above the Run button. Silent when
    everything is green — a banner that is always present is a banner nobody
    reads."""
    if readiness is None or readiness.state == "ok":
        return ""
    blocking = readiness.n_blocking
    if blocking:
        cls, headline = "err", _t(
            "{n} setting(s) will block this run before any request is sent."
        ).format(n=blocking)
    else:
        cls, headline = "warn", _t(
            "{n} setting(s) will make results less conclusive."
        ).format(n=readiness.n_warnings)
    items = "".join(
        f"<li><b>{e(c.label)}</b> — {e(c.detail)}</li>"
        for c in readiness.checks if c.state != "ok"
    )
    return (
        f"<div class='card pad {cls}' style='margin-bottom:14px'>"
        f"<p style='margin:0 0 6px'><b>{e(headline)}</b></p>"
        f"<ul style='margin:0 0 10px;padding-left:18px' class='muted'>{items}</ul>"
        f"<a href='{e(href)}' class='btn sec'>{_t('Open configuration')}</a></div>"
    )


# -- page state -------------------------------------------------------------


class _State:
    """Where the assessment is, computed once and consulted by every section.

    Which sections open by default, which step the nav marks current and which
    empty state is shown all follow from the same three counts, so they are
    derived in one place rather than re-inferred per section.
    """

    def __init__(self, n_endpoints: int, plan_meta: dict, n_executions: int) -> None:
        # Taken from the plan-wide counts the repository computes during the same
        # scan the filter facets need — the page must not have to load and
        # validate every test in a 400-test plan just to say how many are
        # approved.
        self.n_endpoints = n_endpoints
        self.n_tests = int(plan_meta.get("total", 0))
        self.n_approved = int(plan_meta.get("approved", 0))
        self.n_rejected = int(plan_meta.get("rejected", 0))
        self.n_destructive_approved = int(plan_meta.get("approved_destructive", 0))
        self.n_executions = n_executions

    @property
    def stage(self) -> str:
        if not self.n_tests:
            return "design"
        if not self.n_approved:
            return "approve"
        if not self.n_executions:
            return "execute"
        return "report"

    def opens(self) -> dict[str, bool]:
        stage = self.stage
        return {
            "endpoints": stage == "design",
            "design": stage == "design",
            "coverage": stage in ("approve",),
            "plan": stage in ("approve", "execute"),
            "execute": stage == "execute",
            "results": stage == "report",
        }


# -- step nav ---------------------------------------------------------------

_STEPS = [
    # (anchor, label, state key)
    ("#s-endpoints", "Analyze", "analyze"),
    ("#s-design", "Design", "design"),
    ("#s-plan", "Approve", "approve"),
    ("#s-execute", "Execute", "execute"),
    ("#s-results", "Report", "report"),
]

VI.update({
    "Analyze": "Phân tích", "Design": "Thiết kế", "Approve": "Duyệt",
    "Execute": "Chạy", "Report": "Báo cáo",
})


def _step_nav(st: _State) -> str:
    done = {
        "analyze": st.n_endpoints > 0,
        "design": st.n_tests > 0,
        "approve": st.n_approved > 0,
        "execute": st.n_executions > 0,
        "report": st.n_executions > 0,
    }
    counts = {
        "analyze": st.n_endpoints or "",
        "design": st.n_tests or "",
        "approve": st.n_approved or "",
        "execute": st.n_executions or "",
        "report": "",
    }
    current = next((key for _h, _l, key in _STEPS if not done[key]), "report")
    out = ""
    for href, label, key in _STEPS:
        cls = "done" if done[key] else ""
        if key == current:
            cls += " current"
        n = counts[key]
        out += (
            f'<a href="{href}" class="{cls}" data-step="{key}">'
            f'<span class="dot"></span>{e(_t(label))}'
            + (f'<span class="n">{e(n)}</span>' if n else "")
            + "</a>"
        )
    return f'<nav class="stepnav" aria-label="Assessment workflow">{out}</nav>'


# -- stat strip -------------------------------------------------------------


def _sev_dots(findings) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [
        f'<span style="color:var(--{ui.SEV_CLASS[s]})">{counts[s]}{s[0]}</span>'
        for s in order if counts.get(s)
    ]
    return f'<span class="sevdots">{"".join(parts)}</span>' if parts else ""


def _stats(st: _State, findings, coverage: list[dict]) -> str:
    applicable = [r for r in coverage if r.get("applicable")]
    covered = sum(1 for r in applicable if r.get("state") == "COVERED")
    partial = sum(1 for r in applicable if r.get("state") == "PARTIAL")
    cov_pct = round(100 * (covered + 0.5 * partial) / len(applicable)) if applicable else 0
    findings_cell = f"{len(findings)} {_sev_dots(findings)}" if findings else "0"
    return ui.stats([
        (str(st.n_endpoints), _t("Endpoints"), "", "#s-endpoints"),
        (str(st.n_tests), _t("Tests"), "", "#s-plan"),
        (str(st.n_approved), _t("Approved"), TIP["approval"], "#s-plan"),
        (str(st.n_executions), _t("Executed"), "", "#s-execute"),
        (findings_cell, _t("Findings"), "", "#s-results"),
        (f"{cov_pct}%" if applicable else "—", _t("Coverage"), TIP["coverage_kpi"], "#s-coverage"),
    ])


# -- 1. endpoints -----------------------------------------------------------


_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def _method_options(selected: str) -> str:
    return "".join(
        f'<option value="{m}"{" selected" if m == selected.upper() else ""}>{m}</option>'
        for m in _METHODS
    )


def _endpoint_form_cells(ep: dict, form_id: str) -> str:
    """The editable cells for one endpoint.

    The inputs use `form=` to point at a submit button that lives in the last
    cell, which is what lets a table row be a form without nesting a <form>
    inside <tr> (invalid, and dropped by the parser). The row therefore still
    works with JavaScript off; the JS only chooses whether the readable row or
    the editable row is the visible one.
    """
    ids = " ".join(ep.get("object_id_params") or [])
    urls = " ".join(ep.get("url_fields") or [])
    return (
        f'<td><div class="row" style="gap:6px;flex-wrap:nowrap">'
        f'<select name="method" form="{attr(form_id)}" aria-label="Method" '
        f'style="max-width:104px">{_method_options(str(ep.get("method", "GET")))}</select>'
        f'<input name="path" form="{attr(form_id)}" class="mono" required '
        f'aria-label="Path" value="{attr(ep.get("path", ""))}" '
        f'placeholder="/customers/{{id}}"></div></td>'
        f'<td><input name="object_id_params" form="{attr(form_id)}" class="mono" '
        f'aria-label="Object id parameters" value="{attr(ids)}" placeholder="customerId"></td>'
        f'<td><input type="checkbox" name="auth_required" value="true" form="{attr(form_id)}" '
        f'aria-label="Auth required" style="width:auto"'
        f'{" checked" if ep.get("auth_required") else ""}></td>'
        f'<td><input type="checkbox" name="expected_public" value="true" form="{attr(form_id)}" '
        f'aria-label="Expected public" style="width:auto"'
        f'{" checked" if ep.get("expected_public") else ""}></td>'
        f'<td><input type="checkbox" name="writes_properties" value="true" form="{attr(form_id)}" '
        f'aria-label="Writes properties" style="width:auto"'
        f'{" checked" if ep.get("writes_properties") else ""}></td>'
        f'<td><input name="url_fields" form="{attr(form_id)}" class="mono" '
        f'aria-label="URL fields" value="{attr(urls)}" placeholder="callbackUrl"></td>'
    )


_REQ_STATE_CLASS = {
    "COVERED_PASS": "low", "COVERED_FAIL": "crit", "PARTIAL": "med",
    "NOT_COVERED": "med", "NOT_TESTED": "info",
}


def _requirements_panel(requirements: list[dict], coverage_items: list) -> str:
    """What the ticket asks for, and what the run proved about each item.

    Rendered above the endpoint list because it is the thing the endpoint list
    exists to serve: a plan is judged against these, and the coverage percentage
    is computed over them. Showing the percentage without showing its rows would
    be asking a tester to act on a number they cannot decompose.
    """
    if not requirements:
        return ""
    by_id = {i.item_id: i for i in (coverage_items or [])}
    rows = ""
    for item in requirements:
        item_id = str(item.get("item_id", ""))
        hints = "".join(f'<span class="kchip">{e(h.split(":")[0])}</span>'
                        for h in item.get("owasp_hints") or [])
        manual = f' {ui.pill("manual", "info", TIP["manual"])}' if item.get("manual") else ""
        result = by_id.get(item_id)
        if result is None:
            state_cell = '<span class="muted">&mdash;</span>'
            note = ""
        else:
            tone = _REQ_STATE_CLASS.get(result.state, "info")
            state_cell = ui.pill(result.state.replace("_", " "), tone)
            note = e(result.note)
        none_cell = f"<span class=muted>{_t('none')}</span>"
        rows += (
            f'<tr><td class="mono">{e(item_id)}{manual}</td>'
            f'<td>{e(item.get("text", ""))}</td>'
            f'<td>{hints or none_cell}</td>'
            f"<td>{state_cell}</td>"
            f'<td class="muted">{note}</td></tr>'
        )
    heading = (
        f'<div class="glabel" style="margin-bottom:4px">{_t("Requirements read from the ticket")}'
        f'{info(TIP["requirement"], _t("Requirements"))}</div>'
    )
    return heading + ui.table(
        [_t("Item"), _t("Requirement"), f"OWASP{info(TIP['category'], 'OWASP')}",
         f"{_t('State')}{info(TIP['req_state'], _t('State'))}", _t("Note")],
        rows, scroll=len(requirements) > 10, cls="compact",
        empty=_t("No requirement items were extracted from this ticket."),
    ) + '<div style="height:18px"></div>'


no_endpoints_text = (
    "No endpoints were extracted from the ticket &mdash; the extractor reads prose, so "
    "an endpoint written in a table or an attachment is invisible to it. Add it in the "
    "row below; without one there is nothing for the designer to build tests against."
)
stale_headline_text = "The current test plan was generated from a different endpoint list."
stale_body_text = (
    "Regenerate it in step 2 &mdash; otherwise the plan you approve is the one built "
    "for the endpoints you have since changed. Approvals on tests that come back "
    "unchanged are kept."
)
reanalyze_note_text = (
    "Re-reads the Jira issue and rebuilds this list. Hand-entered rows are kept; the "
    "OWASP mapping is rebuilt from scratch, which is the only operation allowed to "
    "drop a category."
)


def _endpoints_section(aid: str, endpoints: list[dict], stale: bool, opened: bool,
                       requirements: list[dict] | None = None,
                       coverage_items: list | None = None) -> str:
    rows = ""
    for i, ep in enumerate(endpoints):
        sig = f'{str(ep.get("method", "")).upper()} {ep.get("path", "")}'
        ids = "".join(f'<span class="kchip">{e(p)}</span>'
                      for p in ep.get("object_id_params") or [])
        urls = "".join(f'<span class="kchip">{e(p)}</span>'
                       for p in ep.get("url_fields") or [])
        manual = f' {ui.pill("manual", "info", TIP["manual"])}' if ep.get("manual") else ""
        form_id = f"epf-{i}"
        # Two rows per endpoint: the readable one and the editable one. Toggling
        # between them is a visibility change, so starting an edit costs no
        # request and abandoning one costs nothing at all.
        rows += (
            f'<tr class="ep-view" data-ep="{i}">'
            f'<td class="mono"><b>{e(ep.get("method", ""))}</b> {e(ep.get("path", ""))}{manual}</td>'
            f'<td>{ids or "<span class=muted>&mdash;</span>"}</td>'
            f'<td>{_t("yes") if ep.get("auth_required") else _t("no")}</td>'
            f'<td>{_t("yes") if ep.get("expected_public") else "&mdash;"}</td>'
            f'<td>{_t("yes") if ep.get("writes_properties") else "&mdash;"}</td>'
            f'<td>{urls or "<span class=muted>&mdash;</span>"}</td>'
            f'<td class="rowact">'
            f'<button type="button" class="btn ghost ep-edit" data-ep="{i}">{_t("Edit")}</button>'
            f'<form method="post" action="/assessment/{attr(aid)}/endpoints/delete" '
            f'style="margin:0" class="confirm-ep" data-what="{attr(sig)}">'
            f'<input type="hidden" name="signature" value="{attr(sig)}">'
            f'<button class="btn ghost danger">{_t("Delete")}</button></form></td></tr>'
            f'<tr class="ep-edit-row editing" data-ep="{i}" hidden>'
            f'{_endpoint_form_cells(ep, form_id)}'
            f'<td class="rowact">'
            f'<form method="post" action="/assessment/{attr(aid)}/endpoints" '
            f'id="{attr(form_id)}" style="margin:0">'
            f'<input type="hidden" name="replaces" value="{attr(sig)}">'
            f'<button class="btn" style="padding:4px 10px">{_t("Save")}</button></form>'
            f'<button type="button" class="btn ghost ep-cancel" data-ep="{i}">{_t("Cancel")}</button>'
            f"</td></tr>"
        )

    # The add row lives inside the table, so a new endpoint is entered in the
    # same shape it will be read in.
    rows += (
        '<tr class="addrow">'
        + _endpoint_form_cells({"method": "GET", "auth_required": True}, "epf-new")
        + f'<td class="rowact"><form method="post" action="/assessment/{attr(aid)}/endpoints" '
          f'id="epf-new" style="margin:0">'
          f'<button class="btn" style="padding:4px 10px">{_t("Add")}</button></form></td></tr>'
    )

    body = _requirements_panel(requirements or [], coverage_items or []) + ui.table(
        [
            _t("Endpoint"),
            _t("Object IDs") + info(TIP["object_ids"], _t("Object IDs")),
            _t("Auth") + info(TIP["auth"], _t("Auth")),
            _t("Expected public") + info(TIP["expected_public"], _t("Expected public")),
            _t("Writes") + info(TIP["writes"], _t("Writes")),
            _t("URL fields") + info(TIP["url_fields"], _t("URL fields")),
            "",
        ],
        rows,
        cls="compact",
        scroll=len(endpoints) > 14,
    )
    if not endpoints:
        body = (
            f"<p class='muted' style='margin:0 0 12px'>{_t(no_endpoints_text)}</p>" + body
        )
    if stale:
        body += (
            "<div class='card pad warn stale' style='margin-top:12px'>"
            f"<b>&#9888; {_t(stale_headline_text)}</b>"
            f"<p class='muted' style='margin:6px 0 0'>{_t(stale_body_text)}</p>"
            f"<p style='margin:10px 0 0'><a class='btn sec' href='#s-design'>"
            f"{_t('Go to step 2')}</a></p></div>"
        )

    actions = (
        f'<form method="post" action="/assessment/{attr(aid)}/reanalyze" style="margin:0" '
        f'class="confirm-reanalyze">'
        f'<button class="btn sec">&#8635; {_t("Re-analyze from ticket")}</button></form>'
        f'<span class="muted" style="font-size:12.5px;align-self:center">'
        f'{_t(reanalyze_note_text)}</span>'
    )

    n_manual = sum(1 for ep in endpoints if ep.get("manual"))
    summary = _t("{n} endpoint(s)").format(n=len(endpoints))
    if requirements:
        summary = _t("{n} requirement(s) · ").format(n=len(requirements)) + summary
    if n_manual:
        summary += _t(" · {n} hand-entered").format(n=n_manual)
    if stale:
        summary += " · " + _t("plan is stale")

    return ui.section(
        # Retitled when the requirement list is present, because the step now
        # holds both halves of "what is this plan derived from": what the ticket
        # asks for, and the surface those asks live on.
        "s-endpoints", "1",
        _t("Requirements & endpoints") if requirements else _t("Endpoints"),
        body + _ENDPOINTS_JS,
        summary=summary,
        actions=actions,
        open=opened,
        tone="stale" if stale else "",
        tip=_t(
            "Everything downstream is derived from this list: the designer builds one "
            "test set per endpoint, and the OWASP mapping is computed from these "
            "parameters. A missed endpoint is a whole untested surface, and a missed "
            "requirement is a coverage percentage that flatters the run."
        ),
    )


_ENDPOINTS_JS = """
<script>
(function () {
  function rows(kind, i) {
    return document.querySelectorAll('tr.' + kind + '[data-ep="' + i + '"]');
  }
  function swap(i, editing) {
    rows('ep-view', i).forEach(function (r) { r.hidden = editing; });
    rows('ep-edit-row', i).forEach(function (r) { r.hidden = !editing; });
  }
  document.querySelectorAll('.ep-edit').forEach(function (b) {
    b.addEventListener('click', function () {
      swap(b.dataset.ep, true);
      var row = document.querySelector('tr.ep-edit-row[data-ep="' + b.dataset.ep + '"]');
      var first = row && row.querySelector('input[name="path"]');
      if (first) first.focus();
    });
  });
  document.querySelectorAll('.ep-cancel').forEach(function (b) {
    b.addEventListener('click', function () { swap(b.dataset.ep, false); });
  });
  document.querySelectorAll('form.confirm-ep').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      if (!confirm('Remove ' + f.dataset.what + ' from the analysis?\\n\\n' +
                   'Tests already generated for it stay in the plan until you ' +
                   'regenerate it.')) ev.preventDefault();
    });
  });
  document.querySelectorAll('form.confirm-reanalyze').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      if (!confirm('Re-read the ticket and rebuild the endpoint list and OWASP ' +
                   'mapping?\\n\\nHand-entered endpoints are kept. Edits you made to ' +
                   'extracted rows are not.')) ev.preventDefault();
    });
  });
})();
</script>
"""

VI.update({
    "{n} setting(s) will block this run before any request is sent.":
        "{n} cấu hình sẽ chặn lượt chạy này trước khi có request nào được gửi.",
    "{n} setting(s) will make results less conclusive.":
        "{n} cấu hình sẽ khiến kết quả kém chắc chắn hơn.",
    "Open configuration": "Mở cấu hình",
    "Endpoints": "Endpoint", "Tests": "Test", "Approved": "Đã duyệt",
    "Executed": "Đã chạy", "Findings": "Phát hiện", "Coverage": "Độ phủ",
    "none": "không có",
    "Requirements read from the ticket": "Yêu cầu đọc được từ ticket",
    "Requirements": "Yêu cầu", "Item": "Mục", "Requirement": "Yêu cầu",
    "State": "Trạng thái", "Note": "Ghi chú",
    "No requirement items were extracted from this ticket.":
        "Không trích xuất được mục yêu cầu nào từ ticket này.",
    "yes": "có", "no": "không",
    "Edit": "Sửa", "Delete": "Xoá", "Save": "Lưu", "Cancel": "Huỷ", "Add": "Thêm",
    "Object IDs": "Object ID", "Auth": "Auth", "Writes": "Ghi dữ liệu",
    "URL fields": "Trường URL",
    "No endpoints were extracted from the ticket &mdash; the extractor reads prose, so "
    "an endpoint written in a table or an attachment is invisible to it. Add it in the "
    "row below; without one there is nothing for the designer to build tests against.":
        "Không trích xuất được endpoint nào từ ticket &mdash; bộ trích xuất đọc văn xuôi, "
        "nên một endpoint viết trong bảng hoặc file đính kèm sẽ không thấy được. Thêm nó "
        "ở dòng bên dưới; không có nó thì designer không có gì để dựng test.",
    "The current test plan was generated from a different endpoint list.":
        "Kế hoạch test hiện tại được tạo từ một danh sách endpoint khác.",
    "Regenerate it in step 2 &mdash; otherwise the plan you approve is the one built "
    "for the endpoints you have since changed. Approvals on tests that come back "
    "unchanged are kept.":
        "Tạo lại ở bước 2 &mdash; nếu không kế hoạch bạn duyệt sẽ là kế hoạch dựng cho "
        "danh sách endpoint cũ, trong khi bạn đã thay đổi nó. Các duyệt trên test không "
        "đổi sẽ được giữ nguyên.",
    "Go to step 2": "Đến bước 2",
    "Re-analyze from ticket": "Phân tích lại từ ticket",
    "Re-reads the Jira issue and rebuilds this list. Hand-entered rows are kept; the "
    "OWASP mapping is rebuilt from scratch, which is the only operation allowed to "
    "drop a category.":
        "Đọc lại issue Jira và dựng lại danh sách này. Các dòng nhập tay được giữ "
        "nguyên; ánh xạ OWASP được dựng lại từ đầu — đây là thao tác duy nhất được phép "
        "bỏ một danh mục.",
    "{n} endpoint(s)": "{n} endpoint", "{n} requirement(s) · ": "{n} yêu cầu · ",
    " · {n} hand-entered": " · {n} nhập tay", "plan is stale": "kế hoạch đã cũ",
    "Requirements & endpoints": "Yêu cầu & endpoint",
    "Everything downstream is derived from this list: the designer builds one "
    "test set per endpoint, and the OWASP mapping is computed from these "
    "parameters. A missed endpoint is a whole untested surface, and a missed "
    "requirement is a coverage percentage that flatters the run.":
        "Mọi thứ phía sau đều bắt nguồn từ danh sách này: designer dựng một bộ test cho "
        "mỗi endpoint, và ánh xạ OWASP được tính từ các tham số này. Bỏ sót một endpoint "
        "là bỏ sót cả một bề mặt chưa được test, và bỏ sót một yêu cầu là một tỷ lệ phủ "
        "đang tâng bốc lượt chạy.",
})


# -- 2. design --------------------------------------------------------------


def _design_section(aid: str, detected_poc: str, has_tests: bool, opened: bool) -> str:
    notice = ""
    if detected_poc:
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
        "s-design", "2", _t("Design test plan"), f"""
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


def _coverage_section(aid: str, coverage: list[dict], opened: bool) -> str:
    applicable = [r for r in coverage if r.get("applicable")]
    other = [r for r in coverage if not r.get("applicable")]

    def _rows(items: list[dict]) -> str:
        out = ""
        for r in items:
            cat = str(r.get("category", ""))
            state = str(r.get("state", "UNKNOWN"))
            tone = ui.STATE_CLASS.get(state, "info")
            pct = int(r.get("pct", 0) or 0) if state != "NOT_APPLICABLE" else 0
            title, control_tip = _control_meta(cat)
            existing = int(r.get("existing_tests", 0) or 0)
            generated = int(r.get("generated_tests", 0) or 0)
            test_count_label = _t("{n} test(s) →").format(n=existing + generated)
            filter_link = (
                f'<a class="btn ghost" style="padding:2px 8px" '
                f'href="/assessment/{attr(aid)}?cat={attr(cat)}#s-plan">'
                f"{test_count_label}</a>"
                if existing + generated else f'<span class="muted">{_t("none")}</span>'
            )
            bar_tip = _t("{pct}% of this category comes from the imported PoC").format(pct=pct)
            gen_label = _t("{existing} PoC · {generated} gen").format(
                existing=existing, generated=generated)
            out += (
                "<tr>"
                f'<td><b class="mono">{e(cat.split(":")[0])}</b> {e(title)}'
                f'{info(control_tip, title)}</td>'
                f'<td>{ui.pill(_t(state.replace("_", " ")), tone)}</td>'
                f'<td>{ui.bar(pct, tone, bar_tip)}'
                f'<span class="muted mono" style="margin-left:6px">{pct}%</span></td>'
                f'<td class="muted mono">{gen_label}</td>'
                f"<td>{filter_link}</td></tr>"
            )
        return out

    headers = [
        _t("Category") + info(TIP["category"], _t("Category")),
        _t("State") + info(TIP["state"], _t("State")),
        _t("From PoC") + info(TIP["from_poc"], _t("From PoC")),
        _t("Tests") + info(TIP["tests"], _t("Tests")),
        "",
    ]
    body = ui.table(
        headers, _rows(applicable),
        empty=_t("Run step 2 to compute coverage."),
        cls="compact",
    )
    if other:
        show_label = _t("Show {n} category(ies) the analyzer judged not applicable").format(n=len(other))
        body += f"""<details style="margin-top:10px">
<summary class="muted" style="cursor:pointer;font-size:12.5px">
{show_label}</summary>
<div style="margin-top:8px">{ui.table(headers, _rows(other), cls="compact")}</div>
</details>"""
    covered = sum(1 for r in applicable if r.get("state") == "COVERED")
    summary = (_t("{n} applicable · {c} covered").format(n=len(applicable), c=covered)
               if coverage else _t("not computed yet"))
    return ui.section(
        "s-coverage", "3", _t("OWASP Coverage"), body,
        summary=summary,
        open=opened,
        tip=_t(
            "What this ticket needs tested, versus what the plan actually tests. The "
            "point of the tool is the gap between those two."
        ),
    )


def _control_meta(cat_value: str) -> tuple[str, str]:
    for cat in OwaspApiCategory:
        if cat.value == cat_value:
            control = CONTROLS.get(cat)
            if control:
                refs = " · ".join(control.references)
                return control.title, f"{control.summary} ({refs})"
            return cat.title, ""
    return cat_value, ""


# -- placeholder sections replaced in later steps ---------------------------


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
    "Run step 2 to compute coverage.": "Chạy bước 2 để tính độ phủ.",
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
    "No tests yet. Generate a plan in step 2 — or add the endpoint it should "
    "be built against in step 1 first.":
        "Chưa có test nào. Tạo kế hoạch ở bước 2 — hoặc thêm endpoint cần dựng test "
        "trước ở bước 1.",
    "nothing to approve": "chưa có gì để duyệt",
})


def _plan_section(aid: str, plan: dict, filters: dict, opened: bool, review=None) -> str:
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
            "No tests yet. Generate a plan in step 2 — or add the endpoint it should "
            "be built against in step 1 first."
        )
        return ui.section(
            "s-plan", "4", _t("Test plan & approval"),
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
            f'<span class="mono">{e(t.source.value)}</span></div>'
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
    return ui.section(
        "s-plan", "4", _t("Test plan & approval"), body,
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
<a class="btn ghost" href="/assessment/{attr(aid)}#s-plan">{_t("Clear")}</a>
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
        return (f'<a class="{e(cls)}" href="{base}{joiner}page={n}#s-plan">'
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


def _execute_section(aid: str, issue_key: str, st: _State, environments: dict[str, str],
                     active_environment: str, readiness, planner_enabled: bool,
                     opened: bool) -> str:
    can_execute = bool(environments)
    if environments:
        env_options = "".join(
            f"<option value='{attr(name)}' {'selected' if name == active_environment else ''}>"
            f"{e(name)} — {e(url)}</option>"
            for name, url in environments.items()
        )
        env_select = (f"<label class='field' style='max-width:320px'><span>{_t('Target environment')}</span>"
                      f"<select name='environment'>{env_options}</select></label>")
    else:
        env_select = ""

    adaptive_toggle = ""
    if can_execute and planner_enabled:
        adaptive_tip = _t(
            "After each undecided or failed result, the AI planner proposes a "
            "follow-up probe and the platform runs it automatically — bounded by "
            "iteration, wall-clock and follow-up caps, restricted to reviewed "
            "non-destructive mutations, and subject to the same scope validation. "
            "Follow-ups are auto-approved by policy, not reviewed by you."
        )
        adaptive_toggle = (
            f"<label class='row' style='gap:6px;align-items:center;margin:0' "
            f"data-tip='{attr(adaptive_tip)}'>"
            "<input type='checkbox' name='adaptive' value='true' style='width:auto'>"
            f"<span class='muted'>{_t('Adaptive follow-up')}</span></label>"
        )

    blockers = []
    if not can_execute:
        blockers.append(_t("no environment configured"))
    if not st.n_approved:
        blockers.append(_t("no approved tests"))
    disabled = "disabled" if blockers else ""
    note = (
        f"<span class='muted'>{_t('Blocked:')} {e(', '.join(blockers))}."
        + (f"  <a href='/config?tab=environments'>{_t('Add an environment')}</a>."
           if not can_execute else "")
        + "</span>"
        if blockers else
        f"<span class='muted'>{_t('Runs the {n} approved, non-destructive test(s) after scope validation.').format(n=st.n_approved)}</span>"
    )

    destructive_block = ""
    if can_execute and st.n_destructive_approved:
        # Deliberately separate from "Run approved tests" and off by default:
        # this sends real POST/PUT/PATCH/DELETE. A JS confirm() is one click to
        # blow through by habit, so this asks the tester to type the issue key
        # -- a real, if light, speed bump before mutating a live target.
        n = st.n_destructive_approved
        issue_key_js = repr(issue_key)
        run_destructive_label = _t("Run {n} destructive test(s) too").format(n=n)
        destructive_note = _t(
            "Sends real POST/PUT/PATCH/DELETE requests -- can create, modify, or delete "
            "real data on the target. Requires typing the issue key to confirm."
        )
        default_target = _t("the configured target")
        confirm_msg = _t(
            "This sends real POST/PUT/PATCH/DELETE requests for {n} destructive test(s) "
            "against {target}. This can create, modify, or delete real data -- it is not "
            "reversible. Type {issue} to confirm."
        )
        mismatch_msg = _t("Issue key did not match -- cancelled, nothing was run.")
        running_msg = _t("Running destructive tests...")
        destructive_block = f"""<div style="margin-top:14px;padding-top:14px;border-top:1px dashed var(--border-strong)">
<button type="button" class="btn sec danger" id="destructive-btn" onclick="confirmDestructive()">
{run_destructive_label}</button>
<p class="muted" style="margin:8px 0 0">{destructive_note}</p>
</div>
<script>
function confirmDestructive() {{
  var form = document.getElementById('execute-form');
  var sel = form.querySelector('select[name="environment"]');
  var target = sel ? sel.options[sel.selectedIndex].text : {json.dumps(default_target)};
  var typed = prompt(
    {json.dumps(confirm_msg)}.replace('{{n}}', '{n}').replace('{{target}}', target)
      .replace('{{issue}}', {issue_key_js})
  );
  if (typed === null) return;
  if (typed.trim() !== {issue_key_js}) {{
    alert({json.dumps(mismatch_msg)});
    return;
  }}
  document.getElementById('include-destructive-flag').value = 'true';
  var btn = document.getElementById('destructive-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> ' + {json.dumps(running_msg)};
  form.submit();
}}
</script>"""

    run_label = _t("Re-run approved tests") if st.n_executions else _t("Run approved tests")
    running_tests_msg = _t("Running tests…")
    body = f"""{readiness_banner(readiness)}
<form method="post" action="/assessment/{attr(aid)}/execute" class="row" id="execute-form"
 style="align-items:flex-end;gap:12px">
{env_select}
<input type="hidden" name="include_destructive" id="include-destructive-flag" value="false">
{adaptive_toggle}
<button class="btn" id="execute-btn" {disabled}>{e(run_label)}</button>
</form>
<p style="margin:10px 0 0">{note}</p>
{destructive_block}
<script>
(function () {{
  var form = document.getElementById('execute-form');
  if (!form) return;
  form.addEventListener('submit', function () {{
    var btn = document.getElementById('execute-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> ' + {json.dumps(running_tests_msg)};
  }});
}})();
</script>"""
    summary = (_t("{n} execution(s)").format(n=st.n_executions) if st.n_executions
               else (_t("ready") if not blockers else _t("blocked")))
    return ui.section(
        "s-execute", "5", _t("Execute"), body,
        summary=summary,
        open=opened,
        tip=_t(
            "Only APPROVED, non-destructive tests are sent, and only after every "
            "request passes scope validation."
        ),
    )


VI.update({
    "All categories": "Mọi danh mục", "Any severity": "Mọi mức độ",
    "Any approval": "Mọi trạng thái duyệt", "Any source": "Mọi nguồn",
    "{n} of {total} tests": "{n} trong {total} test", "{n} tests": "{n} test",
    "page {page}/{pages}": "trang {page}/{pages}",
    "Search": "Tìm kiếm", "Severity": "Mức độ", "Approval": "Duyệt",
    "All": "Tất cả", "Write only": "Chỉ ghi", "Read only": "Chỉ đọc",
    "Destructive": "Phá huỷ", "Source": "Nguồn",
    "Generation order": "Thứ tự tạo", "Category": "Danh mục", "Endpoint": "Endpoint",
    "Sort": "Sắp xếp", "Per page": "Mỗi trang", "Apply": "Áp dụng", "Clear": "Xoá bộ lọc",
    "matching this filter": "khớp bộ lọc này", "in the plan": "trong kế hoạch",
    "Back to PENDING. Withdrawing an approval is a thing you can do; unchecking a "
    "box never was — the handler only ever read the boxes that were ticked.":
        "Về lại PENDING. Rút lại một lượt duyệt là việc bạn có thể làm; bỏ tick một ô "
        "thì chưa bao giờ là vậy — handler chỉ từng đọc các ô đã được tick.",
    "apply to all {n} {scope}, not just the page": "áp dụng cho cả {n} test {scope}, không chỉ trang này",
    "selected": "đã chọn", "Reject": "Từ chối", "Reset": "Đặt lại",
    "{n} test(s)": "{n} test",
    "Target environment": "Môi trường mục tiêu",
    "After each undecided or failed result, the AI planner proposes a "
    "follow-up probe and the platform runs it automatically — bounded by "
    "iteration, wall-clock and follow-up caps, restricted to reviewed "
    "non-destructive mutations, and subject to the same scope validation. "
    "Follow-ups are auto-approved by policy, not reviewed by you.":
        "Sau mỗi kết quả chưa rõ hoặc thất bại, AI planner đề xuất một phép thử tiếp "
        "theo và nền tảng tự động chạy nó — giới hạn bởi số vòng lặp, thời gian thực "
        "và số lần thử tiếp theo, chỉ giới hạn ở các mutation không phá huỷ đã được "
        "duyệt trước, và vẫn qua đúng bước kiểm tra phạm vi. Các lượt tiếp theo được "
        "tự động duyệt theo chính sách, không phải do bạn xem lại.",
    "Adaptive follow-up": "Thử tiếp theo thích ứng",
    "no environment configured": "chưa cấu hình môi trường",
    "no approved tests": "chưa có test nào được duyệt",
    "Blocked:": "Bị chặn:", "Add an environment": "Thêm môi trường",
    "Runs the {n} approved, non-destructive test(s) after scope validation.":
        "Chạy {n} test không phá huỷ đã duyệt, sau khi qua kiểm tra phạm vi.",
    "Run {n} destructive test(s) too": "Chạy luôn {n} test phá huỷ",
    "Sends real POST/PUT/PATCH/DELETE requests -- can create, modify, or delete "
    "real data on the target. Requires typing the issue key to confirm.":
        "Gửi request POST/PUT/PATCH/DELETE thật -- có thể tạo, sửa hoặc xoá dữ liệu "
        "thật trên mục tiêu. Cần gõ issue key để xác nhận.",
    "the configured target": "mục tiêu đã cấu hình",
    "This sends real POST/PUT/PATCH/DELETE requests for {n} destructive test(s) "
    "against {target}. This can create, modify, or delete real data -- it is not "
    "reversible. Type {issue} to confirm.":
        "Thao tác này gửi request POST/PUT/PATCH/DELETE thật cho {n} test phá huỷ vào "
        "{target}. Có thể tạo, sửa hoặc xoá dữ liệu thật -- không thể hoàn tác. Gõ "
        "{issue} để xác nhận.",
    "Issue key did not match -- cancelled, nothing was run.":
        "Issue key không khớp -- đã huỷ, không có gì được chạy.",
    "Running destructive tests...": "Đang chạy test phá huỷ...",
    "Re-run approved tests": "Chạy lại test đã duyệt", "Run approved tests": "Chạy test đã duyệt",
    "Running tests…": "Đang chạy test…",
    "{n} execution(s)": "{n} lượt chạy", "ready": "sẵn sàng", "blocked": "bị chặn",
    "Execute": "Chạy",
    "Only APPROVED, non-destructive tests are sent, and only after every "
    "request passes scope validation.":
        "Chỉ các test không phá huỷ đã DUYỆT mới được gửi, và chỉ sau khi mọi request "
        "qua kiểm tra phạm vi.",
})


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


_OVERALL_TONE = {"PASSED": "low", "FAILED": "crit", "INCOMPLETE": "med"}


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
            "covered. It never overwrites a sealed verdict and never creates a finding."
        )
        return (
            "<div class='card pad' style='margin-bottom:14px'>"
            f"<p style='margin:0 0 8px'><b>{_t('These results have not been reviewed.')}</b> "
            f"<span class='muted'>{not_reviewed_note}</span></p>"
            + _triage_summary(triage) +
            f"<form method='post' action='/assessment/{attr(aid)}/adjudicate' "
            "class='js-busy' style='margin:0'>"
            f"<button class='btn sec'>{_t('Review results')}</button></form></div>"
        )

    tone = _OVERALL_TONE.get(run.overall, "info")
    manual = run.manual_review_items
    manual_rows = ""
    for adjudication in manual[:12]:
        manual_rows += (
            f'<tr><td class="mono">{e(adjudication.test_id)}</td>'
            f'<td>{e(adjudication.triage_reason)}</td>'
            f'<td class="muted">{e(adjudication.recommended_action)}</td></tr>'
        )
    manual_html = ""
    if manual_rows:
        manual_html = (
            f'<div class="glabel" style="margin-top:12px">{_t("Still needs you")}'
            f'{info(TIP["review"], _t("Review"))}</div>'
            + ui.table([_t("Test"), _t("Why it is undecided"), _t("What would settle it")],
                       manual_rows, cls="compact",
                       scroll=len(manual) > 8)
        )
        if len(manual) > 12:
            more_label = _t("{n} more in the report.").format(n=len(manual) - 12)
            manual_html += f"<p class='muted' style='margin:6px 0 0'>{more_label}</p>"

    resolved = run.auto_resolved
    resolved_html = ""
    if resolved:
        advisory_word = _t("advisory")
        rows = "".join(
            f'<tr><td class="mono">{e(a.test_id)}</td>'
            f'<td>{ui.pill(_t(a.assessed_result), ui.VERDICT_CLASS.get(a.assessed_result, "info"))}'
            f' <span class="muted">{advisory_word}</span></td>'
            f'<td>{e(a.rationale)}</td></tr>'
            for a in resolved[:12]
        )
        settled_note = _t("(advisory — the sealed verdict and the finding count are unchanged)")
        resolved_html = (
            f'<div class="glabel" style="margin-top:12px">{_t("Settled by review")} '
            f'<span class="muted">{settled_note}</span></div>'
            + ui.table([_t("Test"), _t("Read as"), _t("Why")], rows, cls="compact",
                       scroll=len(resolved) > 8)
        )

    degraded = (f"<p class='muted' style='margin:6px 0 0'>&#9888; {e(run.degraded_reason)}</p>"
                if run.degraded_reason else "")
    who = _t("AI reviewer") if run.reviewer == "ai" else _t("deterministic triage only")
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
        f"<button class='btn ghost'>&#8635; {_t('Review again')}</button></form></div>"
    )


def _results_section(aid: str, issue_key: str, st: _State, findings, verdicts: dict,
                     opened: bool, run=None, triage: dict | None = None) -> str:
    rows = ""
    for f in findings:
        tone = ui.SEV_CLASS.get(f.severity.value, "info")
        rows += (
            f'<tr><td class="mono"><b>{e(f.finding_id)}</b></td>'
            f"<td>{e(f.title)}</td>"
            f'<td class="mono">{e(f.owasp_category.value.split(":")[0])}</td>'
            f"<td>{ui.pill(f.severity.value, tone)}</td>"
            f'<td class="mono"><span class="trunc">{e(f.endpoint)}</span></td>'
            f'<td class="mono muted">{e(", ".join(f.affected_tests))}</td></tr>'
        )
    findings_table = ui.table(
        [_t("ID"), _t("Title"), "OWASP", _t("Severity"), _t("Endpoint"), _t("Tests")],
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
        rerun = f"""<div class="glabel" style="margin-top:16px">{_t("Run again")}</div>
<div class="actionrow">
<form method="post" action="/assessment/{attr(aid)}/rerun" class="rerun-form" style="margin:0"
 data-kind="same">
<input type="hidden" name="mode" value="same">
<button class="btn sec">&#8635; {_t("Re-run this plan")}</button></form>
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
    if (!confirm(msg)) {{ ev.preventDefault(); return; }}
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
<a class="btn sec" href="/assessment/{attr(aid)}/report" target="_blank">{_t("HTML report")} ↗</a>
<a class="btn sec" href="/assessment/{attr(aid)}/regression">{_t("Regression diff")}</a>
<a class="btn sec" href="/assessment/{attr(aid)}/comment">{_t("Preview Jira comment")}</a>
</div>
<div class="glabel">{_t("Export")}</div>
<div class="actionrow">
<a class="btn sec" href="/assessment/{attr(aid)}/export.html">HTML</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.pdf">PDF</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.xlsx">XLSX</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.json">JSON</a>
<a class="btn sec" href="/assessment/{attr(aid)}/export.postman">Postman (Newman)</a>
</div>"""
    summary = _t("{n} finding(s)").format(n=len(findings)) if st.n_executions else _t("not run yet")
    if run is not None:
        summary = _t("{overall} · {pct}% covered · ").format(
            overall=_t(run.overall), pct=run.coverage_pct) + summary
    return ui.section(
        "s-results", "6", _t("Results"), body,
        summary=summary,
        open=opened,
        tip=_t(
            "A finding is only minted from a test the runner judged FAIL — a confirmed "
            "control break with disclosure in the response."
        ),
    )


# -- flash ------------------------------------------------------------------


VI.update({
    "Verdicts": "Kết luận",
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
    "Review results": "Đánh giá kết quả",
    "Still needs you": "Vẫn cần bạn", "Review": "Đánh giá",
    "Test": "Test", "Why it is undecided": "Vì sao chưa rõ",
    "What would settle it": "Cần gì để giải quyết",
    "{n} more in the report.": "{n} mục nữa trong báo cáo.",
    "advisory": "tham khảo", "Settled by review": "Đã giải quyết qua đánh giá",
    "(advisory — the sealed verdict and the finding count are unchanged)":
        "(chỉ tham khảo — kết luận đã niêm phong và số finding không đổi)",
    "Read as": "Đọc là", "Why": "Vì sao",
    "AI reviewer": "AI reviewer", "deterministic triage only": "chỉ phân loại tất định",
    "· {decided}% of executions decided · reviewed by {who}":
        "· {decided}% lượt thực thi đã quyết · người đánh giá {who}",
    "{pct}% of the ticket covered": "{pct}% ticket đã được phủ",
    "ID": "ID", "Title": "Tiêu đề", "Endpoint": "Endpoint", "Tests": "Test",
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
    "Working…": "Đang xử lý…",
    "Run again": "Chạy lại", "Re-run this plan": "Chạy lại kế hoạch này",
    "Re-import from Jira": "Nhập lại từ Jira",
    "View": "Xem", "HTML report": "Báo cáo HTML", "Regression diff": "So sánh regression",
    "Preview Jira comment": "Xem trước comment Jira", "Export": "Xuất",
    "{n} finding(s)": "{n} phát hiện", "not run yet": "chưa chạy",
    "{overall} · {pct}% covered · ": "{overall} · phủ {pct}% · ",
    "PASSED": "ĐẠT", "FAILED": "LỖI", "INCOMPLETE": "CHƯA HOÀN TẤT",
    "Results": "Kết quả",
    "A finding is only minted from a test the runner judged FAIL — a confirmed "
    "control break with disclosure in the response.":
        "Một finding chỉ được tạo từ test mà runner đánh giá là LỖI — control thực sự bị "
        "phá vỡ và phản hồi có để lộ điều đó.",
    "opening the report…": "đang mở báo cáo…", "View report now": "Xem báo cáo ngay",
    "Open ticket": "Mở ticket",
})


_EXECUTED_FLASH = re.compile(r"^Executed (\d+) tests?, (\d+) FAIL$")


def _flash(aid: str, flash: str, ticket_url: str) -> str:
    """`flash` arrives as one of a handful of fixed English signals main.py
    generates (`"Executed N tests, M FAIL"`, `"Posted to Jira"`, ...) — kept in
    English there so this function can still recognise them by exact
    match/prefix regardless of the viewer's language, then render its own
    translated sentence rather than echo the English signal verbatim."""
    report_href = f"/assessment/{e(aid)}/report"
    m = _EXECUTED_FLASH.match(flash)
    if m:
        # Land here right after a run: say what happened, then move straight to
        # the report — the natural next step — while leaving an escape hatch in
        # case the redirect is slow or the user wants to stay.
        shown = _t("Executed {n} tests, {f} FAIL").format(n=m.group(1), f=m.group(2))
        return f"""<div class='card pad flash exec-flash' id='exec-flash'>
<b>{e(shown)}</b> — {_t("opening the report…")}
<a href="{report_href}" class="btn sec">{_t("View report now")}</a>
</div>
<script>setTimeout(function () {{ window.location.href = {report_href!r}; }}, 1400);</script>"""
    if flash == "Posted to Jira" and ticket_url and ticket_url.startswith(("http://", "https://")):
        # ticket_url is a client-supplied query parameter (it round-trips through
        # a redirect, not signed/verified) — html.escape() alone does not block a
        # javascript: href, so the scheme must be checked before this ever
        # becomes a clickable link.
        return f"""<div class='card pad flash exec-flash'>
<b>{_t("Posted to Jira")}</b>
<a href="{e(ticket_url)}" class="btn sec" target="_blank" rel="noopener">{_t("Open ticket")} ↗</a>
</div>"""
    if flash:
        return f"<div class='card pad flash'>{e(_t(flash))}</div>"
    return ""


# -- the page ---------------------------------------------------------------

def _body_js() -> str:
    working_label = json.dumps(_t("Working…"))
    return f"""
(function () {{
  // PoC format tabs
  document.querySelectorAll('.tabbar').forEach(function (bar) {{
    bar.querySelectorAll('button').forEach(function (b) {{
      b.addEventListener('click', function () {{
        bar.querySelectorAll('button').forEach(function (x) {{
          x.classList.remove('active');
          x.setAttribute('aria-selected', 'false');
        }});
        bar.parentElement.querySelectorAll('.tabpane').forEach(function (x) {{
          x.classList.remove('active');
        }});
        b.classList.add('active');
        b.setAttribute('aria-selected', 'true');
        var pane = document.getElementById(b.dataset.tab);
        if (pane) pane.classList.add('active');
      }});
    }});
  }});
  // Every long-running form gets the same feedback, rather than only Execute.
  document.querySelectorAll('form.js-busy').forEach(function (f) {{
    f.addEventListener('submit', function () {{
      var btn = f.querySelector('button:not([type=button])');
      if (!btn || btn.disabled) return;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> ' + {working_label};
    }});
  }});
  // Highlight the step nav entry for the section currently in view.
  var links = Array.prototype.slice.call(document.querySelectorAll('.stepnav a'));
  var targets = links.map(function (a) {{ return document.querySelector(a.getAttribute('href')); }});
  function spy() {{
    var best = -1, bestTop = -Infinity;
    targets.forEach(function (t, i) {{
      if (!t) return;
      var top = t.getBoundingClientRect().top - 80;
      if (top <= 0 && top > bestTop) {{ bestTop = top; best = i; }}
    }});
    links.forEach(function (a, i) {{ a.classList.toggle('on', i === best); }});
  }}
  spy();
  window.addEventListener('scroll', spy, {{ passive: true }});
}})();
"""


def body(
    assessment: Assessment,
    analysis: dict,
    coverage: list[dict],
    plan: dict,
    *,
    filters: dict,
    n_executions: int,
    findings: list,
    environments: dict[str, str],
    active_environment: str,
    readiness,
    planner_enabled: bool,
    verdicts: dict | None = None,
    plan_review=None,
    run_assessment=None,
    triage: dict | None = None,
    flash: str = "",
    ticket_url: str = "",
) -> str:
    verdicts = verdicts or {}
    aid = assessment.id
    analysis = analysis or {}
    endpoints = analysis.get("endpoints") or []
    st = _State(len(endpoints), plan.get("meta") or {}, n_executions)
    opens = st.opens()
    # st.n_tests, not the page: a filter that happens to match nothing must not
    # make a stale plan look current or relabel the design button.
    stale = (bool(analysis.get("plan_fingerprint")) and st.n_tests > 0
             and _is_stale(analysis))

    status_label, status_tone = ui.STATUS_PILL.get(
        assessment.status, (assessment.status.title(), "info")
    )
    summary_line = analysis.get("business_summary") or ""
    sensitive = analysis.get("sensitive_operation")
    target = assessment.target_base_url

    copy_tip = _t("Copy the assessment id")
    sensitive_label = _t("sensitive operation:") + f" <b>{_t('yes') if sensitive else _t('no')}</b>"
    last_target = (f'· {_t("last target:")} <span class="mono">{e(target)}</span>' if target else "")
    copied_label = json.dumps(_t("copied"))
    head = f"""<div class="pagehead">
<div>
<h1>{e(assessment.issue_key)} {ui.pill(_t(status_label), status_tone)}</h1>
<p class="sub" style="margin:4px 0 0">{e(summary_line)}</p>
<p class="muted" style="margin:6px 0 0;font-size:12.5px">
<span class="mono">{e(aid)}</span>
<button type="button" class="copy" data-copy="{attr(aid)}"
 data-tip="{attr(copy_tip)}">{_t("copy")}</button>
· {sensitive_label}
{last_target}</p>
</div>
<div class="row" style="gap:6px">
<a href="/assessment/{attr(aid)}/report" class="btn sec" target="_blank">{_t("Report")} ↗</a>
<a href="/" class="btn ghost">← {_t("All assessments")}</a>
</div>
</div>"""

    return f"""{_flash(aid, flash, ticket_url)}
{head}
{_stats(st, findings, coverage)}
{_step_nav(st)}
{_endpoints_section(aid, endpoints, stale, opens["endpoints"],
                   requirements=analysis.get("requirements") or [],
                   coverage_items=(run_assessment.items if run_assessment else []))}
{_design_section(aid, analysis.get("detected_poc_source") or "", st.n_tests > 0, opens["design"])}
{_coverage_section(aid, coverage or [], opens["coverage"])}
{_plan_section(aid, plan, filters, opens["plan"], review=plan_review)}
{_execute_section(aid, assessment.issue_key, st, environments or {}, active_environment,
                  readiness, planner_enabled, opens["execute"])}
{_results_section(aid, assessment.issue_key, st, findings, verdicts, opens["results"],
                  run=run_assessment, triage=triage or {})}
<script>
{_body_js()}
(function () {{
  document.querySelectorAll('.copy').forEach(function (b) {{
    b.addEventListener('click', function () {{
      navigator.clipboard && navigator.clipboard.writeText(b.dataset.copy);
      var was = b.textContent; b.textContent = {copied_label};
      setTimeout(function () {{ b.textContent = was; }}, 1200);
    }});
  }});
}})();
</script>"""


def _is_stale(analysis: dict) -> bool:
    """True when the stored plan fingerprint no longer matches the endpoints."""
    from app.schemas.analysis import IssueAnalysis

    try:
        return IssueAnalysis.model_validate(analysis).plan_is_stale()
    except Exception:
        # A malformed analysis blob is not worth a 500 on a page whose job is to
        # let a tester fix exactly that kind of problem.
        return False


VI.update({
    "Working…": "Đang xử lý…",
    "Copy the assessment id": "Copy id của assessment",
    "sensitive operation:": "thao tác nhạy cảm:", "yes": "có", "no": "không",
    "last target:": "mục tiêu gần nhất:",
    "copied": "đã copy",
    "copy": "copy",
    "Report": "Báo cáo", "All assessments": "Tất cả assessment",
    "Analyzed": "Đã phân tích",
    "Executed {n} tests, {f} FAIL": "Đã chạy {n} test, {f} LỖI",
})
