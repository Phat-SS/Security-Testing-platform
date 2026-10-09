"""Phase 1 — Scope: what the ticket asks for, and the attack surface it lives
on.

Every test is built per endpoint, so this list is the single input the whole
plan is derived from — which is why it is editable.
"""

from __future__ import annotations


from app.api import ui
from app.api.ui import attr, e, info
from .state import TIP
from app.core.i18n import VI, tt as _t
from app.owasp.api_top10_2023 import CONTROLS
from app.schemas.enums import OwaspApiCategory

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
        f'aria-label="Expected Public" style="width:auto"'
        f'{" checked" if ep.get("expected_public") else ""}></td>'
        f'<td><input type="checkbox" name="writes_properties" value="true" form="{attr(form_id)}" '
        f'aria-label="Writes properties" style="width:auto"'
        f'{" checked" if ep.get("writes_properties") else ""}></td>'
        f'<td><input name="url_fields" form="{attr(form_id)}" class="mono" '
        f'aria-label="URL Fields" value="{attr(urls)}" placeholder="callbackUrl"></td>'
    )


_REQ_STATE_CLASS = {
    "COVERED_PASS": "ok", "COVERED_FAIL": "crit", "PARTIAL": "med",
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
        f'<div class="glabel" style="margin-bottom:4px">{_t("Requirements Read from the Ticket")}'
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
    "Regenerate it under Plan &mdash; otherwise the plan you approve is the one built "
    "for the endpoints you have since changed. Approvals on tests that come back "
    "unchanged are kept."
)
reanalyze_note_text = (
    "Re-reads the Jira issue and rebuilds this list. Hand-entered rows are kept; the "
    "OWASP mapping is rebuilt from scratch, which is the only operation allowed to "
    "drop a category."
)
uncovered_headline_text = "The test plan targets an endpoint that is not in this list."
uncovered_body_text = (
    "This is not a stale-plan problem: the endpoint list is read from ticket prose, "
    "while a PoC's request can be built from a variable the extractor never sees. Add "
    "the endpoint below if it is real attack surface, or leave it if the test is an "
    "intentional negative control."
)


def stale_banner(aid: str) -> str:
    """The plan no longer matches the endpoint list it was built from.

    Page-level, not phase-level: the person this warning is for is the one
    reading the plan, and they are not on the Scope phase.
    """
    return (
        "<div class='card pad warn stale' style='margin-bottom:14px'>"
        f"<b>&#9888; {_t(stale_headline_text)}</b>"
        f"<p class='muted' style='margin:6px 0 0'>{_t(stale_body_text)}</p>"
        f"<p style='margin:10px 0 0'><a class='btn sec' href='/assessment/{attr(aid)}?phase=plan'>"
        f"{_t('Go to Plan')}</a></p></div>"
    )


def _spec_import(aid: str) -> str:
    """Take the endpoint list from a specification instead of from prose.

    Placed with the endpoint table rather than beside the PoC import, because
    this is not another source of tests — it is the source of the list every
    test is generated from. The regex over ticket prose that produced this list
    until now cannot see an endpoint written in a table, cannot tell whether a
    route is public, and only finds object ids that appear in a path.
    """
    tip = _t("Parsed, never fetched or replayed. Additive: hand-entered rows are kept. "
             "From a HAR only names are kept, never header values or bodies.")
    return (
        f'<details class="sect" id="s-spec" data-sect="s-spec">'
        f'<summary class="s-head"><span class="s-chev" aria-hidden="true"></span>'
        f'<span class="s-title">{_t("Import Endpoints")}</span>'
        f'{info(tip, _t("Import Endpoints"))}'
        f'<span class="s-sum">{_t("OpenAPI · Swagger · HAR Capture")}</span></summary>'
        f'<div class="s-body">'
        f'<form method="post" action="/assessment/{attr(aid)}/openapi" '
        f'enctype="multipart/form-data" class="js-busy">'
        f'<label class="field"><span>{_t("Paste a Spec or HAR")}</span>'
        '<textarea name="spec" rows="6" '
        'placeholder="openapi: 3.0.3&#10;paths: ..."></textarea></label>'
        f'<div class="row" style="margin-top:10px">'
        f'<input type="file" name="spec_file" accept=".json,.yaml,.yml,.har,application/json,text/yaml"'
        f' style="max-width:320px">'
        f'<button class="btn">{_t("Import Endpoints")}</button>'
        f'</div></form></div></details>'
    )


def _endpoints_section(aid: str, endpoints: list[dict], stale: bool, opened: bool,
                       requirements: list[dict] | None = None,
                       coverage_items: list | None = None,
                       uncovered_poc_endpoints: list[str] | None = None) -> str:
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
            f'<td class="rowact">' + ui.action_menu([
                ui.Item(_t("Edit"), button_class="ep-edit", button_data={"ep": i}),
                ui.Item(_t("Delete"), action=f"/assessment/{aid}/endpoints/delete",
                        fields={"signature": sig}, form_class="confirm-ep",
                        form_data={"what": sig}, danger=True),
            ], _t("Actions for {name}").format(name=sig)) + '</td></tr>'
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
            _t("Expected Public") + info(TIP["expected_public"], _t("Expected Public")),
            _t("Writes") + info(TIP["writes"], _t("Writes")),
            _t("URL Fields") + info(TIP["url_fields"], _t("URL Fields")),
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
    # `stale` is rendered by the shell, above the rail — see `stale_banner`.
    # It is a fact about the PLAN, so burying it here meant someone approving a
    # stale plan never met it.
    if uncovered_poc_endpoints:
        sigs = "".join(f'<span class="kchip mono">{e(sig)}</span>'
                       for sig in uncovered_poc_endpoints)
        body += (
            "<div class='card pad warn stale' style='margin-top:12px'>"
            f"<b>&#9888; {_t(uncovered_headline_text)}</b>"
            f"<p class='muted' style='margin:6px 0 0'>{_t(uncovered_body_text)}</p>"
            f"<p style='margin:10px 0 0'>{sigs}</p></div>"
        )

    actions = (
        f'<form method="post" action="/assessment/{attr(aid)}/reanalyze" style="margin:0" '
        f'class="confirm-reanalyze">'
        f'<button class="btn sec">&#8635; {_t("Re-analyze from Ticket")}</button></form>'
        f'<span class="muted" style="font-size:12.5px;align-self:center">'
        f'{_t(reanalyze_note_text)}</span>'
    )

    n_manual = sum(1 for ep in endpoints if ep.get("manual"))
    summary = _t("{n} Endpoint(s)").format(n=len(endpoints))
    if requirements:
        summary = _t("{n} Requirement(s) · ").format(n=len(requirements)) + summary
    if n_manual:
        summary += _t(" · {n} hand-entered").format(n=n_manual)
    if stale:
        summary += " · " + _t("plan is stale")
    if uncovered_poc_endpoints:
        summary += " · " + _t("{n} Test(s) Target an Unlisted Endpoint").format(
            n=len(uncovered_poc_endpoints))

    return ui.section(
        # Retitled when the requirement list is present, because the step now
        # holds both halves of "what is this plan derived from": what the ticket
        # asks for, and the surface those asks live on.
        "s-endpoints", "",
        _t("Requirements & Endpoints") if requirements else _t("Endpoints"),
        body + _spec_import(aid) + _ENDPOINTS_JS,
        summary=summary,
        actions=actions,
        open=opened,
        tone="stale" if (stale or uncovered_poc_endpoints) else "",
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
      stpConfirmSubmit(f, ev, 'Remove ' + f.dataset.what + ' from the analysis?\\n\\n' +
                   'Its tests stay in the plan until you regenerate it.', { danger: true });
    });
  });
  document.querySelectorAll('form.confirm-reanalyze').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      stpConfirmSubmit(f, ev, 'Re-read the ticket and rebuild the endpoint list?\\n\\n' +
                   'Hand-entered endpoints are kept. Edits to extracted rows are not.');
    });
  });
})();
</script>
"""

VI.update({
    "Parsed, never fetched or replayed. Additive: hand-entered rows are kept. "
    "From a HAR only names are kept, never header values or bodies.":
        "Chỉ phân tích, không bao giờ gọi hay phát lại. Chỉ bổ sung: các dòng nhập tay "
        "được giữ. Từ HAR chỉ giữ tên, không bao giờ giữ giá trị header hay body.",
    "OpenAPI · Swagger · HAR Capture": "OpenAPI · Swagger · Bản Ghi HAR",
    "Paste a Spec or HAR": "Dán Spec Hoặc HAR",
})


VI.update({
    "{n} setting(s) will block this run before any request is sent.":
        "{n} cấu hình sẽ chặn lượt chạy này trước khi có request nào được gửi.",
    "{n} setting(s) will make results less conclusive.":
        "{n} cấu hình sẽ khiến kết quả kém chắc chắn hơn.",
    "Open Configuration": "Mở Cấu Hình",
    "Endpoints": "Endpoint", "Tests": "Test", "Approved": "Đã Duyệt",
    "Executed": "Đã Chạy", "Findings": "Phát Hiện", "Coverage": "Độ Phủ",
    "none": "không có",
    "Requirements Read from the Ticket": "Yêu Cầu Đọc Được Từ Ticket",
    "Requirements": "Yêu Cầu", "Item": "Mục", "Requirement": "Yêu Cầu",
    "State": "Trạng Thái", "Note": "Ghi Chú",
    "No requirement items were extracted from this ticket.":
        "Không trích xuất được mục yêu cầu nào từ ticket này.",
    "yes": "có", "no": "không",
    "Edit": "Sửa", "Delete": "Xoá", "Save": "Lưu", "Cancel": "Huỷ", "Add": "Thêm",
    "Object IDs": "Object ID", "Auth": "Auth", "Writes": "Ghi Dữ Liệu",
    "URL Fields": "Trường URL",
    "No endpoints were extracted from the ticket &mdash; the extractor reads prose, so "
    "an endpoint written in a table or an attachment is invisible to it. Add it in the "
    "row below; without one there is nothing for the designer to build tests against.":
        "Không trích xuất được endpoint nào từ ticket &mdash; bộ trích xuất đọc văn xuôi, "
        "nên một endpoint viết trong bảng hoặc file đính kèm sẽ không thấy được. Thêm nó "
        "ở dòng bên dưới; không có nó thì designer không có gì để dựng test.",
    "The current test plan was generated from a different endpoint list.":
        "Kế hoạch test hiện tại được tạo từ một danh sách endpoint khác.",
    "Regenerate it under Plan &mdash; otherwise the plan you approve is the one built "
    "for the endpoints you have since changed. Approvals on tests that come back "
    "unchanged are kept.":
        "Tạo lại ở phần Kế hoạch &mdash; nếu không kế hoạch bạn duyệt sẽ là kế hoạch dựng cho "
        "danh sách endpoint cũ, trong khi bạn đã thay đổi nó. Các duyệt trên test không "
        "đổi sẽ được giữ nguyên.",
    "Go to Plan": "Đến Phần Kế Hoạch",
    "Re-analyze from Ticket": "Phân Tích Lại Từ Ticket",
    "Import Endpoints": "Nhập Endpoint",
    "Re-reads the Jira issue and rebuilds this list. Hand-entered rows are kept; the "
    "OWASP mapping is rebuilt from scratch, which is the only operation allowed to "
    "drop a category.":
        "Đọc lại issue Jira và dựng lại danh sách này. Các dòng nhập tay được giữ "
        "nguyên; ánh xạ OWASP được dựng lại từ đầu — đây là thao tác duy nhất được phép "
        "bỏ một danh mục.",
    "{n} Endpoint(s)": "{n} Endpoint", "{n} Requirement(s) · ": "{n} Yêu Cầu · ",
    " · {n} hand-entered": " · {n} nhập tay", "plan is stale": "kế hoạch đã cũ",
    "{n} Test(s) Target an Unlisted Endpoint": "{n} Test Nhắm Vào Endpoint Chưa Có Trong Danh Sách",
    "The test plan targets an endpoint that is not in this list.":
        "Kế hoạch test đang nhắm vào một endpoint không có trong danh sách này.",
    "This is not a stale-plan problem: the endpoint list is read from ticket prose, "
    "while a PoC's request can be built from a variable the extractor never sees. Add "
    "the endpoint below if it is real attack surface, or leave it if the test is an "
    "intentional negative control.":
        "Đây không phải lỗi kế hoạch cũ: danh sách endpoint được đọc từ văn xuôi ticket, "
        "trong khi request của PoC có thể được dựng từ một biến mà bộ trích xuất không "
        "bao giờ thấy. Thêm endpoint bên dưới nếu đó là bề mặt tấn công thật, hoặc bỏ qua "
        "nếu test đó là một control âm tính có chủ đích.",
    "Requirements & Endpoints": "Yêu Cầu & Endpoint",
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
            test_count_label = _t("{n} Test(s) →").format(n=existing + generated)
            filter_link = (
                f'<a class="btn ghost" style="padding:2px 8px" '
                f'href="/assessment/{attr(aid)}?cat={attr(cat)}&phase=plan">'
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
        empty=_t("Generate a plan to compute coverage."),
        cls="compact",
    )
    if other:
        show_label = _t("Show {n} Not-Applicable Category(ies)").format(n=len(other))
        body += f"""<details style="margin-top:10px">
<summary class="muted" style="cursor:pointer;font-size:12.5px">
{show_label}</summary>
<div style="margin-top:8px">{ui.table(headers, _rows(other), cls="compact")}</div>
</details>"""
    covered = sum(1 for r in applicable if r.get("state") == "COVERED")
    summary = (_t("{n} Applicable · {c} Covered").format(n=len(applicable), c=covered)
               if coverage else _t("not computed yet"))
    return ui.section(
        "s-coverage", "", _t("OWASP Coverage"), body,
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


_REVIEW_TONE = {"APPROVE": "ok", "REVISE": "med", "INSUFFICIENT": "crit"}
