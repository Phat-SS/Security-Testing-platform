"""Phase 3 — Run: the environment, the gates, and the button that sends packets.

`readiness_banner` is defined here, beside the run it is about, but the shell
renders it above the phase rail: a configuration problem that will make every
request come back BLOCKED is worth knowing while you are still approving tests.
"""

from __future__ import annotations

import json

from app.api import ui
from app.api.ui import attr, e
from .progress import RUNNING_STATES, live_panel
from .state import _State
from app.core.i18n import VI, tt as _t

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
        f"<a href='{e(href)}' class='btn sec'>{_t('Open Configuration')}</a></div>"
    )


# -- page state -------------------------------------------------------------


def _execute_section(aid: str, issue_key: str, st: _State, environments: dict[str, str],
                     active_environment: str, planner_enabled: bool, opened: bool,
                     job=None) -> str:
    running = job is not None and job.state in RUNNING_STATES
    can_execute = bool(environments) and not running
    if environments:
        env_options = "".join(
            f"<option value='{attr(name)}' {'selected' if name == active_environment else ''}>"
            f"{e(ui.titleize(name))} — {e(url)}</option>"
            for name, url in environments.items()
        )
        env_select = (f"<label class='field' style='max-width:320px'><span>{_t('Target Environment')}</span>"
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
            f"<span class='muted'>{_t('Adaptive Follow-up')}</span></label>"
        )

    blockers = []
    if not can_execute:
        blockers.append(_t("no environment configured"))
    if not st.n_approved:
        blockers.append(_t("no approved tests"))
    disabled = "disabled" if blockers else ""
    note = (
        f"<span class='muted'>{_t('Blocked:')} {e(', '.join(blockers))}."
        + (f"  <a href='/config?tab=environments'>{_t('Add an Environment')}</a>."
           if not can_execute else "")
        + "</span>"
        if blockers else
        f"<span class='muted'>{_t('Runs the {n} approved, non-destructive test(s) after scope validation.').format(n=st.n_approved)}</span>"
    )

    destructive_block = ""
    if can_execute and st.n_destructive_approved:
        # Deliberately separate from "Run Approved Tests" and off by default:
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
  // The issue key must be typed exactly before Confirm enables: the dialog
  // never accepts a near match, so there is no mismatch case to report.
  stpConfirm(
    {json.dumps(confirm_msg)}.replace('{{n}}', '{n}').replace('{{target}}', target)
      .replace('{{issue}}', {issue_key_js}),
    {{ danger: true, requireText: {issue_key_js}, ok: {json.dumps(run_destructive_label)} }}
  ).then(function (yes) {{
    if (!yes) return;
    document.getElementById('include-destructive-flag').value = 'true';
    var btn = document.getElementById('destructive-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> ' + {json.dumps(running_msg)};
    form.submit();
  }});
}}
</script>"""

    run_label = _t("Re-run Approved Tests") if st.n_executions else _t("Run Approved Tests")
    running_tests_msg = _t("Running tests…")
    # The banner itself is rendered once by the shell, above the rail, so a
    # tester reading the plan sees that the run will be blocked without having
    # to reach the Run phase to find out. See shell.body.
    body = f"""{live_panel(aid, job)}
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
    summary = (_t("{n} Execution(s)").format(n=st.n_executions) if st.n_executions
               else (_t("ready") if not blockers else _t("blocked")))
    return ui.section(
        "s-execute", "", _t("Execute"), body,
        summary=summary,
        open=opened,
        tip=_t(
            "Only APPROVED, non-destructive tests are sent, and only after every "
            "request passes scope validation."
        ),
    )


VI.update({
    "All Categories": "Mọi Danh Mục", "Any Severity": "Mọi Mức Độ",
    "Any Approval": "Mọi Trạng Thái Duyệt", "Any Source": "Mọi Nguồn",
    "{n} of {total} tests": "{n} Trong {total} Test", "{n} tests": "{n} Test",
    "page {page}/{pages}": "trang {page}/{pages}",
    "Search": "Tìm Kiếm", "Severity": "Mức Độ", "Approval": "Duyệt",
    "All": "Tất Cả", "Write Only": "Chỉ Ghi", "Read Only": "Chỉ Đọc",
    "Destructive": "Phá Huỷ", "Source": "Nguồn",
    "Generation Order": "Thứ Tự Tạo", "Category": "Danh Mục", "Endpoint": "Endpoint",
    "Sort": "Sắp Xếp", "Per Page": "Mỗi Trang", "Apply": "Áp Dụng", "Clear": "Xoá Bộ Lọc",
    "Matching This Filter": "Khớp Bộ Lọc Này", "in the Plan": "Trong Kế Hoạch",
    "Back to PENDING. Withdrawing an approval is a thing you can do; unchecking a "
    "box never was — the handler only ever read the boxes that were ticked.":
        "Về lại PENDING. Rút lại một lượt duyệt là việc bạn có thể làm; bỏ tick một ô "
        "thì chưa bao giờ là vậy — handler chỉ từng đọc các ô đã được tick.",
    "Apply to All {n} {scope}, Not Just the Page": "Áp Dụng Cho Cả {n} Test {scope}, Không Chỉ Trang Này",
    "selected": "đã chọn", "Reject": "Từ Chối", "Reset": "Đặt Lại",
    "{n} Test(s)": "{n} Test",
    "Target Environment": "Môi Trường Mục Tiêu",
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
    "Adaptive Follow-up": "Thử Tiếp Theo Thích Ứng",
    "no environment configured": "chưa cấu hình môi trường",
    "no approved tests": "chưa có test nào được duyệt",
    "Blocked:": "Bị chặn:", "Add an Environment": "Thêm Môi Trường",
    "Runs the {n} approved, non-destructive test(s) after scope validation.":
        "Chạy {n} test không phá huỷ đã duyệt, sau khi qua kiểm tra phạm vi.",
    "Run {n} destructive test(s) too": "Chạy Luôn {n} Test Phá Huỷ",
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
    "Running destructive tests...": "Đang chạy test phá huỷ...",
    "Re-run Approved Tests": "Chạy Lại Test Đã Duyệt", "Run Approved Tests": "Chạy Test Đã Duyệt",
    "Running tests…": "Đang Chạy Test…",
    "{n} Execution(s)": "{n} Lượt Chạy", "ready": "sẵn sàng", "blocked": "bị chặn",
    "Execute": "Chạy",
    "Only APPROVED, non-destructive tests are sent, and only after every "
    "request passes scope validation.":
        "Chỉ các test không phá huỷ đã DUYỆT mới được gửi, và chỉ sau khi mọi request "
        "qua kiểm tra phạm vi.",
})
