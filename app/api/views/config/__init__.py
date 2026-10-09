"""The engagement configuration screens.

One module per pane, in the order a new engagement needs them. `shared` holds
the readiness vocabulary and the tab names they all refer to.
"""

from __future__ import annotations

from app.core.i18n import VI, tt as _t

from ..shell import _e, appbar, page

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

from .advanced import _advanced_pane
from .identities import _personas_pane
from .readiness import _readiness_pane
from .shared import _CONFIG_TABS, _READY_CLASS, resolve_config_tab
from .target import _target_pane

def config_page(
    readiness,
    engagement,
    engagement_path: str,
    limits,
    runtime: list[tuple[str, str, str]],
    ai_evidence: dict[str, object],
    jira_mode: str,
    jira_live: bool,
    jira_warning: str,
    jira_env: list[tuple[str, str, str]],
    jira_keys: list[str],
    tab: str = "readiness",
    flash: str = "",
    error: str = "",
) -> str:
    requested_tab = tab
    tab = resolve_config_tab(tab)
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
    error_html = f"<div class='card pad err'>&#9888; {_e(_t(error))}</div>" if error else ""

    personas = list(engagement.raw.get("personas") or [])
    panes = {
        "readiness": _readiness_pane(
            readiness, engagement_path,
            show_wizard=not engagement.environments or len(personas) < 2,
        ),
        "target": _target_pane(engagement),
        "identities": _personas_pane(personas, engagement.attacker, engagement.victim),
        "advanced": _advanced_pane(
            limits, engagement.runner, ai_evidence,
            jira_mode, jira_live, jira_warning, jira_env, jira_keys, runtime,
            open_section=requested_tab,
        ),
    }

    state_cls = _READY_CLASS[readiness.state]
    if readiness.n_blocking:
        counts = _t("{n} Blocking").format(n=readiness.n_blocking)
    elif readiness.n_warnings:
        counts = _t("{n} To Check").format(n=readiness.n_warnings)
    else:
        counts = _t("All Checks Pass")

    bodies = "".join(
        f"<div class='tabpane {'active' if key == tab else ''}' id='cfg-{key}'>{panes[key]}</div>"
        for key, _label in _CONFIG_TABS
    )

    # The sidebar is the nav for these panes, so there is no second tab bar
    # here: the app bar names the open pane (in the sidebar's own words) and
    # carries the one thing the sidebar cannot fit, the readiness verdict.
    title = _t(dict(_CONFIG_TABS)[tab])
    bar = appbar(title, actions=(
        f'<span class="chip">{_t("Status")} '
        f'<b class="pill {state_cls}" style="margin-left:6px">{_e(counts)}</b></span>'
    ))

    return page(title, f"""
{flash_html}{error_html}
<div>{bodies}</div>
<script>
(function () {{
  document.querySelectorAll('.confirm-delete').forEach(function (f) {{
    f.addEventListener('submit', function (e) {{
      stpConfirmSubmit(f, e, 'Delete ' + f.dataset.what + '? This rewrites the engagement config.',
                       {{ danger: true }});
    }});
  }});
}})();
</script>
""", active=tab, appbar_html=bar)


VI.update({
    # -- shared chrome (topbar, present on every page) --
    "API Security Testing Platform": "Nền Tảng Kiểm Thử Bảo Mật API",
    "Dashboard": "Trang Chủ",
    "Configuration": "Cấu Hình",
    "Log in": "Đăng Nhập",
    "Shutting down…": "Đang Tắt…",
    # -- dashboard --
    "Assessments": "Assessment", "Imported": "Đã Nhập", "Designed": "Đã Lên Kế Hoạch",
    "Executed": "Đã Chạy",
    "Analyzed, no plan generated yet.": "Đã phân tích, chưa có kế hoạch.",
    "A plan exists; it may not be approved.": "Đã có kế hoạch; có thể chưa được duyệt.",
    "At least one run has happened.": "Đã có ít nhất một lượt chạy.",
    "No assessments match this filter.": "Không có assessment nào khớp bộ lọc này.",
    "No assessments yet — import a Jira issue above.":
        "Chưa có assessment nào — nhập một issue Jira ở trên.",
    "not configured — execution disabled": "chưa cấu hình — không thể chạy test",
    "AI (Claude)": "AI (Claude)",
    "Analyzer": "Bộ Phân Tích", "Target": "Mục Tiêu",
    "Import a Jira Issue": "Nhập Một Issue Jira",
    "Depth": "Độ Sâu", "Standard": "Tiêu Chuẩn", "Aggressive": "Nâng Cao",
    "Analyze the ticket and its embedded PoC, design a plan, let the AI planner add "
    "depth, then have a reviewing agent audit the plan against the ticket's requirements "
    "and send its gaps back for one revision round. You land on the plan with something "
    "to approve. Nothing runs: every test arrives PENDING. Uncheck to analyze only — "
    "which is what you want when the endpoint list needs correcting first.":
        "Phân tích ticket và PoC đính kèm, lên kế hoạch, để AI planner bổ sung chiều sâu, "
        "sau đó một agent đánh giá kế hoạch so với yêu cầu của ticket và gửi lại các lỗ "
        "hổng cho một vòng chỉnh sửa. Bạn sẽ đến thẳng trang kế hoạch để duyệt. Không có "
        "gì được chạy: mọi test đều ở trạng thái PENDING. Bỏ chọn để chỉ phân tích — dùng "
        "khi cần sửa lại danh sách endpoint trước.",
    "Plan &amp; review on import": "Lên Kế Hoạch &Amp; Đánh Giá Khi Nhập",
    "Import": "Nhập", "Recent Assessments": "Assessment Gần Đây",
    "Working…": "Đang Xử Lý…", "Running…": "Đang Chạy…",
    "Delete this assessment? This cannot be undone.":
        "Xoá assessment này? Không thể hoàn tác.",
    # -- dashboard search + filter bar --
    "Newest First": "Mới Nhất Trước",
    "Oldest First": "Cũ Nhất Trước", "Issue Key": "Issue Key",
    "Most Findings": "Nhiều Phát Hiện Nhất",
    "Search Issue Key or Assessment Id": "Tìm Theo Issue Key Hoặc Mã Assessment",
    "Search issue key or assessment id — e.g. BH-142":
        "Tìm Theo Issue Key Hoặc Mã Assessment — Ví Dụ BH-142",
    "Status": "Trạng Thái", "Sort": "Sắp Xếp", "Show": "Hiển Thị",
    "Search": "Tìm Kiếm", "Clear": "Xoá Bộ Lọc",
    "Clear Filters": "Xoá Bộ Lọc", "Clear Search": "Xoá Từ Khoá",
    "{n} of {total}": "{n} Trên {total}", "{n} assessments": "{n} Assessment",
    "page {n}": "trang {n}",
    # -- sidebar --
    "New Assessment": "Assessment Mới", "Deterministic": "Tất Định", "Available:": "Có sẵn:",
    "Any issue key your Jira account can read.":
        "Bất kỳ issue key nào tài khoản Jira của bạn đọc được.",
    "On Import": "Khi Nhập", "Analyze Only": "Chỉ Phân Tích", "Auto-Plan (AI)": "Tự Lập Kế Hoạch (AI)",
    "Ticket PoC Only": "Chỉ PoC Của Ticket",
    "Analyze Only: map endpoints. Auto-Plan: rules + AI planner + review. "
    "Ticket PoC Only: just the ticket's script. Nothing runs on import.":
        "Chỉ Phân Tích: liệt kê endpoint. Tự Lập Kế Hoạch: rule + AI planner + đánh giá. "
        "Chỉ PoC Của Ticket: chỉ script trong ticket. Không có gì chạy khi nhập.",
    "Re-import {issue} from Jira as a new assessment? Nothing runs.":
        "Nhập lại {issue} từ Jira thành assessment mới? Không chạy gì.",
    "Re-run {issue}? Runs the approved non-destructive tests as a new assessment.":
        "Chạy lại {issue}? Chạy các test không phá huỷ đã duyệt thành assessment mới.",
    "Open": "Mở", "Open Report": "Mở Báo Cáo", "Re-Run Plan": "Chạy Lại Kế Hoạch",
    "Re-Import From Jira": "Nhập Lại Từ Jira", "Select {name}": "Chọn {name}",
    "Selected": "Đã Chọn", "Select All on Page": "Chọn Tất Cả Trên Trang",
    "Select": "Chọn", "Selection": "Mục Đã Chọn", "Clear Selection": "Bỏ Chọn",
    "Delete Selected": "Xoá Mục Đã Chọn",
    "Delete {n} assessment(s)? This cannot be undone.":
        "Xoá {n} assessment? Không thể hoàn tác.",
    "Findings by Severity": "Phát Hiện Theo Mức Độ",
    "Recent Assessments With Findings": "Assessment Gần Đây Có Phát Hiện",
    "Show as Table": "Xem Dạng Bảng", "No confirmed findings yet.": "Chưa có phát hiện nào được xác nhận.",
    "Test Outcomes per Run": "Kết Quả Test Mỗi Lượt Chạy",
    "Latest Executed Assessments": "Assessment Đã Chạy Gần Nhất",
    "Nothing has run yet.": "Chưa có gì được chạy.", "Fail": "Lỗi", "Pass": "Đạt",
    "Blocked / Error": "Bị Chặn / Lỗi",
    "Search Options": "Tìm Lựa Chọn", "No Matches": "Không Có Kết Quả",
    "Confirm": "Xác Nhận", "Actions for {name}": "Thao Tác Cho {name}", "Attacker": "Kẻ Tấn Công", "Victim": "Nạn Nhân", "Default": "Mặc Định",
    "Jira Offline": "Jira Ngoại Tuyến", "Offline": "Ngoại Tuyến",
    "Collapse Sidebar": "Thu Gọn Thanh Bên", "Expand Sidebar": "Mở Rộng Thanh Bên",
    "Workspace": "Không Gian Làm Việc", "Engagement": "Engagement", "System": "Hệ Thống",
    "Scope & Targets": "Phạm Vi & Mục Tiêu", "Audit Log": "Nhật Ký Kiểm Toán",
    "Settings": "Cài Đặt", "Log In": "Đăng Nhập", "Log Out": "Đăng Xuất",
    "Shut Down Server": "Tắt Server", "Server Stopped": "Server Đã Dừng",
    "Start it again from a terminal.": "Khởi động lại từ terminal.",
    "Shut down the server?\n\nStops this app and every process started from this "
    "project, in any terminal.":
        "Tắt server?\n\nDừng app này và mọi tiến trình của dự án, ở mọi terminal.",
    # -- assessment card --
    "{n} Test(s)": "{n} Test", "{n} Approved": "{n} Đã Duyệt", "{n} Run": "{n} Lượt Chạy",
    "Re-run": "Chạy Lại", "Re-import": "Nhập Lại", "Delete": "Xoá",
    # -- login / error pages --
    "API Key": "API Key",
    "Multi-user auth is enabled. Paste the API key printed by "
    "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> to authenticate "
    "this browser for actions like designing tests, approving, and executing. Reads "
    "stay open either way.":
        "Xác thực đa người dùng đang bật. Dán API key được in ra bởi "
        "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> để xác thực "
        "trình duyệt này cho các thao tác như thiết kế test, duyệt và chạy test. Xem dữ "
        "liệu vẫn luôn mở dù có xác thực hay không.",
    "← Back to dashboard": "← Về Trang Chủ",
    "← Back to Assessment": "← Về Assessment",
    "← Back to the new assessment": "← Về Assessment Mới",
    # -- main.py flash messages (static ones only — dynamic ones with names/counts
    # baked into the string are left in English, since a template-less lookup
    # cannot translate a value it has already been substituted into) --
    "Invalid API key": "API Key Không Hợp Lệ", "Logged out": "Đã Đăng Xuất",
    "Deleted assessment": "Đã Xoá Assessment", "Assessment not found": "Không Tìm Thấy Assessment",
    "Test plan generated": "Đã Tạo Kế Hoạch Test", "Unknown action": "Hành Động Không Xác Định",
    "No tests selected": "Chưa Chọn Test Nào",
    "Execution disabled: no engagement configured": "Không Thể Chạy: Chưa Cấu Hình Engagement",
    "Scope saved": "Đã Lưu Phạm Vi",
    "Saved — approval reset to PENDING": "Đã Lưu — Duyệt Được Đặt Lại Về PENDING",
    "Posted to Jira": "Đã Đăng Lên Jira",
    # -- main.py error_page titles --
    "Invalid environment name": "Tên Môi Trường Không Hợp Lệ", "Invalid URL": "URL Không Hợp Lệ",
    "Import failed": "Nhập Thất Bại", "Re-analysis failed": "Phân Tích Lại Thất Bại",
    "Planning agent failed": "Agent Lên Kế Hoạch Thất Bại",
    "Result review failed": "Đánh Giá Kết Quả Thất Bại",
    "Execution failed": "Chạy Test Thất Bại", "Re-import failed": "Nhập Lại Thất Bại",
    "Re-run failed": "Chạy Lại Thất Bại", "Posting to Jira failed": "Đăng Lên Jira Thất Bại",
    # -- config page shell --
    "Everything a run depends on, in one place.": "Mọi thứ một lượt chạy cần, ở một nơi.",
    "{n} Blocking": "{n} Chặn", "{n} To Check": "{n} Cần Kiểm Tra",
    "All Checks Pass": "Mọi Kiểm Tra Đều Đạt",
    # -- readiness pane --
    "No environments to check.": "Không có môi trường nào để kiểm tra.",
    "Ready to run.": "Sẵn sàng chạy.",
    "Nothing in this configuration will stop a request from being sent.":
        "Không có gì trong cấu hình này ngăn request được gửi đi.",
    "{n} blocking issue(s).": "{n} vấn đề chặn.",
    "A run started now comes back entirely BLOCKED or ERROR. Each row below names the "
    "setting and the pane that fixes it.":
        "Nếu chạy ngay bây giờ, kết quả sẽ toàn BỊ CHẶN hoặc LỖI. Mỗi dòng dưới đây nêu "
        "rõ cấu hình và tab cần sửa.",
    "State": "Trạng Thái", "Check": "Kiểm Tra",
    "Scope Verdict per Environment": "Kết Luận Phạm Vi Theo Từng Môi Trường",
    "Each base URL run through the same <code>ScopeValidator</code> the runner calls, DNS "
    "lookup included. Whatever this table says here is exactly what the execution log will say.":
        "Mỗi base URL được chạy qua đúng <code>ScopeValidator</code> mà runner gọi, kể cả "
        "tra cứu DNS. Bảng này nói gì thì nhật ký thực thi cũng sẽ nói y hệt vậy.",
    "Environment": "Môi Trường", "Base URL": "Base URL", "Verdict": "Kết Luận",
    "Reason": "Lý Do", "Config file:": "File cấu hình:",
    "default": "mặc định", "ALLOWED": "CHO PHÉP", "BLOCKED": "BỊ CHẶN",
    # -- environments pane --
    "No environments configured yet.": "Chưa cấu hình môi trường nào.",
    "Named target URLs. Only the path/method/body of a pasted PoC survive transpiling, "
    "so whichever base URL is picked here is what actually gets called.":
        "Các URL mục tiêu có tên. Chỉ path/method/body của PoC dán vào còn giữ lại sau "
        "khi transpile, nên base URL chọn ở đây chính là URL thật sự được gọi.",
    "Name": "Tên",
    "Make Default": "Đặt Làm Mặc Định", "Authorize Its Host": "Cấp Phép Host Này",
    "Save": "Lưu",
    "<b>Authorize its host</b> adds the hostname to <b>Scope &rarr; approved hosts</b> "
    "in the same step. Leave it off for a target the engagement does not actually cover "
    "— the URL is then saved but every request to it stays blocked, which is the safe "
    "direction to fail in.":
        "<b>Cấp phép host này</b> sẽ thêm hostname vào <b>Scope &rarr; approved hosts</b> "
        "cùng lúc. Bỏ chọn nếu mục tiêu không thực sự nằm trong phạm vi engagement — URL "
        "vẫn được lưu nhưng mọi request đến đó vẫn bị chặn, đây là hướng an toàn khi lỗi.",
    # -- scope pane --
    "The authorization boundary. Every outbound request is checked against this "
    "before it is sent, and the hostname must appear in <b>approved hosts</b> exactly "
    "— there are no wildcards, because a wildcard in a pentest authorization list is "
    "how an unauthorized host gets tested by accident.":
        "Ranh giới cấp phép. Mọi request gửi đi đều được kiểm tra với danh sách này trước "
        "khi gửi, và hostname phải khớp chính xác trong <b>approved hosts</b> — không có "
        "wildcard, vì wildcard trong danh sách cấp phép pentest chính là cách một host "
        "không được phép bị test nhầm.",
    "Approved Hosts — One per Line": "Host Được Cấp Phép — Mỗi Dòng Một Host",
    "Blocked hosts — one per line (always wins)": "Host Bị Chặn — Mỗi Dòng Một Host (Luôn Ưu Tiên)",
    "Allow Private / Loopback Ranges": "Cho Phép Dải IP Nội Bộ / Loopback",
    "Off by default. When off, a host that <i>resolves</i> to 127.0.0.0/8, 10/8, "
    "172.16/12, 192.168/16 or 169.254/16 (cloud metadata) is refused even if its name "
    "is on the approved list — that check is what stops a DNS-based SSRF from reaching "
    "an internal service. Turn it on only for a local lab target.":
        "Mặc định tắt. Khi tắt, một host mà DNS <i>trả về</i> 127.0.0.0/8, 10/8, "
        "172.16/12, 192.168/16 hoặc 169.254/16 (cloud metadata) sẽ bị từ chối dù tên nó "
        "có trong danh sách cấp phép — kiểm tra này ngăn SSRF qua DNS chạm tới dịch vụ "
        "nội bộ. Chỉ bật khi mục tiêu là lab nội bộ.",
    "Save Scope": "Lưu Phạm Vi",
    "Hostnames only — no scheme, no port, no path. A port is not part of the check "
    "(<code>api.example.com:8443</code> is authorized by <code>api.example.com</code>), "
    "and DNS is resolved and the resulting IP re-checked on every request, so a name "
    "that resolves somewhere new is caught at send time.":
        "Chỉ hostname — không scheme, không port, không path. Port không nằm trong kiểm "
        "tra (<code>api.example.com:8443</code> được cấp phép bởi <code>api.example.com</code>), "
        "và DNS được resolve rồi IP kết quả được kiểm tra lại mỗi request, nên một tên miền "
        "trỏ đến nơi mới sẽ bị phát hiện ngay lúc gửi.",
    # -- personas pane --
    "attacker": "kẻ tấn công", "victim": "nạn nhân",
    "Role Label": "Nhãn Vai Trò",
    "Owned Object Ids — Key=Value per Line": "ID Object Sở Hữu — Mỗi Dòng Key=Value",
    "Auth Headers — Header: Value per Line": "Auth Headers — Mỗi Dòng Header: Value",
    "Secret Markers — One per Line": "Dấu Hiệu Bí Mật — Mỗi Dòng Một Dấu Hiệu",
    "Scoping Headers to Strip on Privilege-Escalation Tests — One per Line": "Header Scoping Cần Loại Bỏ Khi Test Leo Thang Đặc Quyền — Mỗi Dòng Một Header",
    "Save {name}": "Lưu {name}",
    "No personas defined yet — add one below.": "Chưa có persona nào — thêm một cái bên dưới.",
    "not defined!": "chưa định nghĩa!", "no personas defined": "chưa có persona nào",
    'Test identities and their credentials. You cannot test broken object-level '
    'authorization with one identity: BOLA means "A reaches B\'s object", which needs '
    'two real accounts plus knowledge of what each legitimately owns. Tests reference '
    'personas <i>by name</i>, so a token never lands in a test case, an export or a report.':
        'Danh tính test và thông tin xác thực của chúng. Không thể test broken '
        'object-level authorization với một danh tính duy nhất: BOLA nghĩa là "A chạm '
        'được object của B", cần hai tài khoản thật cộng với biết rõ mỗi bên sở hữu gì. '
        'Test tham chiếu persona <i>bằng tên</i>, nên token không bao giờ xuất hiện trong '
        'test case, file export hay báo cáo.',
    "Attacker Persona": "Persona Kẻ Tấn Công", "Victim Persona": "Persona Nạn Nhân",
    "Save Roles": "Lưu Vai Trò",
    "The attacker sends the requests; generated BOLA cases aim it at ids the victim "
    "owns. Point these at two <i>different</i> personas or the results are "
    "inconclusive by construction.":
        "Kẻ tấn công là bên gửi request; các case BOLA được tạo sẽ nhắm vào id mà nạn "
        "nhân sở hữu. Chọn hai persona <i>khác nhau</i>, nếu không kết quả sẽ luôn chưa "
        "rõ ràng do bản chất thiết kế.",
    "Defined Personas": "Persona Đã Định Nghĩa", "Add a Persona": "Thêm Persona",
    "Add Persona": "Thêm Persona",
    "Use dedicated test accounts. Credentials are written to the engagement config in "
    "plain text and every response is passed through secret redaction before it reaches "
    "a report — but a real user's token does not belong in either.":
        "Dùng tài khoản test riêng. Thông tin xác thực được ghi vào config engagement ở "
        "dạng plain text, và mọi phản hồi đều qua bước che bí mật trước khi vào báo cáo "
        "— nhưng token của một người dùng thật không nên xuất hiện ở cả hai nơi đó.",
    # -- runner pane --
    'Hard caps the trusted runner applies to every outbound request. Blank means '
    '"use the <code>.env</code> value" shown as the placeholder; a value here '
    'overrides it for this engagement only, with no restart.':
        'Giới hạn cứng mà trusted runner áp dụng cho mọi request gửi đi. Để trống nghĩa '
        'là "dùng giá trị <code>.env</code>" hiển thị làm placeholder; điền giá trị ở '
        'đây sẽ ghi đè chỉ cho engagement này, không cần restart.',
    "Request Timeout (s)": "Timeout Request (Giây)",
    "Raise it for a slow staging host.": "Tăng lên nếu host staging phản hồi chậm.",
    "Max Requests per Test": "Số Request Tối Đa Mỗi Test",
    "Caps a single test's fan-out, race windows included.":
        "Giới hạn số request một test có thể gửi, kể cả trong race window.",
    "Max Response Bytes": "Số Byte Phản Hồi Tối Đa",
    "Body larger than this is truncated before storage.":
        "Body lớn hơn mức này sẽ bị cắt bớt trước khi lưu.",
    "Save Limits": "Lưu Giới Hạn", "Reset to .env Defaults": "Khôi Phục Mặc Định .env",
    "The runner never auto-follows a redirect: a 302 to an internal host is the same "
    "SSRF wearing a hat, and blindly chasing it would let the HTTP client re-resolve DNS "
    "outside the scope gate. A 3xx response is captured and evaluated exactly as received "
    "— there is no redirect setting to tune here.":
        "Runner không bao giờ tự động theo redirect: một 302 trỏ vào host nội bộ cũng "
        "chính là SSRF đội lốt, và đi theo nó một cách mù quáng sẽ để HTTP client "
        "resolve DNS lại ngoài tầm kiểm soát của scope gate. Response 3xx được ghi nhận "
        "và đánh giá đúng như nhận được — không có tuỳ chọn redirect nào để chỉnh ở đây.",
    # -- mcp pane --
    "LIVE": "TRỰC TIẾP", "MOCK": "GIẢ LẬP", "Serves:": "Phục vụ:",
    "SET": "ĐÃ ĐẶT", "NOT SET": "CHƯA ĐẶT",
    "External MCP connectors this platform talks to. Credentials live in <code>.env</code> "
    "only — never in <code>engagement.json</code> or a report. <b>Reconnect</b> re-reads "
    "<code>.env</code> and rebinds the client in place, which is all a restart would have "
    "done anyway — useful right after refreshing a short-lived OAuth token.":
        "Các kết nối MCP bên ngoài mà nền tảng này giao tiếp. Thông tin xác thực chỉ nằm "
        "trong <code>.env</code> — không bao giờ trong <code>engagement.json</code> hay "
        "báo cáo. <b>Reconnect</b> đọc lại <code>.env</code> và gắn lại client tại chỗ, "
        "đúng bằng những gì một lần restart sẽ làm — hữu ích ngay sau khi làm mới token "
        "OAuth ngắn hạn.",
    "Reconnect": "Kết Nối Lại",
    "Environment Variable": "Biến Môi Trường", "Purpose": "Mục Đích",
    "To refresh an expired token: authorize once with "
    "<code>npx -y mcp-remote https://mcp.atlassian.com/v1/mcp</code> (opens the Atlassian "
    "OAuth login in your browser — only needed again once the refresh token itself is "
    "revoked or expires), then run <code>npm run jira:token</code> to pull the new token "
    "into <code>.env</code>, then click <b>Reconnect</b> above.":
        "Để làm mới token đã hết hạn: cấp phép một lần với "
        "<code>npx -y mcp-remote https://mcp.atlassian.com/v1/mcp</code> (mở màn hình đăng "
        "nhập OAuth của Atlassian trên trình duyệt — chỉ cần lặp lại khi refresh token bị "
        "thu hồi hoặc hết hạn), sau đó chạy <code>npm run jira:token</code> để lấy token "
        "mới vào <code>.env</code>, rồi bấm <b>Kết nối lại</b> ở trên.",
    "Other Connectors": "Kết Nối Khác", "NOT CONFIGURED": "CHƯA CẤU HÌNH",
    "No MCP integration is wired up for this platform — there is nothing here yet to "
    "connect or reconnect. (Separately, a completed assessment can already export a "
    "Postman collection from its report page — a one-way file export, unrelated to this "
    "connector list.)":
        "Chưa có tích hợp MCP nào cho nền tảng này — chưa có gì để kết nối hay kết nối "
        "lại ở đây. (Tách biệt với việc này, một assessment đã hoàn tất có thể export "
        "bộ sưu tập Postman từ trang report — một file export một chiều, không liên quan "
        "đến danh sách kết nối này.)",
    # -- runtime pane --
    "Read-only. These come from the process environment (<code>.env</code>), are read "
    "at startup, and need a server restart to change — so they are shown here rather "
    "than made editable, which would offer a save button that quietly does nothing "
    "until the next boot.":
        "Chỉ đọc. Các giá trị này đến từ biến môi trường tiến trình (<code>.env</code>), "
        "được đọc lúc khởi động, và cần restart server để thay đổi — nên chỉ hiển thị ở "
        "đây thay vì cho sửa, vì nút lưu sẽ âm thầm không có tác dụng gì cho tới lần "
        "khởi động sau.",
    "Setting": "Cấu Hình", "Current": "Giá Trị Hiện Tại",
    "Secrets are never echoed here — only whether one is present. Keep tokens in "
    "<code>.env</code>, never in <code>engagement.json</code>.":
        "Bí mật không bao giờ hiển thị ở đây — chỉ báo có tồn tại hay không. Giữ token "
        "trong <code>.env</code>, không bao giờ trong <code>engagement.json</code>.",
    # -- AI & Evidence pane ---------------------------------------------------
    # Previously the one pane that rendered in raw English whatever the language.
    "Written to <code>.env</code> and applied immediately, with no restart. Needs the "
    "<b>admin</b> role when authentication is on.":
        "Ghi vào <code>.env</code> và áp dụng ngay, không cần restart. Cần vai trò "
        "<b>admin</b> khi bật xác thực.",
    # "Analyzer" and "Save" are already mapped above — same words, same meaning.
    "Evidence Keys": "Khoá Bằng Chứng", "Optional Integration": "Tích Hợp Tuỳ Chọn",
    "ON": "BẬT", "OFF": "TẮT", "ACTIVE": "ĐANG DÙNG",
    "CLI NOT FOUND": "KHÔNG TÌM THẤY CLI",
    "CONFIGURED": "ĐÃ CẤU HÌNH", "NOT SET UP": "CHƯA THIẾT LẬP",
    "Use Claude": "Dùng Claude", "CLI": "CLI", "model": "model",
    "Runs through your own Claude Code login — no separate API key, no separate bill.":
        "Chạy bằng chính đăng nhập Claude Code của bạn — không cần API key riêng, "
        "không tính phí riêng.",
    "The CLI is available. Analysis runs on the deterministic path until you turn "
    "this on.":
        "CLI đã sẵn sàng. Phân tích vẫn chạy theo hướng tất định cho tới khi bạn bật.",
    "Claude Code is not installed on this machine, or is not on PATH. Analysis "
    "runs on the deterministic path until it is.":
        "Máy này chưa cài Claude Code, hoặc nó không nằm trong PATH. Phân tích chạy theo "
        "hướng tất định cho tới khi có.",
    "the CLI default": "model mặc định của CLI",
    "Model": "Model", "empty — use the CLI's model": "để trống — dùng model của CLI",
    "Leave blank unless you need a specific one. An alias, or a full versioned id.":
        "Để trống trừ khi bạn cần một model cụ thể. Có thể là alias hoặc id đầy đủ "
        "có version.",
    "Effort": "Mức Suy Luận", "CLI Default": "Mặc Định Của CLI",
    "How much reasoning each call is allowed. Higher costs more and takes longer.":
        "Cho phép mỗi lần gọi suy luận tới đâu. Cao hơn thì tốn hơn và lâu hơn.",
    "Spend Cap per Call (USD)": "Trần Chi Phí Mỗi Lần Gọi (USD)",
    "no cap": "không giới hạn",
    "A hard stop, not a target. Blank lets the CLI decide.":
        "Đây là mức chặn cứng, không phải mục tiêu. Để trống thì CLI tự quyết.",
    "Compliance Option": "Tuỳ Chọn Tuân Thủ",
    "Refuse to Run Unless the Model Above Is a Full Versioned Id": "Không Chạy Nếu Model Ở Trên Không Phải Id Đầy Đủ Có Version",
    "For deployments that must be able to say which exact model produced a report. An "
    "alias like <code>sonnet</code> moves between releases, so it is rejected here — with "
    "this on, a blank model field stops the AI path entirely.":
        "Dành cho triển khai cần nói được chính xác model nào đã tạo ra báo cáo. Alias như "
        "<code>sonnet</code> thay đổi theo từng bản phát hành nên bị từ chối ở đây — bật "
        "tuỳ chọn này mà để trống ô model thì hướng AI dừng hẳn.",
    "Cross-identity Correlation": "Đối Chiếu Chéo Danh Tính",
    "HMACs identity values so a BOLA finding can show the attacker saw the victim's own "
    "data. Without it that comparison is skipped and those verdicts come back "
    "INCONCLUSIVE.":
        "Băm HMAC các giá trị định danh để một phát hiện BOLA chứng minh được kẻ tấn công "
        "đã thấy đúng dữ liệu của nạn nhân. Không có nó thì phép so sánh bị bỏ qua và các "
        "kết luận đó trả về INCONCLUSIVE.",
    "Report Manifest Signing": "Ký Manifest Báo Cáo",
    "Signs each report manifest, so it can be shown not to have been edited after "
    "the run. Without it manifests are still written, just unsigned.":
        "Ký từng manifest báo cáo để chứng minh nó không bị sửa sau khi chạy. Không có nó "
        "manifest vẫn được ghi, chỉ là không có chữ ký.",
    "Generate the Missing Keys": "Tạo Các Khoá Còn Thiếu",
    "Generated in your browser, stored when you save.":
        "Sinh ngay trên trình duyệt của bạn, chỉ lưu lại khi bạn bấm Lưu.",
    "Nothing to do here.": "Không còn gì phải làm ở đây.",
    "Enter Keys by Hand": "Nhập Khoá Thủ Công",
    "For restoring a key from a secret manager, or rotating one. Stored values are never "
    "sent back to the browser: blank keeps the current key, and removing one takes the "
    "explicit checkbox.":
        "Dùng khi khôi phục khoá từ secret manager, hoặc khi xoay khoá. Giá trị đã lưu "
        "không bao giờ được gửi lại về trình duyệt: để trống là giữ nguyên khoá hiện tại, "
        "và muốn xoá thì phải tick ô xác nhận.",
    "stored — blank keeps it": "đã lưu — để trống là giữ nguyên", "not set": "chưa đặt",
    "Clear the Stored Value": "Xoá Giá Trị Đã Lưu",
    "Signing Key Id": "Mã Khoá Ký",
    "A label recorded in the manifest, so a verifier knows which key to reach for.":
        "Một nhãn được ghi vào manifest để bên kiểm chứng biết cần dùng khoá nào.",
    "Out-of-band Collaborator": "Collaborator Ngoài Luồng",
    "Blind and out-of-band tests can be confirmed.":
        "Các test blind và ngoài luồng có thể được xác nhận.",
    "Blind SSRF and other out-of-band tests report INCONCLUSIVE — there is nowhere "
    "for the target's callback to land.":
        "Blind SSRF và các test ngoài luồng khác sẽ trả về INCONCLUSIVE — callback từ mục "
        "tiêu không có chỗ nào để đáp xuống.",
    "Public Callback Base URL": "URL Gốc Nhận Callback Công Khai",
    "Authenticated Polling Base URL": "URL Gốc Để Poll Có Xác Thực",
    "Polling API Token": "Token API Để Poll",
    "Polling Timeout (s)": "Timeout Poll (Giây)",
    "Both URLs must be HTTPS and are set together. The token is sent only to the polling "
    "endpoint — never into the callback URL handed to the target.":
        "Cả hai URL phải là HTTPS và được đặt cùng lúc. Token chỉ gửi tới endpoint poll — "
        "không bao giờ nhét vào URL callback đưa cho mục tiêu.",
    # -- gaps this tab already had -------------------------------------------
    "Tests in Flight at Once": "Số Test Chạy Song Song",
    "1 runs a plan one test at a time. Higher finishes a long plan faster, at "
    "proportionally higher request rate against the target — a blast-radius decision, "
    "so it is not raised for you.":
        "Để 1 thì kế hoạch chạy tuần tự từng test. Cao hơn thì xong nhanh hơn, đổi lại "
        "tần suất request lên mục tiêu tăng tương ứng — đây là quyết định về mức độ ảnh "
        "hưởng, nên hệ thống không tự nâng giúp bạn.",
    "Refresh Token": "Làm Mới Token",
    # -- readiness: the relocated session-cookie check ------------------------
    "Login Session Cookie": "Cookie Phiên Đăng Nhập",
    "Mark the Cookie Secure": "Đánh Dấu Cookie Là Secure",
})
