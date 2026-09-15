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
        counts = _t("{n} blocking").format(n=readiness.n_blocking)
    elif readiness.n_warnings:
        counts = _t("{n} to check").format(n=readiness.n_warnings)
    else:
        counts = _t("all checks pass")

    buttons = "".join(
        f"<button class='{'active' if key == tab else ''}' data-tab='cfg-{key}'>{_t(label)}"
        + (f" <span class='pill {state_cls}' style='margin-left:6px'>{readiness.n_blocking or ''}</span>"
           if key == "readiness" and readiness.n_blocking else "")
        + "</button>"
        for key, label in _CONFIG_TABS
    )
    bodies = "".join(
        f"<div class='tabpane {'active' if key == tab else ''}' id='cfg-{key}'>{panes[key]}</div>"
        for key, _label in _CONFIG_TABS
    )

    # The sidebar already names the section; the app bar carries the one thing
    # it cannot fit — the readiness verdict — and the standfirst is gone. It
    # said "Everything a run depends on, in one place", which the page itself
    # demonstrates.
    bar = appbar(_t("Configuration"), actions=(
        f'<span class="chip">{_t("Status")} '
        f'<b class="pill {state_cls}" style="margin-left:6px">{_e(counts)}</b></span>'
    ))

    return page(_t("Configuration"), f"""
{flash_html}{error_html}
<div class="tabbar" id="config-tabs">{buttons}</div>
<div style="padding-top:16px">{bodies}</div>
<script>
(function () {{
  var bar = document.getElementById('config-tabs');
  function show(id) {{
    bar.querySelectorAll('button').forEach(function (b) {{
      b.classList.toggle('active', b.dataset.tab === id);
    }});
    document.querySelectorAll('.tabpane').forEach(function (p) {{
      p.classList.toggle('active', p.id === id);
    }});
  }}
  bar.querySelectorAll('button').forEach(function (b) {{
    b.addEventListener('click', function () {{
      show(b.dataset.tab);
      // Keep the open pane in the URL so a save (which round-trips through a
      // redirect) comes back to the pane the tester was working in.
      history.replaceState(null, '', '/config?tab=' + b.dataset.tab.slice(4));
    }});
  }});
  document.querySelectorAll('.confirm-delete').forEach(function (f) {{
    f.addEventListener('submit', function (e) {{
      if (!confirm('Delete ' + f.dataset.what + '? This rewrites the engagement config.')) {{
        e.preventDefault();
      }}
    }});
  }});
}})();
</script>
""", active=tab, appbar_html=bar, narrow=True)


VI.update({
    # -- shared chrome (topbar, present on every page) --
    "API Security Testing Platform": "Nền tảng kiểm thử bảo mật API",
    "Dashboard": "Trang chủ",
    "Configuration": "Cấu hình",
    "Log in": "Đăng nhập",
    "Log out": "Đăng xuất",
    "Shutdown server": "Tắt server",
    "Shutting down…": "Đang tắt…",
    "Server is shutting down": "Server đang tắt",
    "All processes for this project have been stopped. Start it again from a "
    "terminal to continue.":
        "Mọi tiến trình của dự án này đã dừng. Khởi động lại từ terminal để tiếp tục.",
    "Shut down the server?\n\nThis stops this app AND any other process running "
    "from this project (the demo target, stray CLI/pytest runs) — including ones "
    "started in other terminals. You will need to start it again manually.":
        "Tắt server?\n\nThao tác này dừng app này VÀ mọi tiến trình khác của dự án "
        "(demo target, các lệnh CLI/pytest đang chạy lẻ) — kể cả những tiến trình "
        "khởi động từ terminal khác. Bạn sẽ phải tự khởi động lại.",
    # -- dashboard --
    "Assessments": "Assessment", "Imported": "Đã nhập", "Designed": "Đã lên kế hoạch",
    "Executed": "Đã chạy",
    "Analyzed, no plan generated yet.": "Đã phân tích, chưa có kế hoạch.",
    "A plan exists; it may not be approved.": "Đã có kế hoạch; có thể chưa được duyệt.",
    "At least one run has happened.": "Đã có ít nhất một lượt chạy.",
    "No assessments match this filter.": "Không có assessment nào khớp bộ lọc này.",
    "No assessments yet — import a Jira issue above.":
        "Chưa có assessment nào — nhập một issue Jira ở trên.",
    "not configured — execution disabled": "chưa cấu hình — không thể chạy test",
    "AI (Claude)": "AI (Claude)", "deterministic (heuristic)": "tất định (heuristic)",
    "importable now:": "có thể nhập ngay:",
    "enter any issue key your Jira account can read":
        "nhập bất kỳ issue key nào tài khoản Jira của bạn đọc được",
    "Analyzer": "Bộ phân tích", "Target": "Mục tiêu",
    "Import a Jira issue": "Nhập một issue Jira",
    "Depth": "Độ sâu", "Standard": "Tiêu chuẩn", "Aggressive": "Nâng cao",
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
    "Plan &amp; review on import": "Lên kế hoạch &amp; đánh giá khi nhập",
    "Import": "Nhập", "Recent assessments": "Assessment gần đây",
    "Working…": "Đang xử lý…", "Running…": "Đang chạy…",
    "Delete this assessment? This cannot be undone.":
        "Xoá assessment này? Không thể hoàn tác.",
    "Re-import {issue} from Jira?\n\nCreates a new assessment from the ticket as it "
    "reads now. No tests are generated and nothing runs.":
        "Nhập lại {issue} từ Jira?\n\nTạo một assessment mới từ nội dung ticket hiện tại. "
        "Không tạo test nào và không chạy gì cả.",
    "Re-run {issue}?\n\nCreates a new assessment with the same plan and approvals, "
    "then runs the approved non-destructive tests. Destructive tests are never "
    "included in a re-run. The previous run is kept as the baseline.":
        "Chạy lại {issue}?\n\nTạo một assessment mới với cùng kế hoạch và các duyệt hiện "
        "có, rồi chạy các test không phá huỷ đã duyệt. Test phá huỷ không bao giờ được "
        "đưa vào lượt chạy lại. Lượt chạy trước được giữ làm mốc so sánh.",
    # -- dashboard toolbar --
    "Any status": "Mọi trạng thái", "Newest first": "Mới nhất trước",
    "Oldest first": "Cũ nhất trước", "Issue key": "Issue key",
    "Most findings": "Nhiều phát hiện nhất",
    "Search issue key": "Tìm theo issue key",
    "Status": "Trạng thái", "Sort": "Sắp xếp", "Per page": "Mỗi trang",
    "Apply": "Áp dụng", "Clear": "Xoá bộ lọc",
    "{n} shown": "{n} đang hiển thị", " · page {n}": " · trang {n}",
    # -- assessment card --
    "{n} test(s)": "{n} test", "{n} approved": "{n} đã duyệt", "{n} run": "{n} lượt chạy",
    "Re-run": "Chạy lại", "Re-import": "Nhập lại", "Delete": "Xoá",
    # -- login / error pages --
    "API key": "API key",
    "Multi-user auth is enabled. Paste the API key printed by "
    "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> to authenticate "
    "this browser for actions like designing tests, approving, and executing. Reads "
    "stay open either way.":
        "Xác thực đa người dùng đang bật. Dán API key được in ra bởi "
        "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> để xác thực "
        "trình duyệt này cho các thao tác như thiết kế test, duyệt và chạy test. Xem dữ "
        "liệu vẫn luôn mở dù có xác thực hay không.",
    "← Back to dashboard": "← Về trang chủ",
    "← Back to assessment": "← Về assessment",
    "← Back to the new assessment": "← Về assessment mới",
    # -- main.py flash messages (static ones only — dynamic ones with names/counts
    # baked into the string are left in English, since a template-less lookup
    # cannot translate a value it has already been substituted into) --
    "Invalid API key": "API key không hợp lệ", "Logged out": "Đã đăng xuất",
    "Deleted assessment": "Đã xoá assessment", "Assessment not found": "Không tìm thấy assessment",
    "Test plan generated": "Đã tạo kế hoạch test", "Unknown action": "Hành động không xác định",
    "No tests selected": "Chưa chọn test nào",
    "Execution disabled: no engagement configured": "Không thể chạy: chưa cấu hình engagement",
    "Scope saved": "Đã lưu phạm vi",
    "Saved — approval reset to PENDING": "Đã lưu — duyệt được đặt lại về PENDING",
    "Posted to Jira": "Đã đăng lên Jira",
    # -- main.py error_page titles --
    "Invalid environment name": "Tên môi trường không hợp lệ", "Invalid URL": "URL không hợp lệ",
    "Import failed": "Nhập thất bại", "Re-analysis failed": "Phân tích lại thất bại",
    "Planning agent failed": "Agent lên kế hoạch thất bại",
    "Result review failed": "Đánh giá kết quả thất bại",
    "Execution failed": "Chạy test thất bại", "Re-import failed": "Nhập lại thất bại",
    "Re-run failed": "Chạy lại thất bại", "Posting to Jira failed": "Đăng lên Jira thất bại",
    # -- config page shell --
    "Everything a run depends on, in one place.": "Mọi thứ một lượt chạy cần, ở một nơi.",
    "{n} blocking": "{n} chặn", "{n} to check": "{n} cần kiểm tra",
    "all checks pass": "mọi kiểm tra đều đạt",
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
    "State": "Trạng thái", "Check": "Kiểm tra",
    "Scope verdict per environment": "Kết luận phạm vi theo từng môi trường",
    "Each base URL run through the same <code>ScopeValidator</code> the runner calls, DNS "
    "lookup included. Whatever this table says here is exactly what the execution log will say.":
        "Mỗi base URL được chạy qua đúng <code>ScopeValidator</code> mà runner gọi, kể cả "
        "tra cứu DNS. Bảng này nói gì thì nhật ký thực thi cũng sẽ nói y hệt vậy.",
    "Environment": "Môi trường", "Base URL": "Base URL", "Verdict": "Kết luận",
    "Reason": "Lý do", "Config file:": "File cấu hình:",
    "default": "mặc định", "ALLOWED": "CHO PHÉP", "BLOCKED": "BỊ CHẶN",
    # -- environments pane --
    "Make default": "Đặt làm mặc định",
    "No environments configured yet.": "Chưa cấu hình môi trường nào.",
    "Named target URLs. Only the path/method/body of a pasted PoC survive transpiling, "
    "so whichever base URL is picked here is what actually gets called.":
        "Các URL mục tiêu có tên. Chỉ path/method/body của PoC dán vào còn giữ lại sau "
        "khi transpile, nên base URL chọn ở đây chính là URL thật sự được gọi.",
    "Name": "Tên",
    "make default": "đặt làm mặc định", "authorize its host": "cấp phép host này",
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
    "Approved hosts — one per line": "Host được cấp phép — mỗi dòng một host",
    "Blocked hosts — one per line (always wins)": "Host bị chặn — mỗi dòng một host (luôn ưu tiên)",
    "Allow private / loopback ranges": "Cho phép dải IP nội bộ / loopback",
    "Off by default. When off, a host that <i>resolves</i> to 127.0.0.0/8, 10/8, "
    "172.16/12, 192.168/16 or 169.254/16 (cloud metadata) is refused even if its name "
    "is on the approved list — that check is what stops a DNS-based SSRF from reaching "
    "an internal service. Turn it on only for a local lab target.":
        "Mặc định tắt. Khi tắt, một host mà DNS <i>trả về</i> 127.0.0.0/8, 10/8, "
        "172.16/12, 192.168/16 hoặc 169.254/16 (cloud metadata) sẽ bị từ chối dù tên nó "
        "có trong danh sách cấp phép — kiểm tra này ngăn SSRF qua DNS chạm tới dịch vụ "
        "nội bộ. Chỉ bật khi mục tiêu là lab nội bộ.",
    "Save scope": "Lưu phạm vi",
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
    "Role label": "Nhãn vai trò",
    "Owned object ids — key=value per line": "ID object sở hữu — mỗi dòng key=value",
    "Auth headers — Header: value per line": "Auth headers — mỗi dòng Header: value",
    "Secret markers — one per line": "Dấu hiệu bí mật — mỗi dòng một dấu hiệu",
    "Scoping headers to strip on privilege-escalation tests — one per line":
        "Header scoping cần loại bỏ khi test leo thang đặc quyền — mỗi dòng một header",
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
    "Attacker persona": "Persona kẻ tấn công", "Victim persona": "Persona nạn nhân",
    "Save roles": "Lưu vai trò",
    "The attacker sends the requests; generated BOLA cases aim it at ids the victim "
    "owns. Point these at two <i>different</i> personas or the results are "
    "inconclusive by construction.":
        "Kẻ tấn công là bên gửi request; các case BOLA được tạo sẽ nhắm vào id mà nạn "
        "nhân sở hữu. Chọn hai persona <i>khác nhau</i>, nếu không kết quả sẽ luôn chưa "
        "rõ ràng do bản chất thiết kế.",
    "Defined personas": "Persona đã định nghĩa", "Add a persona": "Thêm persona",
    "Add persona": "Thêm persona",
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
    "Request timeout (s)": "Timeout request (giây)",
    "Raise it for a slow staging host.": "Tăng lên nếu host staging phản hồi chậm.",
    "Max requests per test": "Số request tối đa mỗi test",
    "Caps a single test's fan-out, race windows included.":
        "Giới hạn số request một test có thể gửi, kể cả trong race window.",
    "Max response bytes": "Số byte phản hồi tối đa",
    "Body larger than this is truncated before storage.":
        "Body lớn hơn mức này sẽ bị cắt bớt trước khi lưu.",
    "Save limits": "Lưu giới hạn", "Reset to .env defaults": "Khôi phục mặc định .env",
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
    "Reconnect": "Kết nối lại",
    "Environment variable": "Biến môi trường", "Purpose": "Mục đích",
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
    "Other connectors": "Kết nối khác", "NOT CONFIGURED": "CHƯA CẤU HÌNH",
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
    "Setting": "Cấu hình", "Current": "Giá trị hiện tại",
    "Secrets are never echoed here — only whether one is present. Keep tokens in "
    "<code>.env</code>, never in <code>engagement.json</code>.":
        "Bí mật không bao giờ hiển thị ở đây — chỉ báo có tồn tại hay không. Giữ token "
        "trong <code>.env</code>, không bao giờ trong <code>engagement.json</code>.",
})
