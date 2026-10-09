"""The regression diff between two assessments, and the Jira comment preview.
"""

from __future__ import annotations

from app.api import ui
from app.core.i18n import VI, tt as _t

from .shell import _e, appbar, page


def regression_page(aid: str, issue_key: str, prev_id: str | None, diff, comment: str,
                    flash: str = "") -> str:
    s = diff.summary()
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
    banner_cls = "err" if s["regressed"] else "flash"
    banner = (_t("Regression: New Findings Since the Last Run") if s["regressed"]
              else _t("No New Findings Since the Last Run"))
    baseline = (_t("Compared with run") + f" <span class='mono'>{_e(prev_id)}</span>" if prev_id
                else _t("No earlier executed run, so current findings are the baseline."))

    def _rows(items, cls):
        return "".join(
            f"<tr><td><b>{_e(f.finding_id)}</b></td><td>{_e(f.title)}</td>"
            f"<td>{_e(f.owasp_category.value)}</td>"
            f"<td>{ui.pill(f.severity.value, cls)}</td>"
            f"<td class='mono'>{_e(f.endpoint)}</td></tr>"
            for f in items
        ) or f"<tr><td colspan='5' class='muted empty'>{_t('None')}</td></tr>"

    head = (f"<tr><th>ID</th><th>{_t('Title')}</th><th>OWASP</th><th>{_t('Severity')}</th>"
            f"<th>{_t('Endpoint')}</th></tr>")

    def _table(title: str, items, cls: str) -> str:
        return (f'<h2 class="section">{title}</h2>'
                f'<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>'
                f"{head}{_rows(items, cls)}</table></div></div>")

    bar = appbar(_t("Regression Diff") + f" — {issue_key}",
                 actions=f'<a class="btn sec" href="/assessment/{_e(aid)}?phase=results">'
                         f'{_t("Back to Assessment")}</a>')
    counts = _t("New: {new} · Fixed: {fixed} · Still Open: {open}").format(
        new=s["new"], fixed=s["fixed"], open=s["persisting"])
    return page(f"{_t('Regression Diff')} — {issue_key}", f"""
{flash_html}
<p class="sub">{baseline}</p>
<div class="card pad {banner_cls}" style="margin-bottom:18px"><b>{banner}</b>
<br><span class="muted">{counts}</span></div>
{_table(_t("New (Regressions)"), diff.new, "crit")}
{_table(_t("Fixed Since Last Run"), diff.fixed, "ok")}
{_table(_t("Still Open"), diff.persisting, "high")}
<h2 class="section">{_t("Jira-Ready Note")}</h2>
<div class="card pad"><pre class="mono" style="white-space:pre-wrap;margin:0">{_e(comment)}</pre></div>
""", active="assessment", appbar_html=bar)


def comment_preview_page(aid: str, issue_key: str, preview: str) -> str:
    bar = appbar(_t("Preview Jira Comment") + f" — {issue_key}")
    return page(f"{_t('Preview Jira Comment')} — {issue_key}", f"""
<p class="sub">{_t("Nothing is posted until you confirm.")}</p>
<div class="card pad" style="margin-bottom:18px"><pre class="mono" style="white-space:pre-wrap;margin:0">{_e(preview)}</pre></div>
<form method="post" action="/assessment/{_e(aid)}/comment" class="row">
<button class="btn">{_t("Confirm &amp; Post to {key}").format(key=_e(issue_key))}</button>
<a class="btn sec" href="/assessment/{_e(aid)}?phase=results">{_t("Cancel")}</a>
</form>
""", active="assessment", appbar_html=bar)


VI.update({
    "Regression: New Findings Since the Last Run": "Hồi Quy: Có Phát Hiện Mới Kể Từ Lần Chạy Trước",
    "No New Findings Since the Last Run": "Không Có Phát Hiện Mới Kể Từ Lần Chạy Trước",
    "Compared with run": "So Sánh Với Lượt Chạy",
    "No earlier executed run, so current findings are the baseline.":
        "Chưa có lượt chạy trước, nên các phát hiện hiện tại là mốc so sánh.",
    "None": "Không Có", "Title": "Tiêu Đề", "Endpoint": "Endpoint",
    "Regression Diff": "So Sánh Hồi Quy", "Back to Assessment": "Về Assessment",
    "New: {new} · Fixed: {fixed} · Still Open: {open}":
        "Mới: {new} · Đã Sửa: {fixed} · Còn Mở: {open}",
    "New (Regressions)": "Mới (Hồi Quy)", "Fixed Since Last Run": "Đã Sửa Từ Lần Chạy Trước",
    "Still Open": "Vẫn Còn Mở", "Jira-Ready Note": "Ghi Chú Cho Jira",
    "Preview Jira Comment": "Xem Trước Bình Luận Jira",
    "Nothing is posted until you confirm.": "Chưa có gì được đăng cho đến khi bạn xác nhận.",
    "Confirm &amp; Post to {key}": "Xác Nhận &Amp; Đăng Lên {key}",
})
