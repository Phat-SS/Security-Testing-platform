"""The audit log, made readable.

Every run, approval, config change and export has always been recorded. Nothing
ever displayed it — the only way to read it was a SQL client. An audit trail
nobody can open is one nobody checks, which is most of the value gone.
"""

from __future__ import annotations

from app.api import ui
from app.api.ui import attr, e
from app.core.i18n import VI, tt as _t

from .shell import appbar, page

#: The actions worth colouring, because they are the ones with consequences
#: outside this process: packets sent, a decision recorded, data leaving.
_TONE = {
    "execute": "crit",
    "approve": "low",
    "reject": "med",
    "export": "info",
    "engagement_snapshot": "info",
    "import_openapi": "info",
    "runtime_config": "med",
    "quick_setup": "med",
}


def _row(entry, issue_key: str) -> str:
    when = entry.created_at.strftime("%Y-%m-%d %H:%M") if entry.created_at else ""
    tone = _TONE.get(entry.action, "info")
    where = (
        f"<a href='/assessment/{attr(entry.assessment_id)}'>{e(issue_key or entry.assessment_id)}</a>"
        if entry.assessment_id else "<span class='muted'>—</span>"
    )
    return (
        f"<tr><td class='mono muted' style='white-space:nowrap'>{e(when)}</td>"
        f"<td><span class='pill {tone}'>{e(entry.action)}</span></td>"
        f"<td>{where}</td>"
        f"<td class='mono'>{e(entry.actor)}</td>"
        f"<td class='muted'>{e(entry.detail)}</td></tr>"
    )


def activity_page(rows: list[tuple], engagement: str = "") -> str:
    """`rows` is (audit entry, issue_key), newest first."""
    body = ui.table(
        [_t("When"), _t("Action"), _t("Assessment"), _t("Who"), _t("Detail")],
        "".join(_row(entry, key) for entry, key in rows),
        empty=_t("Nothing has happened on this engagement yet."),
        scroll=len(rows) > 25,
    )
    note = (f"{_t('Engagement')}: <b>{e(engagement)}</b>" if engagement else "")
    return page(_t("Activity"), body, active="activity",
                appbar_html=appbar(_t("Activity"), note=note))


VI.update({
    "Activity": "Hoạt động", "When": "Lúc", "Action": "Hành động",
    "Who": "Ai", "Detail": "Chi tiết",
    "Nothing has happened on this engagement yet.":
        "Engagement này chưa có hoạt động nào.",
})
