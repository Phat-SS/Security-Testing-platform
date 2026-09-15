"""Every confirmed finding on this engagement, in one place.

The platform could always tell you what one assessment found. What it could
never answer is the question anyone running an engagement actually has — "what
is outstanding across all of it" — because findings only ever existed inside
the assessment that produced them.
"""

from __future__ import annotations

from app.api import ui
from app.api.ui import attr, e
from app.core.i18n import VI, tt as _t

from .shell import _SEV_CLASS, appbar, page

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _row(assessment_id: str, issue_key: str, finding) -> str:
    severity = finding.severity.value
    endpoint = getattr(finding, "endpoint", "") or ""
    return (
        f"<tr><td><span class='pill {_SEV_CLASS.get(severity, 'info')}'>{e(severity)}</span></td>"
        f"<td><b>{e(finding.title)}</b>"
        + (f"<div class='mono muted' style='font-size:12px;margin-top:2px'>{e(endpoint)}</div>"
           if endpoint else "")
        + f"</td><td class='mono'>{e(finding.owasp_category.value)}</td>"
        f"<td><a href='/assessment/{attr(assessment_id)}?phase=results'>{e(issue_key)}</a></td>"
        f"<td class='mono muted'>{e(finding.finding_id)}</td></tr>"
    )


def findings_page(rows: list[tuple], engagement: str = "") -> str:
    """`rows` is (assessment_id, issue_key, finding), newest assessment first."""
    counts: dict[str, int] = {}
    for _aid, _key, finding in rows:
        value = finding.severity.value
        counts[value] = counts.get(value, 0) + 1

    chips = "".join(
        f"<span class='pill {_SEV_CLASS.get(name, 'info')}' style='margin-right:6px'>"
        f"{e(_t(name.title()))} {counts[name]}</span>"
        for name in _SEV_ORDER if counts.get(name)
    ) or f"<span class='muted'>{_t('Nothing confirmed yet.')}</span>"

    # Severity first, then the order they came back in — which is newest
    # assessment first, so the most recent critical is the top line.
    ordered = sorted(rows, key=lambda r: _SEV_ORDER.index(r[2].severity.value)
                     if r[2].severity.value in _SEV_ORDER else len(_SEV_ORDER))

    body = ui.table(
        [_t("Severity"), _t("Finding"), "OWASP", _t("Assessment"), "ID"],
        "".join(_row(*r) for r in ordered),
        empty=_t("No confirmed findings on this engagement yet."),
    )
    note = (f"{_t('Engagement')}: <b>{e(engagement)}</b>" if engagement else "")
    return page(_t("Findings"), f"<div style='margin-bottom:14px'>{chips}</div>{body}",
                active="findings",
                appbar_html=appbar(_t("Findings"), note=note))


VI.update({
    "Findings": "Phát hiện", "Severity": "Mức độ", "Finding": "Phát hiện",
    "Assessment": "Assessment", "Engagement": "Engagement",
    "Nothing confirmed yet.": "Chưa có phát hiện nào được xác nhận.",
    "No confirmed findings on this engagement yet.":
        "Engagement này chưa có phát hiện nào được xác nhận.",
    "Critical": "Nghiêm trọng", "High": "Cao", "Medium": "Trung bình",
    "Low": "Thấp", "Info": "Thông tin",
})
