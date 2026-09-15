"""The error page every route falls back to instead of a bare 500.
"""

from __future__ import annotations



from .shell import _e, page
from app.core.i18n import tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def error_page(title: str, headline: str, hint_html: str,
                back_href: str = "/", back_label: str | None = None) -> str:
    """A failure as a readable page instead of a bare 500. `headline` may
    contain user input and is escaped; `hint_html` is markup we build ourselves."""
    back_label = _t(back_label if back_label is not None else "← Back to dashboard")
    title = _t(title)
    return page(title, f"""
<h1 style="font-size:19px">{_e(title)}</h1>
<div class="card pad err">
<p style="margin:0 0 8px"><b>{_e(_t(headline))}</b></p>
<p class="muted" style="margin:0">{hint_html}</p>
</div>
<p><a href="{_e(back_href)}" class="btn sec">{_e(back_label)}</a></p>
""")
