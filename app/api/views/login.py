"""The login form.
"""

from __future__ import annotations



from .shell import _e, page
from app.core.i18n import tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def login_page(flash: str = "") -> str:
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
    intro = _t(
        "Multi-user auth is enabled. Paste the API key printed by "
        "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> to authenticate "
        "this browser for actions like designing tests, approving, and executing. Reads "
        "stay open either way."
    )
    return page(_t("Log in"), f"""
<h1 style="font-size:19px">{_t("Log in")}</h1>
<p class="sub">{intro}</p>
{flash_html}
<div class="card pad" style="max-width:420px">
<form method="post" action="/login">
<label class="field" style="margin-bottom:12px"><span>{_t("API Key")}</span>
<input type="password" name="api_key" required autofocus></label>
<button class="btn">{_t("Log in")}</button>
</form>
</div>
""")
