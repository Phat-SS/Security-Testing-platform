"""Named environments and the authorized scope.
"""

from __future__ import annotations


from urllib.parse import quote

from app.api import ui
from app.api.ui import attr
from ..shell import _e
from app.core.i18n import tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def _environments_pane(environments: dict[str, str], active: str) -> str:
    rows = ""
    for name, url in environments.items():
        badge = f" <span class='pill ok'>{_t('Default')}</span>" if name == active else ""
        # Names are free-form labels ("DEV_BMW AU"), so the path segment is
        # percent-encoded rather than left to the browser to guess at.
        slug = quote(name, safe="")
        items = [] if name == active else [
            ui.Item(_t("Make Default"), action=f"/config/environments/{slug}/activate")]
        items.append(ui.Item(_t("Delete"), action=f"/config/environments/{slug}/delete",
                             form_class="confirm-delete",
                             form_data={"what": f"environment {name}"}, danger=True))
        menu = ui.action_menu(items, _t("Actions for {name}").format(name=name))
        rows += (
            f"<tr><td><b>{_e(ui.titleize(name))}</b>"
            + (f" <span class='mono muted' style='font-size:12px'>{_e(name)}</span>"
               if ui.titleize(name) != name else "")
            + f"{badge}</td><td class='mono'>{_e(url)}</td>"
            f"<td class='rowact'>{menu}</td></tr>"
        )
    rows = rows or f"<tr><td colspan='3' class='muted'>{_t('No environments configured yet.')}</td></tr>"
    intro = _t("The base URL each run is sent to.")
    intro_tip = _t(
        "Only the path, method and body of a pasted PoC survive transpiling, so "
        "whichever base URL is picked here is what actually gets called — never a "
        "host taken from the script itself."
    )
    authorize_tip = _t(
        "Adds this URL's hostname to the approved scope in the same step. Without it "
        "the URL is saved but every request to it is refused before it is sent — the "
        "safe direction to fail in, and the right choice for a target the engagement "
        "does not actually cover."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}{ui.info(intro_tip)}</p>
<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>{_t("Name")}</th><th>{_t("Base URL")}</th><th></th></tr>{rows}</table></div></div>
<div class="card pad">
<form method="post" action="/config/environments" class="row">
<input name="name" placeholder="staging" style="max-width:160px" required>
<input name="url" placeholder="https://staging.company.com" style="flex:1;min-width:240px" required>
<label class="muted" style="display:flex;align-items:center;gap:4px">
<input type="checkbox" name="make_active" value="true" style="width:auto"> {_t("Make Default")}</label>
<label class="muted" style="display:flex;align-items:center;gap:4px"
 title="{attr(authorize_tip)}">
<input type="checkbox" name="authorize_host" value="true" style="width:auto" checked> {_t("Authorize Its Host")}</label>
<button class="btn">{_t("Save")}</button>
</form>
</div>"""


def _scope_pane(policy) -> str:
    """Prose here is one line per control; the reasoning behind each one moved
    into its ⓘ. The page was four paragraphs deep before a tester reached the
    first input, and the paragraphs were read once and then scrolled past."""
    allowed = "\n".join(sorted(policy.allowed_hosts))
    blocked = "\n".join(sorted(policy.blocked_hosts))
    priv = "checked" if policy.allow_private_ranges else ""
    boundary_tip = _t(
        "The authorization boundary. Every outbound request is checked against this "
        "before it is sent, and the hostname must match exactly — there are no "
        "wildcards, because a wildcard in a pentest authorization list is how an "
        "unauthorized host gets tested by accident. Hostnames only: no scheme, no "
        "port, no path. A port is not part of the check, and DNS is re-resolved and "
        "the resulting IP re-checked on every request."
    )
    priv_tip = _t(
        "When off, a host that resolves to 127.0.0.0/8, 10/8, 172.16/12, 192.168/16 "
        "or 169.254/16 (cloud metadata) is refused even if its name is on the "
        "approved list — that check is what stops a DNS-based SSRF from reaching an "
        "internal service."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{_t(
        "Checked before every request, by name and by resolved IP."
    )}{ui.info(boundary_tip)}</p>
<div class="card pad">
<form method="post" action="/config/scope">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
<label class="field"><span>{_t("Approved Hosts — One per Line")}</span>
<textarea name="allowed_hosts" rows="7" placeholder="staging-api.company.com&#10;127.0.0.1">{_e(allowed)}</textarea></label>
<label class="field"><span>{_t("Never Test — One per Line (Always Wins)")}</span>
<textarea name="blocked_hosts" rows="7" placeholder="production.company.com">{_e(blocked)}</textarea></label>
</div>
<label class="row" style="gap:8px;margin-top:14px">
<input type="checkbox" name="allow_private_ranges" value="true" style="width:auto" {priv}>
<span><b>{_t("Allow Private / Loopback Ranges")}</b>
<span class="muted"> — {_t("Lab Targets Only")}</span>{ui.info(priv_tip)}</span></label>
<div style="margin-top:14px"><button class="btn">{_t("Save Scope")}</button></div>
</form></div>"""


def _target_pane(engagement) -> str:
    """Environments and scope together.

    They were two tabs and that was the wrong seam: a base URL whose host is not
    on the allow-list is the single most common reason an entire run comes back
    BLOCKED, and the fix used to be one tab away from the mistake.
    """
    return f"""{_environments_pane(engagement.environments, engagement.active_environment)}
<h2 class="section">{_t("Scope Authorization")}</h2>
{_scope_pane(engagement.scope.policy)}"""
