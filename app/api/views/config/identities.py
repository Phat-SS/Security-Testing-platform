"""Personas, and which two of them attack each other.
"""

from __future__ import annotations



from ..shell import _e
from .shared import _kv_textarea_value
from app.core.i18n import tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def _personas_pane(personas: list[dict], attacker: str, victim: str) -> str:
    names = [p.get("name", "") for p in personas]
    cards = ""
    for p in personas:
        name = p.get("name", "")
        roles = ""
        if name == attacker:
            roles += f" <span class='pill med'>{_t('attacker')}</span>"
        if name == victim:
            roles += f" <span class='pill high'>{_t('victim')}</span>"
        headers = _kv_textarea_value(p.get("auth_headers") or {}, ": ")
        owns = _kv_textarea_value(p.get("owns") or {}, "=")
        markers = "\n".join(p.get("secret_markers") or [])
        scoping = "\n".join(p.get("scoping_headers") or [])
        save_label = _t("Save {name}").format(name=_e(name))
        cards += f"""<div class="card pad" style="margin-bottom:12px">
<div class="row" style="justify-content:space-between;margin-bottom:10px">
<div><b>{_e(name)}</b>{roles}</div>
<form method="post" action="/config/personas/{_e(name)}/delete" style="margin:0"
 class="confirm-delete" data-what="persona {_e(name)}">
<button class="btn ghost">{_t("Delete")}</button></form>
</div>
<form method="post" action="/config/personas">
<input type="hidden" name="name" value="{_e(name)}">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<label class="field"><span>{_t("Role label")}</span>
<input name="role" value="{_e(p.get('role', 'user'))}"></label>
<label class="field"><span>{_t("Owned object ids — key=value per line")}</span>
<textarea name="owns" rows="3" placeholder="customer_id=2002">{_e(owns)}</textarea></label>
</div>
<label class="field" style="margin-top:12px"><span>{_t("Auth headers — Header: value per line")}</span>
<textarea name="auth_headers" rows="3" placeholder="Authorization: Bearer eyJ...">{_e(headers)}</textarea></label>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px">
<label class="field"><span>{_t("Secret markers — one per line")}</span>
<textarea name="secret_markers" rows="2" placeholder="beth.victim@example.com">{_e(markers)}</textarea></label>
<label class="field"><span>{_t("Scoping headers to strip on privilege-escalation tests — one per line")}</span>
<textarea name="scoping_headers" rows="2" placeholder="entity-context">{_e(scoping)}</textarea></label>
</div>
<div style="margin-top:12px"><button class="btn">{save_label}</button></div>
</form></div>"""
    cards = cards or f"<p class='muted'>{_t('No personas defined yet — add one below.')}</p>"

    def opts(selected: str) -> str:
        out = "".join(
            f"<option value='{_e(n)}' {'selected' if n == selected else ''}>{_e(n)}</option>"
            for n in names
        )
        if selected and selected not in names:
            out = (f"<option value='{_e(selected)}' selected>{_e(selected)} "
                   f"— {_t('not defined!')}</option>" + out)
        return out or f"<option value=''>— {_t('no personas defined')} —</option>"

    personas_intro = _t(
        'Test identities and their credentials. You cannot test broken object-level '
        'authorization with one identity: BOLA means "A reaches B\'s object", which needs '
        'two real accounts plus knowledge of what each legitimately owns. Tests reference '
        'personas <i>by name</i>, so a token never lands in a test case, an export or a report.'
    )
    roles_note = _t(
        "The attacker sends the requests; generated BOLA cases aim it at ids the victim "
        "owns. Point these at two <i>different</i> personas or the results are "
        "inconclusive by construction."
    )
    add_footer = _t(
        "Use dedicated test accounts. Credentials are written to the engagement config in "
        "plain text and every response is passed through secret redaction before it reaches "
        "a report — but a real user's token does not belong in either."
    )

    return f"""<p class="muted" style="margin:0 0 12px">{personas_intro}</p>

<div class="card pad" style="margin-bottom:18px">
<form method="post" action="/config/identities" class="row" style="align-items:flex-end">
<label class="field" style="max-width:220px"><span>{_t("Attacker persona")}</span>
<select name="attacker">{opts(attacker)}</select></label>
<label class="field" style="max-width:220px"><span>{_t("Victim persona")}</span>
<select name="victim">{opts(victim)}</select></label>
<button class="btn">{_t("Save roles")}</button>
</form>
<p class="muted" style="margin:10px 0 0">{roles_note}</p>
</div>

<h2 class="section">{_t("Defined personas")}</h2>
{cards}

<h2 class="section">{_t("Add a persona")}</h2>
<div class="card pad">
<form method="post" action="/config/personas">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<label class="field"><span>{_t("Name")}</span>
<input name="name" placeholder="agent_A" required></label>
<label class="field"><span>{_t("Role label")}</span>
<input name="role" placeholder="agent" value="user"></label>
</div>
<label class="field" style="margin-top:12px"><span>{_t("Auth headers — Header: value per line")}</span>
<textarea name="auth_headers" rows="3" placeholder="Authorization: Bearer eyJ..."></textarea></label>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px">
<label class="field"><span>{_t("Owned object ids — key=value per line")}</span>
<textarea name="owns" rows="2" placeholder="customer_id=1001"></textarea></label>
<label class="field"><span>{_t("Secret markers — one per line")}</span>
<textarea name="secret_markers" rows="2" placeholder="alice.buyer@example.com"></textarea></label>
</div>
<label class="field" style="margin-top:12px"><span>{_t("Scoping headers to strip on privilege-escalation tests — one per line")}</span>
<textarea name="scoping_headers" rows="2" placeholder="entity-context"></textarea></label>
<div style="margin-top:12px"><button class="btn">{_t("Add persona")}</button></div>
</form>
<p class="muted" style="margin:10px 0 0">{add_footer}</p>
</div>"""
