"""The readiness verdict, and the one-submit quick setup shown while the
engagement is still empty.
"""

from __future__ import annotations



from ..shell import _e
from .shared import _READY_CLASS, _READY_ICON, _READY_WORD
from app.core.i18n import tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def _quick_setup_card() -> str:
    """The three things an empty engagement needs, in one submit.

    Reaching a first run used to mean three panes and a text editor: add an
    environment, remember to authorize its host, add two personas whose auth
    headers use `${VAR}` syntax nothing on the page explains, set the ${VAR}s in
    .env, then point attacker/victim at them. Every one of those is a separate
    way to end up with a config that looks finished and produces an entirely
    BLOCKED run. This writes all of it at once, in the shape the rest of the
    platform expects — tokens to .env, references to engagement.json.
    """
    intro = _t(
        "This engagement has no target or no second identity yet. Fill this in once and "
        "it writes the environment, authorizes its host, creates both personas and stores "
        "both tokens in <code>.env</code> — the credentials never enter the engagement "
        "file, which only gets a <code>${PERSONA_A_TOKEN}</code> reference."
    )
    footer = _t(
        "Use dedicated test accounts. Everything written here stays editable under "
        "<b>Target</b> and <b>Identities</b>, and running this again overwrites "
        "<code>agent_A</code> / <code>agent_B</code> rather than adding more."
    )
    return f"""<div class="card pad" style="margin-bottom:22px">
<h2 class="section" style="margin-top:0">{_t("Quick setup")}</h2>
<p class="muted" style="margin:0 0 14px">{intro}</p>
<form method="post" action="/config/quick-setup">
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px">
<label class="field"><span>{_t("Environment name")}</span>
<input name="env_name" value="staging" required></label>
<label class="field" style="grid-column:span 2"><span>{_t("Base URL")}</span>
<input name="url" placeholder="https://staging-api.company.com" required></label>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
<label class="field"><span>{_t("Attacker token (agent_A)")}</span>
<input type="password" name="attacker_token" autocomplete="new-password"
 placeholder="eyJhbGciOi..." required></label>
<label class="field"><span>{_t("Victim token (agent_B)")}</span>
<input type="password" name="victim_token" autocomplete="new-password"
 placeholder="eyJhbGciOi..." required></label>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
<label class="field"><span>{_t("An object id the victim owns — key")}</span>
<input name="owns_key" value="customer_id"></label>
<label class="field"><span>{_t("… and its value")}</span>
<input name="owns_value" placeholder="2002"></label>
</div>
<p class="muted" style="margin:12px 0 0">{_t(
    "BOLA cases are built by pointing the attacker at an id the victim owns. Leave it "
    "blank and the generated tests fall back to guessed ids, which is weaker but valid."
)}</p>
<div class="row" style="margin-top:14px"><button class="btn">{_t("Create this engagement")}</button></div>
</form>
<p class="muted" style="margin:12px 0 0">{footer}</p>
</div>"""


def _readiness_pane(readiness, engagement_path: str, show_wizard: bool = False) -> str:
    rows = ""
    for c in readiness.checks:
        cls = _READY_CLASS[c.state]
        fix = ""
        if c.fix_action:
            hidden = "".join(
                f"<input type='hidden' name='{_e(k)}' value='{_e(v)}'>"
                for k, v in c.fix_fields.items()
            )
            fix = (
                f"<form method='post' action='{_e(c.fix_action)}' style='margin:8px 0 0'>{hidden}"
                f"<button class='btn' style='padding:5px 12px'>{_e(c.fix_label)}</button></form>"
            )
        hint = f"<div class='muted' style='margin-top:4px'>{c.hint_html}</div>" if c.hint_html else ""
        rows += (
            f"<tr><td style='white-space:nowrap'>"
            f"<span class='pill {cls}'>{_READY_ICON[c.state]} {_READY_WORD[c.state]}</span></td>"
            f"<td><b>{_e(c.label)}</b><div class='muted'>{_e(c.detail)}</div>{hint}{fix}</td></tr>"
        )

    env_rows = ""
    for env in readiness.environments:
        cls = _READY_CLASS[env.state]
        star = f" <span class='pill low'>{_t('default')}</span>" if env.is_active else ""
        ip = (f"<div class='muted mono' style='font-size:11.5px'>{_e(env.resolved_ip)}</div>"
              if env.resolved_ip else "")
        verdict_word = _t("ALLOWED") if env.state == "ok" else _t("BLOCKED")
        env_rows += (
            f"<tr><td><code>{_e(env.name)}</code>{star}</td>"
            f"<td class='mono' style='font-size:12.5px'>{_e(env.url)}</td>"
            f"<td><span class='pill {cls}'>{verdict_word}</span>"
            f"{ip}</td>"
            f"<td class='muted'>{_e(env.reason)}</td></tr>"
        )
    env_rows = env_rows or f"<tr><td colspan='4' class='muted'>{_t('No environments to check.')}</td></tr>"

    if readiness.can_run:
        verdict = (f"<div class='card pad flash' style='margin-bottom:16px'>"
                   f"<b>&#10003; {_t('Ready to run.')}</b> "
                   f"{_t('Nothing in this configuration will stop a request from being sent.')}</div>")
    else:
        verdict = ("<div class='card pad err' style='margin-bottom:16px'>"
                   f"<b>&#10007; {_t('{n} blocking issue(s).').format(n=readiness.n_blocking)}</b> "
                   f"{_t('A run started now comes back entirely BLOCKED or ERROR. Each row below names the setting and the pane that fixes it.')}</div>")

    wizard = _quick_setup_card() if show_wizard else ""

    return f"""{wizard}{verdict}
<div class="card" style="margin-bottom:22px"><div class="tblwrap"><table>
<tr><th style="width:110px">{_t("State")}</th><th>{_t("Check")}</th></tr>{rows}</table></div></div>

<h2 class="section">{_t("Scope verdict per environment")}</h2>
<p class="muted" style="margin:-4px 0 10px">{_t(
    'Each base URL run through the same <code>ScopeValidator</code> the runner calls, DNS '
    'lookup included. Whatever this table says here is exactly what the execution log will say.'
)}</p>
<div class="card"><div class="tblwrap"><table>
<tr><th>{_t("Environment")}</th><th>{_t("Base URL")}</th><th>{_t("Verdict")}</th><th>{_t("Reason")}</th></tr>{env_rows}
</table></div></div>
<p class="muted" style="margin-top:12px">{_t("Config file:")} <code>{_e(engagement_path)}</code></p>"""
