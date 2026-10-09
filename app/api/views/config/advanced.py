"""Runner limits, the AI and evidence settings, the Jira connector, and the
read-only runtime facts.
"""

from __future__ import annotations



from app.api import ui

from ..shell import _e
from .shared import _section
from app.core.i18n import tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def _runner_pane(limits, overrides: dict) -> str:
    def field(key: str, label: str, hint: str, step: str = "1") -> str:
        value = overrides.get(key, "")
        env_default = getattr(limits, key)
        return f"""<label class="field">
<span>{label}</span>
<input type="number" name="{key}" value="{_e(value)}" step="{step}" min="0"
 placeholder="{_e(env_default)} (from .env)">
<span class="muted" style="font-size:11.5px;text-transform:none;letter-spacing:0">{hint}</span></label>"""

    intro = _t(
        'Hard caps the trusted runner applies to every outbound request. Blank means '
        '"use the <code>.env</code> value" shown as the placeholder; a value here '
        'overrides it for this engagement only, with no restart.'
    )
    footer = _t(
        "The runner never auto-follows a redirect: a 302 to an internal host is the same "
        "SSRF wearing a hat, and blindly chasing it would let the HTTP client re-resolve DNS "
        "outside the scope gate. A 3xx response is captured and evaluated exactly as received "
        "— there is no redirect setting to tune here."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
<div class="card pad">
<form method="post" action="/config/runner">
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px">
{field("timeout_s", _t("Request Timeout (s)"), _t("Raise it for a slow staging host."), "0.5")}
{field("max_requests_per_test", _t("Max Requests per Test"), _t("Caps a single test's fan-out, race windows included."))}
{field("max_concurrent_tests", _t("Tests in Flight at Once"), _t("1 runs a plan one test at a time. Higher finishes a long plan faster, at proportionally higher request rate against the target — a blast-radius decision, so it is not raised for you."))}
{field("max_response_bytes", _t("Max Response Bytes"), _t("Body larger than this is truncated before storage."))}
{field("max_requests_per_second", _t("Max Requests per Second"), _t("Ceiling on the whole run's request rate. Blank or 0 means no ceiling. Probe bursts are exempt."), "0.5")}
</div>
<div style="margin-top:14px" class="row">
<button class="btn">{_t("Save Limits")}</button>
<button class="btn ghost" name="reset" value="true">{_t("Reset to .env Defaults")}</button>
</div>
</form></div>
<p class="muted" style="margin-top:12px">{footer}</p>"""


def _mcp_pane(
    jira_mode: str,
    jira_live: bool,
    jira_warning: str,
    jira_env: list[tuple[str, str, str]],
    jira_keys: list[str],
) -> str:
    cls = "ok" if jira_live else "med"
    word = _t("LIVE") if jira_live else _t("MOCK")
    warning_html = (
        f"<div class='muted' style='margin-top:6px;color:var(--crit)'>&#9888; {_e(jira_warning)}</div>"
        if jira_warning else ""
    )
    keys_html = (
        f"<div class='muted' style='margin-top:6px'>{_t('Serves:')} "
        + ", ".join(f"<code>{_e(k)}</code>" for k in jira_keys) + "</div>"
        if jira_keys else ""
    )
    env_rows = "".join(
        f"<tr><td class='mono'>{_e(name)}</td>"
        f"<td><span class='pill {'ok' if status == 'set' else 'med'}'>{_t(status.upper())}</span></td>"
        f"<td class='muted'>{_e(hint)}</td></tr>"
        for name, status, hint in jira_env
    )
    intro = _t(
        "External MCP connectors this platform talks to. Credentials live in <code>.env</code> "
        "only — never in <code>engagement.json</code> or a report. <b>Reconnect</b> re-reads "
        "<code>.env</code> and rebinds the client in place, which is all a restart would have "
        "done anyway — useful right after refreshing a short-lived OAuth token."
    )
    refresh_note = _t(
        "<b>Refresh token</b> opens the Atlassian OAuth login in your browser, waits for it, "
        "and reconnects automatically — needs Node.js (<code>npx</code>) and a browser on the "
        "machine running this app. If that isn't available here, do it by hand instead: "
        "authorize once with <code>npx -y mcp-remote https://mcp.atlassian.com/v1/mcp</code>, "
        "run <code>npm run jira:token</code> to pull the new token into <code>.env</code>, then "
        "click <b>Reconnect</b> above."
    )
    postman_note = _t(
        "No MCP integration is wired up for this platform — there is nothing here yet to "
        "connect or reconnect. (Separately, a completed assessment can already export a "
        "Postman collection from its report page — a one-way file export, unrelated to this "
        "connector list.)"
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>

<div class="card pad" style="margin-bottom:18px">
<div class="row" style="justify-content:space-between;align-items:flex-start">
<div>
<b>Jira</b> <span class="pill {cls}" style="margin-left:6px">{word}</span>
<div class="muted" style="margin-top:4px">{_e(jira_mode)}</div>
{warning_html}{keys_html}
</div>
<div class="row" style="gap:8px;margin:0">
<form method="post" action="/config/mcp/jira/refresh-token" class="js-busy" style="margin:0">
<button class="btn ghost">{_t("Refresh Token")}</button></form>
<form method="post" action="/config/mcp/jira/reconnect" style="margin:0">
<button class="btn">{_t("Reconnect")}</button></form>
</div>
</div>
</div>

<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>{_t("Environment Variable")}</th><th>{_t("Status")}</th><th>{_t("Purpose")}</th></tr>{env_rows}
</table></div></div>
<p class="muted" style="margin-bottom:22px">{refresh_note}</p>

<h2 class="section">{_t("Other Connectors")}</h2>
<div class="card pad">
<b>Postman</b> <span class="pill med" style="margin-left:6px">{_t("NOT CONFIGURED")}</span>
<div class="muted" style="margin-top:4px">{postman_note}</div>
</div>"""


#: `--effort` accepts exactly these (see `claude --help`). A closed set, so it
#: gets a <select>: the free-text box it replaces was validated by a regex that
#: accepted any word, including ones the CLI rejects at call time rather than at
#: save time — which turns a typo into a failed analysis instead of an error.
_AI_EFFORTS = ("low", "medium", "high", "xhigh", "max")

#: `--model` takes an alias for the current model or a full versioned id. These
#: are SUGGESTIONS behind a <datalist>, never a closed list: pinning is the
#: minority case, and a hard-coded menu of model ids goes stale — the box this
#: replaces had a stale one baked into its placeholder.
_AI_MODEL_HINTS = ("sonnet", "opus", "fable")

#: Bytes of entropy per generated key. Both are base64url-encoded afterwards, so
#: the stored strings comfortably clear the 16 / 32 character minimums the
#: writer enforces.
_KEY_BYTES = {"EVIDENCE_FINGERPRINT_KEY": 32, "REPORT_SIGNING_KEY": 48}

_HINT = "font-size:11.5px;text-transform:none;letter-spacing:0"
_GRID = "display:grid;grid-template-columns:repeat(auto-fit,minmax({0},1fr));gap:14px"


def _hint(text: str) -> str:
    return f'<span class="muted" style="{_HINT}">{text}</span>'


def _clear_box(key: str) -> str:
    return (
        f'<label class="muted" style="display:flex;gap:6px;align-items:center;'
        f'margin-top:6px;{_HINT}">'
        f'<input type="checkbox" name="clear_{_e(key)}" value="true" style="width:auto">'
        f'{_t("Clear the Stored Value")}</label>'
    )


def _ai_pane(values: dict, flags: dict, ai: dict) -> str:
    """The Claude block, status first.

    Nothing here needs an API key. `ClaudeLLM` shells out to the operator's own
    `claude` CLI, so the login, the subscription and the default model are the
    ones their Claude Code is already using. This pane used to open with a
    "Versioned model ID" box carrying a versioned placeholder, which read as a
    required field — so the one setting most people should leave alone looked
    like the first thing to fill in, and the placeholder had gone stale besides.
    It now says what the AI path is bound to, and the model field defaults
    visibly to "whatever the CLI uses".
    """
    on = bool(flags.get("USE_AI"))
    found = bool(ai.get("found"))
    if not found:
        tone, word = "med", _t("CLI NOT FOUND")
        detail = _t(
            "Claude Code is not installed on this machine, or is not on PATH. Analysis "
            "runs on the deterministic path until it is."
        )
    elif on:
        tone, word = "ok", _t("ON")
        detail = _t(
            "Runs through your own Claude Code login — no separate API key, no separate bill."
        )
    else:
        tone, word = "info", _t("OFF")
        detail = _t(
            "The CLI is available. Analysis runs on the deterministic path until you turn "
            "this on."
        )

    pinned = str(ai.get("pinned_model") or "")
    model_now = f"<code>{_e(pinned)}</code>" if pinned else f"<i>{_t('the CLI default')}</i>"
    cli_path = _e(str(ai.get("path") or "claude"))
    checked = " checked" if on else ""

    hints = "".join(f'<option value="{_e(m)}">' for m in _AI_MODEL_HINTS)
    current_effort = str(values.get("AI_EFFORT", ""))
    efforts = "".join(
        f'<option value="{_e(v)}"{" selected" if current_effort == v else ""}>{_e(ui.titleize(v))}</option>'
        for v in _AI_EFFORTS
    )
    effort_default = "" if current_effort else " selected"
    pin_checked = " checked" if flags.get("AI_REQUIRE_PINNED_MODEL") else ""

    model_hint = _hint(_t("Leave blank unless you need a specific one. An alias, or a full versioned id."))
    effort_hint = _hint(_t("How much reasoning each call is allowed. Higher costs more and takes longer."))
    budget_hint = _hint(_t("A hard stop, not a target. Blank lets the CLI decide."))
    pin_note = _t(
        "For deployments that must be able to say which exact model produced a report. An "
        "alias like <code>sonnet</code> moves between releases, so it is rejected here — with "
        "this on, a blank model field stops the AI path entirely."
    )

    return f"""<div class="card pad" style="margin-bottom:14px">
<div class="row" style="justify-content:space-between;align-items:flex-start">
<div style="min-width:0">
<b>Claude</b> <span class="pill {tone}" style="margin-left:6px">{word}</span>
<div class="muted" style="margin-top:4px">{detail}</div>
<div class="muted" style="font-size:11.5px;margin-top:6px;overflow-wrap:anywhere">
{_t("CLI")}: <span class="mono">{cli_path}</span> &middot; {_t("model")}: {model_now}</div>
</div>
<label class="row" style="gap:7px;margin:0;white-space:nowrap">
<input type="checkbox" name="USE_AI" value="true" style="width:auto"{checked}>
<b>{_t("Use Claude")}</b></label>
</div>
</div>

<div class="card pad" style="margin-bottom:14px">
<div style="{_GRID.format("215px")}">
<label class="field"><span>{_t("Model")}</span>
<input name="ANTHROPIC_MODEL" list="ai-model-hints" value="{_e(values.get("ANTHROPIC_MODEL", ""))}"
 placeholder="{_t("empty — use the CLI's model")}">
<datalist id="ai-model-hints">{hints}</datalist>
{model_hint}</label>

<label class="field"><span>{_t("Effort")}</span>
<select name="AI_EFFORT">
<option value=""{effort_default}>{_t("CLI Default")}</option>{efforts}</select>
{effort_hint}</label>

<label class="field"><span>{_t("Spend Cap per Call (USD)")}</span>
<input type="number" min="0.01" step="0.01" name="AI_MAX_BUDGET_USD"
 value="{_e(values.get("AI_MAX_BUDGET_USD", ""))}" placeholder="{_t("no cap")}">
{budget_hint}</label>

<label class="field"><span>{_t("Budget per Assessment (USD)")}</span>
<input type="number" min="0.01" step="0.01" name="AI_ASSESSMENT_BUDGET_USD"
 value="{_e(values.get("AI_ASSESSMENT_BUDGET_USD", ""))}" placeholder="{_t("no cap")}"></label>
</div>

<details style="margin-top:12px">
<summary class="muted" style="cursor:pointer;font-size:12.5px">{_t("Compliance Option")}</summary>
<label class="row" style="gap:7px;margin:10px 0 0">
<input type="checkbox" name="AI_REQUIRE_PINNED_MODEL" value="true" style="width:auto"{pin_checked}>
{_t("Refuse to Run Unless the Model Above Is a Full Versioned Id")}</label>
<div class="muted" style="margin-top:6px;font-size:12.5px">{pin_note}</div>
</details>
</div>"""


def _evidence_pane(values: dict, secrets: dict) -> str:
    """Two capability rows, not two password boxes.

    Neither key's VALUE means anything — they only have to be random and stable.
    Presenting them as secrets to compose put the reader in front of a password
    field with a length rule, for a decision they never actually had to make,
    while saying nothing about what is lost by leaving them empty, which is the
    only part that matters. The rows lead with what works and what does not; the
    manual boxes move behind a disclosure for the one real case, pasting a key
    back from a secret manager.
    """
    rows = (
        ("EVIDENCE_FINGERPRINT_KEY", _t("Cross-identity Correlation"), _t(
            "HMACs identity values so a BOLA finding can show the attacker saw the victim's "
            "own data. Without it that comparison is skipped and those verdicts come back "
            "INCONCLUSIVE."
        )),
        ("REPORT_SIGNING_KEY", _t("Report Manifest Signing"), _t(
            "Signs each report manifest, so it can be shown not to have been edited after "
            "the run. Without it manifests are still written, just unsigned."
        )),
    )
    body = ""
    for index, (key, label, why) in enumerate(rows):
        live = bool(secrets.get(key))
        pill = (f'<span class="pill ok">{_t("ACTIVE")}</span>' if live
                else f'<span class="pill med">{_t("OFF")}</span>')
        # The rule SEPARATES the rows, so the first one does not get it — it
        # would otherwise draw a stray line across the top of the card.
        rule = "" if index == 0 else "border-top:1px solid var(--border);"
        body += (
            f'<div style="{rule}padding:10px 0">'
            f'<b>{_e(label)}</b> {pill}'
            f'<div class="muted" style="margin-top:3px;font-size:12.5px">{why}</div></div>'
        )

    if any(not secrets.get(key) for key, _, _ in rows):
        action = (
            f'<button class="btn" type="button" onclick="fillEvidenceKeys()">'
            f'{_t("Generate the Missing Keys")}</button>'
            + _hint(_t("Generated in your browser, stored when you save."))
        )
    else:
        action = _hint(_t("Nothing to do here."))

    def box(key: str, minimum: int) -> str:
        placeholder = _t("stored — blank keeps it") if secrets.get(key) else _t("not set")
        return f"""<div><label class="field"><span>{_e(key)}</span>
<input id="secret-{_e(key.lower())}" type="password" name="{_e(key)}" autocomplete="new-password"
 minlength="{minimum}" placeholder="{placeholder}"></label>
{_clear_box(key)}</div>"""

    manual_note = _t(
        "For restoring a key from a secret manager, or rotating one. Stored values are never "
        "sent back to the browser: blank keeps the current key, and removing one takes the "
        "explicit checkbox."
    )
    key_id_hint = _hint(_t("A label recorded in the manifest, so a verifier knows which key to reach for."))

    return f"""<div class="card pad" style="margin-bottom:14px">
{body}
<div class="row" style="margin-top:12px;align-items:center">{action}</div>
<details style="margin-top:12px" id="evidence-manual">
<summary class="muted" style="cursor:pointer;font-size:12.5px">{_t("Enter Keys by Hand")}</summary>
<div class="muted" style="margin:8px 0 12px;font-size:12.5px">{manual_note}</div>
<div style="{_GRID.format("260px")}">
{box("EVIDENCE_FINGERPRINT_KEY", 16)}
{box("REPORT_SIGNING_KEY", 32)}
</div>
<label class="field" style="margin-top:12px;max-width:320px"><span>{_t("Signing Key Id")}</span>
<input name="REPORT_SIGNING_KEY_ID" value="{_e(values.get("REPORT_SIGNING_KEY_ID", ""))}"
 placeholder="local-hmac">
{key_id_hint}</label>
</details>
</div>"""


def _oast_pane(values: dict, secrets: dict) -> str:
    """One line when it is not set up, which is the normal case.

    OAST is an external callback collector. Four fields for an integration most
    engagements do not have was most of this pane's apparent length; collapsed,
    it states the consequence of not having one and gets out of the way.
    """
    configured = bool(values.get("INTERACTSH_SERVER")
                      or (values.get("OAST_PUBLIC_URL") and values.get("OAST_POLL_URL")))
    pill = (f'<span class="pill ok">{_t("CONFIGURED")}</span>' if configured
            else f'<span class="pill info">{_t("NOT SET UP")}</span>')
    if configured:
        summary = _t("Blind and out-of-band tests can be confirmed.")
    else:
        summary = _t(
            "Blind SSRF and other out-of-band tests report INCONCLUSIVE — there is nowhere "
            "for the target's callback to land."
        )
    token_placeholder = (_t("stored — blank keeps it") if secrets.get("OAST_API_TOKEN")
                         else _t("not set"))
    ish_placeholder = (_t("stored — blank keeps it") if secrets.get("INTERACTSH_TOKEN")
                       else _t("not set"))
    footer = _t(
        "Both URLs must be HTTPS and are set together. The token is sent only to the polling "
        "endpoint — never into the callback URL handed to the target."
    )
    return f"""<div class="card pad">
<details{" open" if configured else ""}>
<summary style="cursor:pointer"><b>{_t("Out-of-band Collaborator")}</b> {pill}
<div class="muted" style="margin-top:4px;font-size:12.5px">{summary}</div></summary>
<div style="{_GRID.format("260px")};margin-top:14px">
<label class="field"><span>{_t("Interactsh Server")}</span>
<input name="INTERACTSH_SERVER" value="{_e(values.get("INTERACTSH_SERVER", ""))}"
 placeholder="oast.example.com"></label>
<div><label class="field"><span>{_t("Interactsh Token")}</span>
<input type="password" name="INTERACTSH_TOKEN" autocomplete="new-password"
 placeholder="{ish_placeholder}"></label>
{_clear_box("INTERACTSH_TOKEN")}</div>
</div>
<div class="muted" style="margin:8px 0 0;font-size:12.5px">{_t("Or a generic collector:")}</div>
<div style="{_GRID.format("260px")};margin-top:8px">
<label class="field"><span>{_t("Public Callback Base URL")}</span>
<input name="OAST_PUBLIC_URL" value="{_e(values.get("OAST_PUBLIC_URL", ""))}"
 placeholder="https://callbacks.example.test/c"></label>
<label class="field"><span>{_t("Authenticated Polling Base URL")}</span>
<input name="OAST_POLL_URL" value="{_e(values.get("OAST_POLL_URL", ""))}"
 placeholder="https://callbacks.example.test/api/events"></label>
<div><label class="field"><span>{_t("Polling API Token")}</span>
<input type="password" name="OAST_API_TOKEN" autocomplete="new-password"
 placeholder="{token_placeholder}"></label>
{_clear_box("OAST_API_TOKEN")}</div>
<label class="field"><span>{_t("Polling Timeout (s)")}</span>
<input type="number" min="0.1" step="0.1" name="OAST_TIMEOUT_S"
 value="{_e(values.get("OAST_TIMEOUT_S", ""))}" placeholder="5"></label>
</div>
<div class="muted" style="margin-top:10px;font-size:12.5px">{footer}</div>
</details></div>"""


# Fills only an EMPTY box. These keys cannot be rotated in place: change the
# signing key and every manifest already signed with the old one stops
# verifying, so a convenience button that overwrote a live key would be a trap.
_EVIDENCE_JS = """
function _randomSecret(bytes) {
  var data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  var raw = Array.from(data, function (b) { return String.fromCharCode(b); }).join('');
  return btoa(raw).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
function fillEvidenceKeys() {
  var filled = 0;
  __PAIRS__.forEach(function (pair) {
    var el = document.getElementById(pair[0]);
    if (!el || el.value) return;
    el.value = _randomSecret(pair[1]);
    filled += 1;
  });
  // Opened so the generated values are visible before they are saved: a button
  // that silently stuffs a secret into a collapsed field asks for trust it has
  // not earned.
  if (filled) {
    var manual = document.getElementById('evidence-manual');
    if (manual) manual.open = true;
  }
}
"""


def _ai_evidence_pane(config: dict[str, object]) -> str:
    values = config.get("values") or {}
    flags = config.get("flags") or {}
    secrets = config.get("secrets") or {}
    ai = config.get("ai") or {}

    intro = _t(
        "Written to <code>.env</code> and applied immediately, with no restart. Needs the "
        "<b>admin</b> role when authentication is on."
    )
    pairs = ", ".join(
        f"['secret-{key.lower()}', {size}]" for key, size in _KEY_BYTES.items()
    )
    script = _EVIDENCE_JS.replace("__PAIRS__", f"[{pairs}]")

    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
<form method="post" action="/config/ai-evidence" id="ai-form">

<h2 class="section" style="margin-top:0">{_t("Analyzer")}</h2>
{_ai_pane(values, flags, ai)}

<h2 class="section">{_t("Evidence Keys")}</h2>
{_evidence_pane(values, secrets)}

<h2 class="section">{_t("Optional Integration")}</h2>
{_oast_pane(values, secrets)}

<div class="row" style="margin-top:16px"><button class="btn">{_t("Save")}</button></div>
</form>
<script>{script}</script>"""


def _runtime_pane(facts: list[tuple[str, str, str]]) -> str:
    rows = "".join(
        f"<tr><td><b>{_e(label)}</b></td><td class='mono'>{_e(value)}</td>"
        f"<td class='muted'>{_e(hint)}</td></tr>"
        for label, value, hint in facts
    )
    intro = _t(
        "Read-only. These come from the process environment (<code>.env</code>), are read "
        "at startup, and need a server restart to change — so they are shown here rather "
        "than made editable, which would offer a save button that quietly does nothing "
        "until the next boot."
    )
    footer = _t(
        "Secrets are never echoed here — only whether one is present. Keep tokens in "
        "<code>.env</code>, never in <code>engagement.json</code>."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
<div class="card"><div class="tblwrap"><table>
<tr><th>{_t("Setting")}</th><th>{_t("Current")}</th><th>{_t("Environment Variable")}</th></tr>{rows}
</table></div></div>
<p class="muted" style="margin-top:12px">{footer}</p>"""


def _advanced_pane(
    limits,
    runner_overrides: dict,
    ai_evidence: dict[str, object],
    jira_mode: str,
    jira_live: bool,
    jira_warning: str,
    jira_env: list[tuple[str, str, str]],
    jira_keys: list[str],
    runtime: list[tuple[str, str, str]],
    open_section: str = "runner",
) -> str:
    """The four panes a normal engagement never opens, collapsed by default.

    `open_section` is the *requested* tab name, so the four writers that still
    redirect to `?tab=runner` / `?tab=mcp` / `?tab=ai-evidence` land with the
    block they just saved already expanded — a flash message above four
    collapsed rows would otherwise read as "saved something, somewhere".
    """
    intro = _t("Everything here has a working default. Reference: "
               "<code>docs/configuration.md</code>.")
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
{_section("Runner Limits", "Timeouts and Request Caps",
          _runner_pane(limits, runner_overrides), open_section in ("runner", "advanced"))}
{_section("AI &amp; Evidence", "Analyzer, Evidence Keys — Writes to .env",
          _ai_evidence_pane(ai_evidence), open_section == "ai-evidence")}
{_section("Jira Connector (MCP)", "Live Server vs Offline Mock",
          _mcp_pane(jira_mode, jira_live, jira_warning, jira_env, jira_keys),
          open_section == "mcp")}
{_section("Runtime (.env)", "Read-Only · Restart to Change",
          _runtime_pane(runtime), open_section == "runtime")}"""
