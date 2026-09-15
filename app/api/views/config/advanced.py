"""Runner limits, the AI and evidence settings, the Jira connector, and the
read-only runtime facts.
"""

from __future__ import annotations



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
{field("timeout_s", _t("Request timeout (s)"), _t("Raise it for a slow staging host."), "0.5")}
{field("max_requests_per_test", _t("Max requests per test"), _t("Caps a single test's fan-out, race windows included."))}
{field("max_concurrent_tests", _t("Tests in flight at once"), _t("1 runs a plan one test at a time. Higher finishes a long plan faster, at proportionally higher request rate against the target — a blast-radius decision, so it is not raised for you."))}
{field("max_response_bytes", _t("Max response bytes"), _t("Body larger than this is truncated before storage."))}
</div>
<div style="margin-top:14px" class="row">
<button class="btn">{_t("Save limits")}</button>
<button class="btn ghost" name="reset" value="true">{_t("Reset to .env defaults")}</button>
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
    cls = "low" if jira_live else "med"
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
        f"<td><span class='pill {'low' if status == 'set' else 'med'}'>{_t(status.upper())}</span></td>"
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
<button class="btn ghost">{_t("Refresh token")}</button></form>
<form method="post" action="/config/mcp/jira/reconnect" style="margin:0">
<button class="btn">{_t("Reconnect")}</button></form>
</div>
</div>
</div>

<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>{_t("Environment variable")}</th><th>{_t("Status")}</th><th>{_t("Purpose")}</th></tr>{env_rows}
</table></div></div>
<p class="muted" style="margin-bottom:22px">{refresh_note}</p>

<h2 class="section">{_t("Other connectors")}</h2>
<div class="card pad">
<b>Postman</b> <span class="pill med" style="margin-left:6px">{_t("NOT CONFIGURED")}</span>
<div class="muted" style="margin-top:4px">{postman_note}</div>
</div>"""


def _ai_evidence_pane(config: dict[str, object]) -> str:
    values = config.get("values") or {}
    flags = config.get("flags") or {}
    secrets = config.get("secrets") or {}

    def checked(key: str) -> str:
        return "checked" if flags.get(key) else ""

    def value(key: str) -> str:
        return _e(values.get(key, ""))

    def secret_field(key: str, label: str, minimum: int, hint: str) -> str:
        configured = bool(secrets.get(key))
        status = (
            '<span class="pill low">CONFIGURED</span>'
            if configured else '<span class="pill med">NOT SET</span>'
        )
        placeholder = "Configured — leave blank to keep" if configured else "Not configured"
        field_id = f"secret-{key.lower()}"
        return f"""<div class="card pad" style="margin-bottom:10px">
<div class="row" style="justify-content:space-between;margin-bottom:8px">
<div><b>{_e(label)}</b> {status}</div><code>{_e(key)}</code></div>
<div class="row" style="align-items:flex-end">
<label class="field" style="flex:1"><span>New value</span>
<input id="{field_id}" type="password" name="{_e(key)}" autocomplete="new-password"
 minlength="{minimum}" placeholder="{_e(placeholder)}"></label>
<button class="btn ghost" type="button" onclick="generateRuntimeSecret('{field_id}',{max(32, minimum)})">Generate</button>
</div>
<label class="muted" style="display:flex;gap:6px;align-items:center;margin-top:8px">
<input type="checkbox" name="clear_{_e(key)}" value="true" style="width:auto">
Clear the stored value</label>
<div class="muted" style="margin-top:6px">{_e(hint)}</div></div>"""

    return f"""<p class="muted" style="margin:0 0 12px">
These settings are written to <code>.env</code> and applied immediately. Secret values are
never returned to the browser: blank keeps the current value; clearing requires the explicit
checkbox. This pane requires the <b>admin</b> role when authentication is enabled.</p>
<form method="post" action="/config/ai-evidence">

<h2 class="section">Claude runtime</h2>
<div class="card pad" style="margin-bottom:18px">
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px">
<label class="field"><span>Versioned model ID</span>
<input name="ANTHROPIC_MODEL" value="{value('ANTHROPIC_MODEL')}"
 placeholder="claude-sonnet-4-20260514"></label>
<label class="field"><span>Maximum budget per call (USD)</span>
<input type="number" min="0.01" step="0.01" name="AI_MAX_BUDGET_USD"
 value="{value('AI_MAX_BUDGET_USD')}" placeholder="1.00"></label>
<label class="field"><span>Reasoning effort</span>
<input name="AI_EFFORT" value="{value('AI_EFFORT')}" placeholder="high"></label>
</div>
<div class="row" style="margin-top:12px;gap:18px">
<label><input type="checkbox" name="USE_AI" value="true" style="width:auto" {checked('USE_AI')}> Enable Claude AI</label>
<label><input type="checkbox" name="AI_REQUIRE_PINNED_MODEL" value="true" style="width:auto" {checked('AI_REQUIRE_PINNED_MODEL')}> Require a versioned model ID</label>
</div></div>

<h2 class="section">Evidence and report integrity</h2>
{secret_field('EVIDENCE_FINGERPRINT_KEY', 'Evidence correlation HMAC key', 16,
              'HMACs identity values used for cross-persona correlation. Use a deployment-specific random key.')}
{secret_field('REPORT_SIGNING_KEY', 'Report manifest signing key', 32,
              'Signs report manifests. Production requires at least 32 characters and secret-manager backup.')}
<div class="card pad" style="margin-bottom:18px"><label class="field">
<span>Signing key ID</span><input name="REPORT_SIGNING_KEY_ID"
 value="{value('REPORT_SIGNING_KEY_ID')}" placeholder="prod-report-key-2026"></label></div>

<h2 class="section">OAST collaborator</h2>
<div class="card pad" style="margin-bottom:10px">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<label class="field"><span>Public callback base URL</span>
<input name="OAST_PUBLIC_URL" value="{value('OAST_PUBLIC_URL')}"
 placeholder="https://callbacks.example.test/c"></label>
<label class="field"><span>Authenticated polling base URL</span>
<input name="OAST_POLL_URL" value="{value('OAST_POLL_URL')}"
 placeholder="https://callbacks.example.test/api/events"></label>
</div><label class="field" style="margin-top:12px"><span>Polling timeout (seconds)</span>
<input type="number" min="0.1" step="0.1" name="OAST_TIMEOUT_S"
 value="{value('OAST_TIMEOUT_S')}" placeholder="5"></label></div>
{secret_field('OAST_API_TOKEN', 'OAST polling API token', 1,
              'Sent only to the polling endpoint; never injected into the target callback URL.')}

<h2 class="section">Browser session</h2>
<div class="card pad"><label>
<input type="checkbox" name="AUTH_COOKIE_SECURE" value="true" style="width:auto" {checked('AUTH_COOKIE_SECURE')}>
Set the browser session cookie only over HTTPS</label>
<div class="muted" style="margin-top:6px">Enable this for every HTTPS deployment. Local HTTP development cannot send a Secure cookie.</div></div>

<div class="row" style="margin-top:16px"><button class="btn">Save AI &amp; evidence configuration</button></div>
</form>
<script>
function generateRuntimeSecret(id, bytes) {{
  var data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  var raw = Array.from(data, function (b) {{ return String.fromCharCode(b); }}).join('');
  document.getElementById(id).value = btoa(raw).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}}
</script>"""


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
<tr><th>{_t("Setting")}</th><th>{_t("Current")}</th><th>{_t("Environment variable")}</th></tr>{rows}
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
    intro = _t(
        "Everything here already has a working default — a normal engagement never "
        "needs to open this tab. Full reference: <code>docs/configuration.md</code>."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
{_section("Runner limits", "timeouts and request caps",
          _runner_pane(limits, runner_overrides), open_section in ("runner", "advanced"))}
{_section("AI &amp; Evidence", "Claude runtime, signing keys, OAST — writes to .env",
          _ai_evidence_pane(ai_evidence), open_section == "ai-evidence")}
{_section("Jira connector (MCP)", "live server vs offline mock",
          _mcp_pane(jira_mode, jira_live, jira_warning, jira_env, jira_keys),
          open_section == "mcp")}
{_section("Runtime (.env)", "read-only; changing these needs a restart",
          _runtime_pane(runtime), open_section == "runtime")}"""
