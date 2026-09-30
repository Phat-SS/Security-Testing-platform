"""Readiness checks — "would a run work right now, and if not, why?"

The platform is default-deny by design: an unconfigured scope, a missing
persona or an unset target each stop a run cold. That is the correct behaviour,
but until now the *first* time a tester learned about it was a results table
where every row said BLOCKED, with no pointer to the setting that caused it.

This module answers the question before the run instead of after it, and it
answers it with the real code path — `ScopeValidator.validate_url` is the exact
function `HttpRunner` calls, so a host that passes here cannot be blocked at
send time for a scope reason, and a host that fails here reports the identical
sentence the execution log would have shown.

Every check is read-only. Nothing here sends a request to the target; the only
network operation is the DNS lookup the scope validator performs anyway.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from app.core.engagement import Engagement

# A check is one of three states rather than a bool: "warn" is for a setting
# that will not stop the run but will make the results less meaningful (an
# authenticated test with no credentials, a BOLA test with no victim-owned id),
# which is exactly the class of problem that otherwise gets discovered only
# when a report full of inconclusive PASSes has already been written.
OK = "ok"
WARN = "warn"
FAIL = "fail"

_STATE_RANK = {OK: 0, WARN: 1, FAIL: 2}


@dataclass
class Check:
    key: str
    label: str
    state: str
    detail: str
    # Markup we author ourselves (may contain <code>), never user input.
    hint_html: str = ""
    # When set, the panel renders a one-click POST that fixes this check.
    fix_action: str = ""
    fix_label: str = ""
    fix_fields: dict[str, str] = field(default_factory=dict)


@dataclass
class EnvironmentCheck:
    name: str
    url: str
    host: str
    is_active: bool
    state: str
    reason: str
    resolved_ip: str | None = None


@dataclass
class Readiness:
    checks: list[Check]
    environments: list[EnvironmentCheck]

    @property
    def state(self) -> str:
        worst = OK
        for c in self.checks:
            if _STATE_RANK[c.state] > _STATE_RANK[worst]:
                worst = c.state
        return worst

    @property
    def can_run(self) -> bool:
        return all(c.state != FAIL for c in self.checks)

    @property
    def n_blocking(self) -> int:
        return sum(1 for c in self.checks if c.state == FAIL)

    @property
    def n_warnings(self) -> int:
        return sum(1 for c in self.checks if c.state == WARN)


def host_of(url: str) -> str:
    """The hostname a base URL would be validated against, or "" if unparseable."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def check_environments(engagement: Engagement) -> list[EnvironmentCheck]:
    """Run every configured environment's base URL through the real scope
    validator. Results are cached per host within the call so a config with
    several environments on one host does a single DNS lookup."""
    seen: dict[str, tuple[bool, str, str | None]] = {}
    out: list[EnvironmentCheck] = []
    for name, url in engagement.environments.items():
        host = host_of(url)
        if not host:
            out.append(EnvironmentCheck(name, url, "", name == engagement.active_environment,
                                        FAIL, "URL has no host component."))
            continue
        if host not in seen:
            result = engagement.scope.validate_url(url)
            seen[host] = (result.allowed, result.reason, result.resolved_ip)
        allowed, reason, ip = seen[host]
        out.append(EnvironmentCheck(
            name=name,
            url=url,
            host=host,
            is_active=name == engagement.active_environment,
            state=OK if allowed else FAIL,
            reason=reason,
            resolved_ip=ip,
        ))
    return out


def evaluate(engagement: Engagement, engagement_path: str) -> Readiness:
    """The full pre-run checklist, ordered the way a tester hits the problems."""
    checks: list[Check] = []
    envs = check_environments(engagement)
    active = next((e for e in envs if e.is_active), None)

    # 1. Is there a config file at all? Everything else is downstream of this.
    if not os.path.exists(engagement_path):
        checks.append(Check(
            "config_file", "Engagement config", FAIL,
            f"No config file at {engagement_path}.",
            "Saving anything on this page creates it. The path comes from "
            "<code>ENGAGEMENT_CONFIG</code> in <code>.env</code>.",
        ))
    else:
        checks.append(Check(
            "config_file", "Engagement config", OK,
            f"Reading and writing {engagement_path}.",
        ))

    # 2. A target to aim at.
    if not engagement.environments:
        checks.append(Check(
            "environments", "Target environment", FAIL,
            "No environment is configured, so execution is disabled.",
            "Add one under <b>Target</b> — a name and a base URL such as "
            "<code>https://staging.example.com</code>.",
        ))
    elif active is None:
        checks.append(Check(
            "environments", "Target environment", FAIL,
            "No environment is marked as the default.",
            "Pick one under <b>Target</b>. Runs use the default unless "
            "another is chosen in the dropdown next to Run approved tests.",
        ))
    else:
        checks.append(Check(
            "environments", "Target environment", OK,
            f"{active.name} — {active.url}",
        ))

    # 3. Scope. This is the check that turns a whole run into BLOCKED rows, so
    #    it carries the one-click fix rather than only naming the file to edit.
    allowed = sorted(engagement.scope.policy.allowed_hosts)
    if active is None:
        pass
    elif active.state == OK:
        ip = f" (resolves to {active.resolved_ip})" if active.resolved_ip else ""
        checks.append(Check(
            "scope", "Scope authorization", OK,
            f"{active.host} is in the approved scope{ip}.",
        ))
    elif active.host and active.host not in engagement.scope.policy.allowed_hosts:
        checks.append(Check(
            "scope", "Scope authorization", FAIL,
            active.reason,
            "Every request is checked against <code>scope.allowed_hosts</code> "
            "before it is sent. Add this host only if the engagement actually "
            "authorizes testing it.",
            fix_action="/config/scope/allow-host",
            fix_label=f"Authorize {active.host}",
            fix_fields={"host": active.host},
        ))
    else:
        # In scope by name but still refused: a blocklist entry, a DNS failure,
        # or a private/link-local address with the lab escape hatch off. The
        # validator's own sentence is more precise than anything restated here.
        hint = ("Turn on <b>Allow private / loopback ranges</b> under <b>Target</b> "
                "if this is a local lab target." if "blocked range" in active.reason else
                "Fix the host, the DNS entry, or the block-list under <b>Target</b>.")
        checks.append(Check("scope", "Scope authorization", FAIL, active.reason, hint))

    if not allowed:
        checks.append(Check(
            "scope_empty", "Approved hosts", FAIL,
            "scope.allowed_hosts is empty — default-deny means nothing can run.",
            "Add at least the host of the environment you intend to test.",
        ))

    # 4. Personas. HttpRunner resolves the attacker persona before it even
    #    reaches the scope check, so a missing one raises rather than producing
    #    a BLOCKED row — it fails the run harder and less legibly than scope.
    names = engagement.vault.names()
    real = [n for n in names if n != "anonymous"]
    for role, persona_name in (("attacker", engagement.attacker), ("victim", engagement.victim)):
        if persona_name in names:
            persona = engagement.vault.get(persona_name)
            if persona.missing_env:
                # Checked before the empty-headers WARN below: withholding the
                # header is *why* it is empty, and "no credentials configured"
                # would point the tester at the Personas pane when the thing to
                # fix is one line of .env.
                unset = ", ".join(f"<code>{v}</code>" for v in persona.missing_env)
                checks.append(Check(
                    f"persona_{role}", f"{role.title()} identity", FAIL,
                    f"{persona_name}'s auth header references "
                    f"{len(persona.missing_env)} environment variable(s) that are "
                    f"not set, so the header is withheld.",
                    "The engagement file holds a <code>${VAR}</code> reference so the "
                    f"token itself stays in <code>.env</code>. Set {unset} there and "
                    "restart the server. The run is blocked rather than sent with a "
                    "credential that cannot authenticate — a 401 from an unset "
                    "variable is indistinguishable in a report from a 401 the "
                    "endpoint meant to return.",
                ))
            elif persona_name != "anonymous" and not persona.auth_headers:
                checks.append(Check(
                    f"persona_{role}", f"{role.title()} identity", WARN,
                    f"{persona_name} has no auth headers — its requests go out unauthenticated.",
                    "Authorization tests need a real, logged-in identity. Add an "
                    "<code>Authorization</code> header under <b>Identities</b>.",
                ))
            else:
                checks.append(Check(
                    f"persona_{role}", f"{role.title()} identity", OK,
                    f"{persona_name} ({persona.role})",
                ))
        else:
            checks.append(Check(
                f"persona_{role}", f"{role.title()} identity", FAIL,
                f"'{persona_name}' is not defined in the persona vault.",
                "Every generated test references personas by name. Add it under "
                "<b>Identities</b>, or point the "
                f"<b>{role}</b> role at one of: "
                + (", ".join(f"<code>{n}</code>" for n in real) or "<i>none defined yet</i>"),
            ))

    if len(real) < 2:
        checks.append(Check(
            "persona_pair", "Two distinct identities", WARN,
            f"{len(real)} persona(s) defined besides anonymous.",
            "BOLA/BFLA testing means \"identity A reaches identity B's object\" — "
            "that needs two real accounts. With fewer, those categories can only "
            "be probed unauthenticated.",
        ))
    elif engagement.attacker == engagement.victim:
        checks.append(Check(
            "persona_pair", "Two distinct identities", WARN,
            f"Attacker and victim are both '{engagement.attacker}'.",
            "A persona reaching its own object is authorized behaviour, so BOLA "
            "results will be inconclusive. Point them at different personas.",
        ))
    else:
        victim = engagement.vault.get(engagement.victim) if engagement.victim in names else None
        if victim is not None and not victim.owns:
            checks.append(Check(
                "persona_pair", "Two distinct identities", WARN,
                f"{engagement.victim} has no owned object ids.",
                "BOLA cases are built by pointing the attacker at an id the victim "
                "owns (e.g. <code>customer_id=2002</code>). Without one the "
                "generated tests fall back to guessed ids — set one under <b>Identities</b>.",
            ))
        else:
            checks.append(Check(
                "persona_pair", "Two distinct identities", OK,
                f"{engagement.attacker} attacks objects owned by {engagement.victim}.",
            ))

    # Only when a session cookie is actually issued. With auth off the login
    # route refuses every key and no cookie is ever set, so a warning about its
    # flags would be about a cookie that does not exist.
    if os.getenv("AUTH_ENABLED", "false").lower() == "true":
        cookie = session_cookie_state()
        if cookie["secure"]:
            why = ("PLATFORM_BASE_URL is HTTPS" if cookie["https_base"]
                   else "AUTH_COOKIE_SECURE=true")
            checks.append(Check(
                "session_cookie", "Login session cookie", OK,
                f"Marked Secure ({why}).",
            ))
        else:
            checks.append(Check(
                "session_cookie", "Login session cookie", WARN,
                "Not marked Secure — it will also be sent over plain HTTP.",
                "Turn this on for any deployment reachable over HTTPS. Leave it "
                "off for local HTTP development, where a Secure cookie cannot be "
                "sent at all and would lock you out of your own login.",
                fix_action="/config/session-cookie",
                fix_label="Mark the cookie Secure",
                fix_fields={"secure": "true"},
            ))

    return Readiness(checks=checks, environments=envs)


def jira_env_facts() -> list[tuple[str, str, str]]:
    """(env var, status, hint) rows for the Jira MCP connector pane — presence
    only, never the value, so this is safe to render even when live."""
    def present(name: str) -> str:
        return "set" if os.getenv(name) else "not set"

    return [
        ("JIRA_MCP_URL", present("JIRA_MCP_URL"),
         "Streamable-HTTP endpoint, e.g. https://mcp.atlassian.com/v1/mcp."),
        ("JIRA_CLOUD_ID", present("JIRA_CLOUD_ID"),
         "From the MCP server's getAccessibleAtlassianResources tool."),
        ("JIRA_MCP_TOKEN", present("JIRA_MCP_TOKEN"),
         "OAuth access token. Short-lived — refresh via npx mcp-remote + npm run jira:token."),
        ("JIRA_SITE_URL", present("JIRA_SITE_URL"),
         "Human browse URL — powers the \"Open ticket\" link after posting a comment."),
    ]


def parse_dotenv(path: str) -> dict[str, str]:
    """The KEY=VALUE pairs in a .env file, or {} when it does not exist.

    Minimal by design (optional quotes, '#' comments) — this only needs to
    mirror what scripts/security-ui.js parses, not be a general-purpose dotenv
    implementation. Last occurrence of a key wins, matching both that launcher
    and docker-compose's own env_file handling.
    """
    if not os.path.exists(path):
        return {}
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key:
                values[key] = value
    return values


def load_dotenv(path: str = ".env") -> list[str]:
    """Nạp .env vào process này *một lần lúc khởi động*, biến shell thắng file.

    Without this, only `npm run security:ui` (which parses .env in Node before
    spawning uvicorn) and docker-compose (`env_file:`) ever saw the file — a
    plain `uvicorn app.api.main:app` or `python -m app.cli` started with an
    empty configuration and reported it as a readiness failure about personas
    and Jira, never as "the file you edited was not read". Precedence matches
    every other dotenv implementation: a variable already present in the
    environment is left alone, so a shell/CI/compose value still overrides.

    Returns the names of the keys it applied (values are never logged).
    """
    values = parse_dotenv(path)
    applied = [key for key in values if key not in os.environ]
    for key in applied:
        os.environ[key] = values[key]
    return applied


def reload_dotenv(path: str = ".env") -> None:
    """Re-read .env over the top of the current environment so Reconnect can
    pick up a freshly refreshed token without a server restart.

    Unlike `load_dotenv` this deliberately *overrides* what is already set —
    it exists precisely to replace a token the process is holding.
    """
    os.environ.update(parse_dotenv(path))


def newest_mcp_auth_token(base: Path, newer_than: float | None = None) -> Path | None:
    """Newest *_tokens.json under ~/.mcp-auth/mcp-remote-*/ — the cache
    mcp-remote's OAuth flow writes to. `newer_than` (a time.time() value)
    restricts this to a file written after that moment, so a stale cached
    token lying around from a previous login isn't mistaken for a completed
    fresh one."""
    if not base.is_dir():
        return None
    candidates = [p for p in base.glob("*/*_tokens.json") if p.is_file()]
    if newer_than is not None:
        candidates = [p for p in candidates if p.stat().st_mtime > newer_than]
    return max(candidates, key=lambda p: p.stat().st_mtime, default=None)


def write_dotenv_value(key: str, value: str, path: str = ".env") -> None:
    """Set KEY=value in .env in place — replacing an existing line (commented
    or not) if present, else appending. Mirrors scripts/jira-token.js's own
    rewrite so the two stay interchangeable. The value is never logged.

    *Every* occurrence of the key collapses onto the first one. Replacing only
    the first and leaving the rest is worse than not writing at all: .env is
    last-one-wins (see reload_dotenv), so a duplicate further down keeps the
    stale value winning and a freshly refreshed token gets written and then
    ignored — which is exactly how a "Refresh token" click can appear to do
    nothing at all.
    """
    update_dotenv_values({key: value}, path)


def update_dotenv_values(
    values: dict[str, str | None], path: str = ".env", *, apply_to_environ: bool = False
) -> None:
    """Atomically update several .env keys; ``None`` removes a key.

    Newlines are refused so a submitted secret cannot smuggle additional
    environment assignments into the file. Every duplicate occurrence is
    collapsed, matching ``write_dotenv_value``'s historical contract.
    """
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"Invalid environment key: {key!r}")
        if value is not None and ("\r" in value or "\n" in value):
            raise ValueError(f"{key} must be a single line")

    # Anchored per line, and the '=' is required: a `#  KEY  some prose`
    # comment describing the key is documentation, not a line to overwrite.
    text = Path(path).read_text(encoding="utf-8") if os.path.exists(path) else ""
    newline = "\r\n" if "\r\n" in text else "\n"
    out: list[str] = []
    written: set[str] = set()
    patterns = {
        key: re.compile(rf"^#?[ \t]*{re.escape(key)}=") for key in values
    }
    for raw in text.splitlines():
        matched = next((key for key, pattern in patterns.items() if pattern.match(raw)), None)
        if matched is None:
            out.append(raw)
        elif matched not in written:
            value = values[matched]
            if value is not None:
                out.append(f"{matched}={value}")
            written.add(matched)
        # duplicates and explicitly removed keys are omitted
    for key, value in values.items():
        if key not in written and value is not None:
            out.append(f"{key}={value}")

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(newline.join(out) + newline, encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)  # holds tokens; no-op on Windows ACLs
    except OSError:
        pass
    os.replace(temporary, destination)

    if apply_to_environ:
        # Runtime UI saves must be effective immediately. Other callers (most
        # notably the Jira token writer) already perform an explicit reload;
        # mutating the process implicitly here would leak state across tools
        # and tests that only intended to edit a file.
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def ai_evidence_config_state() -> dict[str, object]:
    """UI-safe runtime state. Secret values are reduced to booleans here."""
    secret_keys = (
        "EVIDENCE_FINGERPRINT_KEY", "REPORT_SIGNING_KEY", "OAST_API_TOKEN",
    )
    public_keys = (
        "ANTHROPIC_MODEL", "AI_MAX_BUDGET_USD", "AI_EFFORT",
        "REPORT_SIGNING_KEY_ID", "OAST_PUBLIC_URL", "OAST_POLL_URL", "OAST_TIMEOUT_S",
    )
    return {
        "secrets": {key: bool(os.getenv(key)) for key in secret_keys},
        "values": {key: os.getenv(key, "") for key in public_keys},
        "flags": {
            key: os.getenv(key, "false").lower() == "true"
            # AUTH_COOKIE_SECURE is deliberately NOT here. It is a login-session
            # setting that only ever sat in this pane because it also lives in
            # .env, and it is now a readiness check with its own writer — see
            # `session_cookie_state()` below.
            for key in ("USE_AI", "AI_REQUIRE_PINNED_MODEL")
        },
        "ai": claude_cli_state(),
    }


def claude_cli_state() -> dict[str, object]:
    """What the AI path is actually bound to right now.

    There is no Anthropic API key anywhere in this platform: `ClaudeLLM` shells
    out to the operator's own `claude` CLI, so the model, the login and the
    billing are whichever ones their Claude Code is already using. The pane used
    to present a model box with a versioned placeholder, which read as "you must
    pin a model here" — the opposite of the truth, and the placeholder had gone
    stale besides.

    The default model is reported as a description rather than resolved: naming
    it would mean running the CLI on every config page load.
    """
    import shutil

    from app.analysis.staged import ClaudeLLM

    cli = os.environ.get("CLAUDE_CLI_PATH", "claude")
    # No "enabled" here: USE_AI is already in `flags`, and two places reporting
    # one switch is how they come to disagree.
    return {
        "found": ClaudeLLM.is_available(),
        "path": shutil.which(cli) or cli,
        "pinned_model": os.getenv("ANTHROPIC_MODEL", "").strip(),
    }


def session_cookie_state() -> dict[str, object]:
    """Whether the login cookie is marked `Secure`, and by what.

    Two signals set it (see routes/auth.py): the explicit flag, or a
    PLATFORM_BASE_URL that is already HTTPS. Reporting only the flag would call
    a correctly-configured HTTPS deployment misconfigured.
    """
    flag = os.getenv("AUTH_COOKIE_SECURE", "").lower() == "true"
    https_base = os.getenv("PLATFORM_BASE_URL", "").lower().startswith("https://")
    return {"flag": flag, "https_base": https_base, "secure": flag or https_base}


def runtime_facts() -> list[tuple[str, str, str]]:
    """(label, value, hint) rows for settings that live in the environment and
    therefore need a server restart to change. Shown read-only next to the
    editable config so a tester can see the whole picture in one place instead
    of guessing which knob lives where."""
    def flag(name: str, default: str = "false") -> bool:
        return os.getenv(name, default).lower() == "true"

    from app.analysis.staged import ClaudeLLM

    cli_status = "found" if ClaudeLLM.is_available() else "not found"
    model_desc = os.getenv("ANTHROPIC_MODEL") or "session default"
    jira_live = bool(os.getenv("JIRA_MCP_URL") and os.getenv("JIRA_MCP_TOKEN"))
    return [
        ("AI analyzer",
         f"USE_AI={'true' if flag('USE_AI') else 'false'}, claude CLI {cli_status}, "
         f"model {model_desc}",
         "Runs `claude -p` under the operator's own Claude Code login (no "
         "separate API key) and falls back to the deterministic analyzer "
         "whenever it is off, the CLI is missing, or it fails."),
        ("Jira connector",
         "live MCP" if jira_live else "offline mock",
         "Needs JIRA_MCP_URL + JIRA_CLOUD_ID + JIRA_MCP_TOKEN. Tokens stay in "
         "the environment — never in engagement.json or a report."),
        ("Multi-user auth",
         "on" if flag("AUTH_ENABLED") else "off (single-user local admin)",
         "AUTH_ENABLED + AUTH_USERS_CONFIG."),
        ("Arbitrary-Python PoC runner",
         "enabled" if flag("ENABLE_PYTHON_RUNNER") else "disabled",
         "Off by default. Requires an isolated sandbox container and an egress "
         "proxy — the app itself is not a boundary for arbitrary code."),
        ("Database",
         os.getenv("DATABASE_URL", "sqlite:///sectest.db"),
         "DATABASE_URL."),
    ]
