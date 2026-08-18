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
from dataclasses import dataclass, field
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
            "Add one under <b>Environments</b> — a name and a base URL such as "
            "<code>https://staging.example.com</code>.",
        ))
    elif active is None:
        checks.append(Check(
            "environments", "Target environment", FAIL,
            "No environment is marked as the default.",
            "Pick one under <b>Environments</b>. Runs use the default unless "
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
        hint = ("Turn on <b>Allow private ranges</b> under <b>Scope</b> if this "
                "is a local lab target." if "blocked range" in active.reason else
                "Fix the host, the DNS entry, or the block-list under <b>Scope</b>.")
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
                    "<code>Authorization</code> header under <b>Personas</b>.",
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
                "<b>Personas</b>, or point the "
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
                "generated tests fall back to guessed ids.",
            ))
        else:
            checks.append(Check(
                "persona_pair", "Two distinct identities", OK,
                f"{engagement.attacker} attacks objects owned by {engagement.victim}.",
            ))

    return Readiness(checks=checks, environments=envs)


def runtime_facts() -> list[tuple[str, str, str]]:
    """(label, value, hint) rows for settings that live in the environment and
    therefore need a server restart to change. Shown read-only next to the
    editable config so a tester can see the whole picture in one place instead
    of guessing which knob lives where."""
    def flag(name: str, default: str = "false") -> bool:
        return os.getenv(name, default).lower() == "true"

    ai_key = "set" if os.getenv("ANTHROPIC_API_KEY") else "not set"
    jira_live = bool(os.getenv("JIRA_MCP_URL") and os.getenv("JIRA_MCP_TOKEN"))
    return [
        ("AI analyzer",
         f"USE_AI={'true' if flag('USE_AI') else 'false'}, ANTHROPIC_API_KEY {ai_key}, "
         f"model {os.getenv('ANTHROPIC_MODEL', 'claude-sonnet-5')}",
         "Falls back to the deterministic analyzer whenever it is off or fails."),
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
        ("Private IP ranges (env default)",
         "allowed" if flag("ALLOW_PRIVATE_RANGES") else "blocked",
         "ALLOW_PRIVATE_RANGES in .env. The engagement's own Scope setting is "
         "what execution actually uses."),
        ("Database",
         os.getenv("DATABASE_URL", "sqlite:///sectest.db"),
         "DATABASE_URL."),
    ]
