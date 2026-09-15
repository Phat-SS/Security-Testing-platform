"""Turning an exception into something a person can act on.

Each of these maps a failure to a (headline, hint) pair for `views.error_page`.
They live together because they share one rule: never a bare 500, and never a
stack trace on its own — the hint names the setting or the step that fixes it.

Moved verbatim out of `main.py` with the routes that raise into them.
"""

from __future__ import annotations

import html

from app.api.runtime import state
from app.core import preflight  # noqa: F401  (kept for the scope hints below)
from app.mcp import available_issue_keys


def import_error(issue_key: str, exc: Exception) -> tuple[str, str]:
    """Map an import failure to (headline, hint). Never a bare 500.

    KeyError is the "no such issue" contract shared by the mock and the live
    client; ValueError comes from parse_issue_ref; RuntimeError is a
    misconfigured live connector (missing `mcp` package, bad headers).
    """
    keys = available_issue_keys(state.jira)
    if isinstance(exc, ValueError):
        return (
            f"{issue_key!r} is not a valid Jira issue reference.",
            "Use a key like <code>CRM-1234</code>, or paste a Jira URL "
            "(<code>https://…/browse/CRM-1234</code>).",
        )
    if isinstance(exc, KeyError):
        if keys:
            listed = ", ".join(f"<code>{html.escape(k)}</code>" for k in keys)
            return (
                f"Issue {issue_key} does not exist in the offline mock Jira.",
                f"Available sample issues: {listed}. To import your own tickets, "
                "point the platform at a real Jira MCP server "
                "(<code>JIRA_MCP_URL</code> + <code>JIRA_CLOUD_ID</code> + "
                "<code>JIRA_MCP_TOKEN</code>).",
            )
        return (
            f"Jira returned no issue for {issue_key}.",
            "Check the key spelling, the configured cloud id, and that the "
            "token has access to that project.",
        )
    if isinstance(exc, RuntimeError):
        return (
            f"The Jira connector is not usable: {exc}",
            "This is a configuration problem, not a bad issue key.",
        )
    return (
        f"Import of {issue_key} failed: {type(exc).__name__}: {exc}",
        "See the server log for the full traceback.",
    )


def comment_error(issue_key: str, exc: Exception) -> tuple[str, str]:
    """Map a post-to-Jira failure to (headline, hint). Never a bare 500.

    Same exception contract as _import_error: KeyError means the issue is
    unknown to the connector (the mock's fixed sample set, or a real key the
    live token can't see), RuntimeError is a misconfigured live connector.
    """
    if isinstance(exc, KeyError):
        return (
            f"Jira rejected the comment: unknown issue {issue_key}.",
            "The offline mock only accepts its sample issue keys "
            f"({', '.join(f'<code>{html.escape(k)}</code>' for k in available_issue_keys(state.jira))}). "
            "To post to a real ticket, configure a live Jira MCP server "
            "(<code>JIRA_MCP_URL</code> + <code>JIRA_CLOUD_ID</code> + "
            "<code>JIRA_MCP_TOKEN</code>).",
        )
    if isinstance(exc, RuntimeError):
        return (
            f"The Jira connector is not usable: {exc}",
            "This is a configuration problem (missing `mcp` package, bad "
            "headers, or an unreachable MCP server), not a bad comment.",
        )
    return (
        f"Posting to {issue_key} failed: {type(exc).__name__}: {exc}",
        "See the server log for the full traceback.",
    )


def execute_error(base_url: str, exc: Exception) -> tuple[str, str]:
    """Map an execution failure to (headline, hint). Never a bare 500.

    Scope violations on a per-test basis are already handled inside
    HttpRunner.run() as a BLOCKED verdict, not an exception — this is mostly a
    backstop for genuinely unexpected errors (e.g. a malformed request the
    transpiler let through). The one *expected* exception is a KeyError from
    PersonaVault.get(), which fires when the attacker/victim names point at
    personas the vault does not hold: HttpRunner.run() resolves the persona
    before scope is even checked, so it lands here rather than as a BLOCKED
    verdict. The readiness panel flags exactly this ahead of a run, so this
    path is now the case where someone ran before looking at it.
    """
    if isinstance(exc, KeyError):
        # str(KeyError("x")) renders as "'x'" (single quotes from repr, not
        # the double quotes this used to strip) — strip either.
        detail = str(exc).strip("'\"")
        return (
            f"Running tests against {base_url} failed: {detail}",
            "Generated tests reference identities by name, and this one is not "
            "in the persona vault. Add it under "
            "<a href='/config?tab=identities'>Configuration &rarr; Identities</a> "
            "(name, auth headers, and the object ids it owns), or point the "
            "attacker/victim roles at personas that already exist. "
            "<a href='/config'>Readiness</a> lists every setting a run needs "
            "before you start one.",
        )
    return (
        f"Running tests against {base_url} failed: {type(exc).__name__}: {exc}",
        "See the server log for the full traceback.",
    )
