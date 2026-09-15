"""Named target URLs, and the one-submit quick setup.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
)

from app.api import views
from app.api.deps import require
from app.api.runtime import state
from app.core import preflight
from app.core.auth import User
from app.core.engagement import (
    allow_host,
    delete_environment,
    normalize_environment_name,
    save_environment,
    save_identities,
    save_persona,
    set_active_environment,
)
from .shared import config_redirect

logger = logging.getLogger(__name__)


router = APIRouter()


@router.post("/config/environments")
async def save_environment_route(
    name: str = Form(...),
    url: str = Form(...),
    make_active: bool = Form(False),
    authorize_host: bool = Form(False),
    user: User = Depends(require("tester")),
):
    url = url.strip().rstrip("/")
    normalized = normalize_environment_name(name)
    if normalized is None:
        return HTMLResponse(
            views.error_page(
                "Invalid environment name",
                f"{name.strip()!r} is not a valid environment name.",
                "Spaces are fine — but it cannot be blank, longer than 64 characters, "
                "or contain <code>/ &#92; ? # % &amp; ; : &quot; ' &lt; &gt; | *</code> "
                "(e.g. <code>dev</code>, <code>staging</code>, <code>DEV_BMW AU</code>).",
                back_href="/config?tab=target", back_label="← Back to target",
            ),
            status_code=400,
        )
    name = normalized
    if not (url.startswith("http://") or url.startswith("https://")):
        return HTMLResponse(
            views.error_page(
                "Invalid URL",
                f"{url!r} is not a valid base URL.",
                "It must start with <code>http://</code> or <code>https://</code>.",
                back_href="/config?tab=target", back_label="← Back to target",
            ),
            status_code=400,
        )
    save_environment(state.engagement_path, name, url, make_active=make_active)
    flash = f"Saved {name}"
    # Adding the URL without authorizing its host is the exact combination that
    # produces an all-BLOCKED run, so the form offers both in one step — opt-in,
    # never implied, since this is the authorization boundary.
    host = preflight.host_of(url)
    if authorize_host and host:
        allow_host(state.engagement_path, host)
        flash += f" and authorized {host}"
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash={quote(flash, safe='')}", status_code=303)


@router.post("/config/environments/{name}/delete")
async def delete_environment_route(name: str, user: User = Depends(require("tester"))):
    delete_environment(state.engagement_path, name)
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash=Removed+{quote(name, safe='')}",
                            status_code=303)


@router.post("/config/environments/{name}/activate")
async def activate_environment_route(name: str, user: User = Depends(require("tester"))):
    set_active_environment(state.engagement_path, name)
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash={quote(name + ' is now the default', safe='')}",
                            status_code=303)


# The token variable names the quick setup writes. They match
# config/engagement.example.json and .env.example, so a config produced here and
# one copied from the examples are the same shape.
_QUICK_SETUP_VARS = {"agent_A": "PERSONA_A_TOKEN", "agent_B": "PERSONA_B_TOKEN"}


@router.post("/config/quick-setup")
async def quick_setup_route(
    env_name: str = Form("staging"),
    url: str = Form(...),
    attacker_token: str = Form(...),
    victim_token: str = Form(...),
    owns_key: str = Form("customer_id"),
    owns_value: str = Form(""),
    user: User = Depends(require("admin")),
):
    """Everything an empty engagement needs, written in one submit.

    Admin rather than tester because it writes credentials to .env, the same
    reason /config/ai-evidence does. The order matters: the tokens land in the
    environment *before* the personas that reference them are saved, so the
    readiness panel this redirects to evaluates the finished state rather than
    reporting two unset variables it is about to be given.
    """
    raw_env_name = env_name.strip()
    env_name = normalize_environment_name(env_name)
    url = url.strip().rstrip("/")
    owns_key = owns_key.strip()
    owns_value = owns_value.strip()

    def fail(message: str) -> RedirectResponse:
        return config_redirect("readiness", message)

    if env_name is None:
        return fail(
            f"{raw_env_name or '(blank)'} is not a valid environment name — "
            "spaces are fine, but not a slash, backslash, or any of ? # % & ; : \" ' < > | * "
            "and no longer than 64 characters"
        )
    if not (url.startswith("http://") or url.startswith("https://")):
        return fail("The base URL must start with http:// or https://")
    host = preflight.host_of(url)
    if not host:
        return fail("That base URL has no hostname")
    if not attacker_token.strip() or not victim_token.strip():
        return fail("Both tokens are required — an unset one blocks every run anyway")

    try:
        preflight.update_dotenv_values(
            {
                _QUICK_SETUP_VARS["agent_A"]: attacker_token.strip(),
                _QUICK_SETUP_VARS["agent_B"]: victim_token.strip(),
            },
            state.runtime_env_path,
            apply_to_environ=True,
        )
    except (OSError, ValueError) as exc:
        # ValueError here means a token with a newline in it, which would have
        # smuggled extra assignments into .env. Nothing is written on either.
        return fail(f"The tokens were not saved: {type(exc).__name__}")

    save_environment(state.engagement_path, env_name, url, make_active=True)
    allow_host(state.engagement_path, host)
    for name, variable in _QUICK_SETUP_VARS.items():
        save_persona(
            state.engagement_path,
            name=name,
            auth_headers={"Authorization": f"Bearer ${{{variable}}}"},
            role="user",
            owns=({owns_key: owns_value} if name == "agent_B" and owns_key and owns_value else {}),
        )
    save_identities(state.engagement_path, "agent_A", "agent_B")
    state.reload_engagement()
    state.repo.audit(
        "quick_setup", actor=user.name,
        detail=f"Created environment {env_name} ({host}), personas agent_A/agent_B; token values omitted.",
    )
    return config_redirect(
        "readiness", f"Engagement created — {env_name} authorized, agent_A attacks agent_B"
    )
