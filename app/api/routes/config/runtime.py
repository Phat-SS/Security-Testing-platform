"""Runner limits, and the AI/evidence settings written to .env.
"""

from __future__ import annotations

import logging
import os
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, Request

from app.api.deps import require
from app.api.runtime import state
from app.core import preflight
from app.core.auth import User
from app.core.engagement import (
    save_runner_limits,
)
from .shared import config_redirect

logger = logging.getLogger(__name__)


router = APIRouter()


@router.post("/config/runner")
async def save_runner_route(
    timeout_s: str = Form(""),
    max_response_bytes: str = Form(""),
    max_requests_per_test: str = Form(""),
    max_concurrent_tests: str = Form(""),
    reset: str = Form(""),
    user: User = Depends(require("tester")),
):
    if reset:
        save_runner_limits(state.engagement_path, {})
        state.reload_engagement()
        return config_redirect("runner", "Runner limits reset to the .env defaults")
    submitted = {
        "timeout_s": timeout_s,
        "max_response_bytes": max_response_bytes,
        "max_requests_per_test": max_requests_per_test,
        "max_concurrent_tests": max_concurrent_tests,
    }
    limits: dict[str, float] = {}
    for key, raw in submitted.items():
        raw = raw.strip()
        if not raw:
            continue  # blank means "fall back to the env var", not zero
        try:
            value = float(raw) if key == "timeout_s" else int(float(raw))
        except ValueError:
            return config_redirect("runner", f"{key} must be a number — nothing saved")
        if value < 0:
            return config_redirect("runner", f"{key} cannot be negative — nothing saved")
        limits[key] = value
    save_runner_limits(state.engagement_path, limits)
    state.reload_engagement()
    return config_redirect("runner", "Runner limits saved")


@router.post("/config/ai-evidence")
async def save_ai_evidence_route(
    request: Request,
    user: User = Depends(require("admin")),
):
    """Save AI/evidence runtime settings without ever echoing stored secrets."""
    form = await request.form()
    secret_keys = (
        "EVIDENCE_FINGERPRINT_KEY", "REPORT_SIGNING_KEY", "OAST_API_TOKEN",
    )
    public_keys = (
        "ANTHROPIC_MODEL", "AI_MAX_BUDGET_USD", "AI_EFFORT",
        "REPORT_SIGNING_KEY_ID", "OAST_PUBLIC_URL", "OAST_POLL_URL", "OAST_TIMEOUT_S",
    )
    changes: dict[str, str | None] = {
        key: "true" if form.get(key) else "false"
        for key in ("USE_AI", "AI_REQUIRE_PINNED_MODEL", "AUTH_COOKIE_SECURE")
    }

    for key in public_keys:
        value = str(form.get(key, "")).strip()
        changes[key] = value or None
    for key in secret_keys:
        value = str(form.get(key, "")).strip()
        clear = bool(form.get(f"clear_{key}"))
        if value and clear:
            return config_redirect("ai-evidence", f"Choose set or clear for {key}, not both")
        if value:
            changes[key] = value
        elif clear:
            changes[key] = None
        # blank without explicit clear deliberately preserves the secret

    def prospective(key: str) -> str:
        if key in changes:
            return changes[key] or ""
        return os.getenv(key, "")

    fingerprint = prospective("EVIDENCE_FINGERPRINT_KEY")
    if fingerprint and len(fingerprint) < 16:
        return config_redirect(
            "ai-evidence", "EVIDENCE_FINGERPRINT_KEY must be at least 16 characters"
        )
    signing = prospective("REPORT_SIGNING_KEY")
    if signing and len(signing) < 32:
        return config_redirect(
            "ai-evidence", "REPORT_SIGNING_KEY must be at least 32 characters"
        )

    public_url = prospective("OAST_PUBLIC_URL")
    poll_url = prospective("OAST_POLL_URL")
    if bool(public_url) != bool(poll_url):
        return config_redirect(
            "ai-evidence", "OAST public and poll URLs must be configured together"
        )
    for label, value in (("OAST_PUBLIC_URL", public_url), ("OAST_POLL_URL", poll_url)):
        parsed = urlsplit(value) if value else None
        if value and (parsed.scheme != "https" or not parsed.hostname):
            return config_redirect("ai-evidence", f"{label} must be an absolute HTTPS URL")

    model = prospective("ANTHROPIC_MODEL")
    if prospective("AI_REQUIRE_PINNED_MODEL") == "true" and not any(c.isdigit() for c in model):
        return config_redirect(
            "ai-evidence", "Pinned-model mode requires a versioned ANTHROPIC_MODEL"
        )
    budget = prospective("AI_MAX_BUDGET_USD")
    timeout = prospective("OAST_TIMEOUT_S")
    for key, raw in (("AI_MAX_BUDGET_USD", budget), ("OAST_TIMEOUT_S", timeout)):
        if not raw:
            continue
        try:
            if float(raw) <= 0:
                raise ValueError
        except ValueError:
            return config_redirect("ai-evidence", f"{key} must be a positive number")
    effort = prospective("AI_EFFORT")
    if effort and not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", effort):
        return config_redirect("ai-evidence", "AI_EFFORT contains unsupported characters")

    try:
        preflight.update_dotenv_values(
            changes, state.runtime_env_path, apply_to_environ=True
        )
        state.reload_ai_runtime()
    except (OSError, ValueError) as exc:
        return config_redirect(
            "ai-evidence", f"Runtime configuration was not saved: {type(exc).__name__}"
        )
    changed_names = sorted(changes)
    state.repo.audit(
        "runtime_config", actor=user.name,
        detail=f"Updated {len(changed_names)} allowlisted AI/evidence setting(s); values omitted.",
    )
    return config_redirect("ai-evidence", "AI and evidence configuration saved")
