"""Runtime configuration. Everything security-relevant is env-driven so the
same binary is safe in a lab and in a locked-down engagement."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class RunnerLimits:
    """Guardrails applied to every outbound request by the trusted runner."""

    timeout_s: float = 15.0
    max_response_bytes: int = 2_000_000  # cap stored/echoed body size
    max_requests_per_test: int = 25
    user_agent: str = "SecTestPlatform/0.1 (+authorized-testing)"


@dataclass(frozen=True)
class Settings:
    """Runner guardrails only.

    Whether a private/loopback address may be reached is deliberately *not*
    here. It is part of the engagement's scope block, which is the reviewable
    authorization artifact — an env var that could widen that boundary from
    outside the file a human signed off on is a backdoor, not a setting.
    """

    limits: RunnerLimits

    @staticmethod
    def from_env() -> "Settings":
        return Settings(
            limits=RunnerLimits(
                timeout_s=float(os.getenv("RUNNER_TIMEOUT_S", "15")),
                max_response_bytes=int(os.getenv("RUNNER_MAX_RESPONSE_BYTES", "2000000")),
                max_requests_per_test=int(os.getenv("RUNNER_MAX_REQUESTS_PER_TEST", "25")),
            ),
        )


def settings_with_overrides(overrides: dict) -> Settings:
    """Env-var settings with per-engagement runner limits layered on top.

    The .env file stays the machine-wide default; the Config UI writes the
    `runner` block in engagement.json for the knobs a tester wants to tune for
    one target (a slow staging host needing a longer timeout, say) without
    editing .env and restarting the server. An absent or unparseable value
    falls back to the env default rather than to zero — a zero timeout or a
    zero request cap would silently disable execution entirely.
    """
    base = Settings.from_env()
    if not overrides:
        return base
    fields = {
        "timeout_s": float,
        "max_response_bytes": int,
        "max_requests_per_test": int,
    }
    applied = {}
    for key, cast in fields.items():
        if key not in overrides or overrides[key] in (None, ""):
            continue
        try:
            value = cast(overrides[key])
        except (TypeError, ValueError):
            continue
        if value <= 0:
            continue
        applied[key] = value
    if not applied:
        return base
    return replace(base, limits=replace(base.limits, **applied))
