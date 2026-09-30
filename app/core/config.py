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
    # How many approved tests may be in flight at once. 1 keeps a run exactly
    # sequential, which is the default because concurrency against someone's
    # API is request *rate*, and rate is a blast-radius decision for whoever
    # signed the authorization. Raising it is what makes a 300-test plan finish
    # in a minute instead of five; the evidence chain is unaffected either way
    # (see Orchestrator.execute).
    max_concurrent_tests: int = 1
    user_agent: str = "SecTestPlatform/0.1 (+authorized-testing)"
    # A dropped connection or a read timeout is noise, not a finding — but only
    # for a request nothing about resending is unsafe to repeat. Retrying is
    # gated to GET/HEAD/OPTIONS in the runner regardless of this count, so a
    # flaky target can't turn a retry into an extra POST/DELETE.
    retry_max_attempts: int = 2  # 1 = no retry; 2 = one retry
    retry_backoff_ms: int = 200


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
                max_concurrent_tests=int(os.getenv("RUNNER_MAX_CONCURRENT_TESTS", "1")),
                retry_max_attempts=int(os.getenv("RUNNER_RETRY_MAX_ATTEMPTS", "2")),
                retry_backoff_ms=int(os.getenv("RUNNER_RETRY_BACKOFF_MS", "200")),
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
        "max_concurrent_tests": int,
        "retry_max_attempts": int,
        "retry_backoff_ms": int,
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
