"""Runtime configuration. Everything security-relevant is env-driven so the
same binary is safe in a lab and in a locked-down engagement."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RunnerLimits:
    """Guardrails applied to every outbound request by the trusted runner."""

    timeout_s: float = 15.0
    max_response_bytes: int = 2_000_000  # cap stored/echoed body size
    max_redirects: int = 0  # auto-follow OFF; each hop re-validated explicitly
    max_requests_per_test: int = 25
    user_agent: str = "SecTestPlatform/0.1 (+authorized-testing)"


@dataclass(frozen=True)
class Settings:
    limits: RunnerLimits
    default_allow_private_ranges: bool

    @staticmethod
    def from_env() -> "Settings":
        return Settings(
            limits=RunnerLimits(
                timeout_s=float(os.getenv("RUNNER_TIMEOUT_S", "15")),
                max_response_bytes=int(os.getenv("RUNNER_MAX_RESPONSE_BYTES", "2000000")),
                max_redirects=int(os.getenv("RUNNER_MAX_REDIRECTS", "0")),
                max_requests_per_test=int(os.getenv("RUNNER_MAX_REQUESTS_PER_TEST", "25")),
            ),
            # Default-deny private ranges. Only a lab explicitly opts in.
            default_allow_private_ranges=os.getenv("ALLOW_PRIVATE_RANGES", "false").lower()
            == "true",
        )
