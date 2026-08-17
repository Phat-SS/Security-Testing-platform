"""Isolated arbitrary-Python runner — OPT-IN, gated, off by default.

The platform's core principle is "never execute untrusted code." This runner is
the deliberate, narrow exception for PoCs whose logic the static transpiler
cannot express (computed values, crypto, multi-step flows). It exists so the
capability is available *safely and explicitly*, never by accident.

Layered gates, ALL required before a single line runs:
  1. ENABLE_PYTHON_RUNNER=true            — the operator turned it on.
  2. reviewed=True                        — a human explicitly reviewed THIS PoC.
  3. static validation passes             — no os.system/eval/subprocess/etc.
  4. an egress proxy is configured        — scope can only be enforced at the
     network layer for arbitrary code, so we refuse without one.
  5. running inside the sandbox container — HTTP_PROXY/HTTPS_PROXY env vars
     are a convention arbitrary code can trivially ignore (raw sockets,
     os.environ.clear(), ctypes, ...). A bare subprocess on the host is NOT a
     security boundary, so gate 4 alone is not load-bearing: this refuses to
     actually execute unless it detects it is running inside
     docker/Dockerfile.sandbox (INSIDE_SECURITY_SANDBOX=true), where
     non-root, a read-only FS, dropped capabilities, and a default-deny
     egress proxy are real, kernel-enforced boundaries the code cannot opt
     out of.

Even with all gates passed, execution happens in a separate process with a hard
timeout and captured, size-capped output.

IMPORTANT: a subprocess is NOT a security boundary on its own. A real
deployment MUST run this inside container isolation (Docker/gVisor) with a
network egress allowlist. This module enforces the gates and fails closed; it
does not pretend a subprocess equals a sandbox.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

from app.core.redaction import redact_text
from app.poc.transpiler import transpile_python


class PythonRunnerDisabled(Exception):
    """Raised when execution is attempted without all gates satisfied."""


@dataclass
class PythonRunResult:
    ran: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    refused_reason: str = ""
    flagged_constructs: list[str] = field(default_factory=list)


class PythonRunner:
    def __init__(self, settings=None, enabled: bool | None = None,
                 egress_proxy: str | None = None, sandboxed: bool | None = None) -> None:
        self._settings = settings
        self._enabled = (
            enabled if enabled is not None
            else os.getenv("ENABLE_PYTHON_RUNNER", "false").lower() == "true"
        )
        self._egress_proxy = egress_proxy or os.getenv("EGRESS_PROXY", "")
        self._sandboxed = (
            sandboxed if sandboxed is not None
            else os.getenv("INSIDE_SECURITY_SANDBOX", "false").lower() == "true"
        )
        self._timeout = float(os.getenv("PYTHON_RUNNER_TIMEOUT_S", "10"))
        self._max_output = int(os.getenv("PYTHON_RUNNER_MAX_OUTPUT", "100000"))

    def run(self, source: str, *, reviewed: bool = False) -> PythonRunResult:
        # Gate 1: globally enabled.
        if not self._enabled:
            return PythonRunResult(False, refused_reason=(
                "Python runner is disabled. Set ENABLE_PYTHON_RUNNER=true to allow "
                "reviewed PoCs to run in isolation."))

        # Gate 2: explicit per-PoC human review.
        if not reviewed:
            return PythonRunResult(False, refused_reason=(
                "This PoC has not been explicitly marked reviewed. Arbitrary code "
                "runs only after a human reviews it."))

        # Gate 3: static validation — reject obviously dangerous constructs.
        static = transpile_python(source)
        if not static.is_safe:
            return PythonRunResult(False, flagged_constructs=static.dangerous_constructs,
                                   refused_reason=(
                "Static validation rejected the PoC: dangerous constructs "
                f"{static.dangerous_constructs}. Not executed."))

        # Gate 4: scope for arbitrary code can only be enforced at the network
        # layer. Refuse unless an egress proxy (allowlist) is configured.
        if not self._egress_proxy:
            return PythonRunResult(False, refused_reason=(
                "No EGRESS_PROXY configured. Scope cannot be enforced for arbitrary "
                "code without a network egress allowlist; refusing to run."))

        # Gate 5: an egress proxy is a convention, not an enforcement
        # mechanism, on a bare host — arbitrary code can ignore HTTP_PROXY/
        # HTTPS_PROXY entirely. Refuse unless this process is itself running
        # inside the isolated sandbox container, where the boundary is real.
        if not self._sandboxed:
            return PythonRunResult(False, refused_reason=(
                "Not running inside the isolated sandbox container "
                "(INSIDE_SECURITY_SANDBOX is not set). An egress proxy alone is "
                "not a security boundary for arbitrary code on a bare host; "
                "build and run docker/Dockerfile.sandbox (see "
                "docker/docker-compose.yml) and run the platform from inside it."))

        return self._execute(source)

    def _execute(self, source: str) -> PythonRunResult:
        # Minimal environment; route all traffic through the egress allowlist
        # proxy so the process cannot reach off-scope hosts.
        env = {
            "PATH": os.getenv("PATH", ""),
            "HTTP_PROXY": self._egress_proxy,
            "HTTPS_PROXY": self._egress_proxy,
            "NO_PROXY": "",
            "SYSTEMROOT": os.getenv("SYSTEMROOT", ""),  # Windows needs this
        }
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "poc.py")
            with open(script, "w", encoding="utf-8") as f:
                f.write(source)
            try:
                # -I isolated mode: ignore env python vars, no user site, no cwd
                # on sys.path. -B: no bytecode. cwd is the throwaway tmp dir.
                proc = subprocess.run(
                    [sys.executable, "-I", "-B", script],
                    capture_output=True, text=True, timeout=self._timeout,
                    env=env, cwd=tmp,
                )
            except subprocess.TimeoutExpired:
                return PythonRunResult(True, exit_code=None,
                                       refused_reason="timeout", stdout="", stderr="timed out")

        return PythonRunResult(
            ran=True,
            exit_code=proc.returncode,
            stdout=redact_text(proc.stdout[: self._max_output]) or "",
            stderr=redact_text(proc.stderr[: self._max_output]) or "",
        )
