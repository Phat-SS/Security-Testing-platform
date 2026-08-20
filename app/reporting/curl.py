"""Render one captured execution as a copy-pasteable curl command.

The stored `CapturedRequest` is redacted for storage — real secret header
values are discarded (not merely hidden) the instant a request is captured
(see `core/redaction.py`: "fail closed, when in doubt, redact") and cannot be
recovered from the evidence itself.

This does NOT re-run the test to re-derive a fresh request. Doing that would
mean firing the test's setup/baseline steps again — real network calls with
real side effects (seeding data, capturing a victim's token) — merely to
produce a copyable string, which is not what a "copy" action should ever do.
Instead it takes the exact recorded method/url/body — the actual attack that
was sent — and patches back only the attacker persona's known auth header(s)
by name, resolved live from the vault. Any other value that happened to be
redacted (e.g. a password field inside the JSON body) stays masked; there is
no way to recover it once discarded.
"""

from __future__ import annotations

import shlex
from urllib.parse import urlsplit

from app.core.redaction import MASK
from app.schemas.execution import CapturedRequest
from app.vault.personas import Persona


def render_curl(request: CapturedRequest, persona: Persona | None) -> str:
    headers = dict(request.headers)
    if persona is not None:
        for name, value in persona.auth_headers.items():
            if headers.get(name) == MASK:
                headers[name] = value

    lines = [f"curl -sS -i -X {shlex.quote(request.method)} {shlex.quote(request.url)}"]

    # Pin to the exact IP the runner's scope validator resolved and connected
    # to, not whatever DNS answers at copy time — the same TOCTOU/rebinding
    # concern _pin_dns in http_runner.py exists for, applied to reproduction.
    if request.resolved_ip:
        parts = urlsplit(request.url)
        if parts.hostname:
            port = parts.port or (443 if parts.scheme == "https" else 80)
            lines.append(
                f"--resolve {shlex.quote(f'{parts.hostname}:{port}:{request.resolved_ip}')}"
            )

    for k, v in headers.items():
        lines.append(f"-H {shlex.quote(f'{k}: {v}')}")

    if request.body:
        lines.append(f"--data-raw {shlex.quote(request.body)}")

    return " \\\n  ".join(lines)
