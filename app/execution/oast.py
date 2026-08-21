"""Generic out-of-band application security testing collaborator adapter."""

from __future__ import annotations

import os
import secrets
from typing import Protocol
from urllib.parse import quote, urlparse

import httpx


class OastVerifier(Protocol):
    def issue(self) -> tuple[str, str]: ...
    def observed(self, token: str) -> bool: ...


class HttpOastVerifier:
    """Small provider-neutral contract.

    `OAST_PUBLIC_URL/{token}` is injected into the target. The separately
    authenticated `OAST_POLL_URL/{token}` must return JSON `{"observed": true}`.
    No provider credential is ever put in a test case or callback URL.
    """

    def __init__(self, public_url: str, poll_url: str, api_token: str = "",
                 timeout_s: float = 5.0) -> None:
        self.public_url = public_url.rstrip("/")
        self.poll_url = poll_url.rstrip("/")
        self.api_token = api_token
        self.timeout_s = timeout_s
        public = urlparse(self.public_url)
        poll = urlparse(self.poll_url)
        if public.scheme != "https" or poll.scheme != "https" or not public.hostname or not poll.hostname:
            raise ValueError("OAST public and poll URLs must be absolute HTTPS URLs")

    def issue(self) -> tuple[str, str]:
        token = secrets.token_urlsafe(24)
        return token, f"{self.public_url}/{quote(token, safe='')}"

    def observed(self, token: str) -> bool:
        headers = {"Authorization": f"Bearer {self.api_token}"} if self.api_token else {}
        response = httpx.get(
            f"{self.poll_url}/{quote(token, safe='')}", headers=headers,
            timeout=self.timeout_s, follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
        return payload.get("observed") is True


def build_oast_verifier() -> HttpOastVerifier | None:
    public = os.getenv("OAST_PUBLIC_URL", "").strip()
    poll = os.getenv("OAST_POLL_URL", "").strip()
    if not public or not poll:
        return None
    return HttpOastVerifier(
        public, poll, os.getenv("OAST_API_TOKEN", "").strip(),
        float(os.getenv("OAST_TIMEOUT_S", "5")),
    )
