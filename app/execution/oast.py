"""Out-of-band (OAST) collaborators: a generic HTTP-poll contract, and interactsh.

A blind SSRF, XXE or injection never shows in the response: the only proof is
the target reaching out to a host we control. These adapters hand the runner a
unique callback per execution and answer one question afterwards — did the
target call it?
"""

from __future__ import annotations

import atexit
import base64
import json
import logging
import os
import secrets
import string
import threading
import time
import uuid
from typing import Protocol
from urllib.parse import quote, urlparse

import httpx

logger = logging.getLogger(__name__)


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


class InteractshVerifier:
    """A ProjectDiscovery interactsh server as the collaborator.

    Registers an RSA public key once, then every execution gets its own
    subdomain `<correlation-id><nonce>.<server>`. The target calling it over
    DNS *or* HTTP counts as observed — DNS is what a blind SSRF behind an
    egress proxy usually manages, and the generic contract cannot see it.

    Interactions arrive encrypted (AES-CFB, its key wrapped with RSA-OAEP) and
    each poll returns them once, so every one seen is remembered for the life
    of this verifier. Nothing secret ever goes into the callback URL: the
    correlation id is random and the private key never leaves this process.

    Opt-in only (`INTERACTSH_SERVER`): registering sends this platform's
    public key to that server, which is a third party unless self-hosted.
    """

    _ALPHABET = string.ascii_lowercase + string.digits

    def __init__(self, server: str, token: str = "", timeout_s: float = 5.0,
                 wait_s: float = 5.0, client: httpx.Client | None = None) -> None:
        host = urlparse(server if "://" in server else f"https://{server}").hostname
        if not host:
            raise ValueError("INTERACTSH_SERVER must be a host name, e.g. oast.example.com")
        self.server = host
        self.token = token
        self.wait_s = max(0.0, wait_s)
        self._client = client or httpx.Client(timeout=timeout_s, follow_redirects=False)
        self._lock = threading.Lock()
        self._registered = False
        self._register_failed_at = 0.0
        self._seen: set[str] = set()
        self._correlation = "".join(secrets.choice(self._ALPHABET) for _ in range(20))
        self._secret = str(uuid.uuid4())
        self._key = None

    # -- protocol ---------------------------------------------------------

    def _headers(self) -> dict:
        return {"Authorization": self.token} if self.token else {}

    def _register(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        response = self._client.post(
            f"https://{self.server}/register", headers=self._headers(),
            json={"public-key": base64.b64encode(pem).decode(),
                  "secret-key": self._secret, "correlation-id": self._correlation},
        )
        response.raise_for_status()
        self._registered = True

    def _decrypt(self, aes_key_b64: str, item_b64: str) -> dict:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = self._key.decrypt(
            base64.b64decode(aes_key_b64),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        raw = base64.b64decode(item_b64)
        iv, body = raw[:16], raw[16:]
        plain = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor().update(body)
        return json.loads(plain.decode("utf-8", "replace"))

    def _poll(self) -> None:
        response = self._client.get(
            f"https://{self.server}/poll",
            params={"id": self._correlation, "secret": self._secret}, headers=self._headers(),
        )
        response.raise_for_status()
        payload = response.json() or {}
        aes_key = payload.get("aes_key")
        for item in payload.get("data") or []:
            try:
                interaction = self._decrypt(aes_key, item)
            except Exception:  # noqa: BLE001 - one bad record must not hide the rest
                logger.warning("interactsh: could not decrypt one interaction", exc_info=True)
                continue
            for field in ("unique-id", "full-id"):
                value = str(interaction.get(field) or "").lower()
                if value:
                    self._seen.add(value)

    # -- OastVerifier -----------------------------------------------------

    def issue(self) -> tuple[str, str]:
        with self._lock:
            if not self._registered:
                # A collaborator that just refused us is not asked again for
                # a minute: otherwise every test in the run generates a fresh
                # RSA key and hammers a server that is down.
                if time.monotonic() - self._register_failed_at < 60:
                    raise RuntimeError("interactsh registration failed recently; not retrying yet")
                try:
                    self._register()
                except Exception:
                    self._register_failed_at = time.monotonic()
                    raise
        nonce = "".join(secrets.choice(self._ALPHABET) for _ in range(13))
        token = f"{self._correlation}{nonce}"
        return token, f"https://{token}.{self.server}/"

    def observed(self, token: str) -> bool:
        token = token.lower()
        deadline = time.monotonic() + self.wait_s
        while True:
            with self._lock:
                self._poll()
                hit = any(seen == token or seen.startswith(token) for seen in self._seen)
            if hit or time.monotonic() >= deadline:
                return hit
            time.sleep(1.0)

    def close(self) -> None:
        if not self._registered:
            return
        try:
            self._client.post(f"https://{self.server}/deregister", headers=self._headers(),
                              json={"correlation-id": self._correlation, "secret-key": self._secret})
        except httpx.HTTPError:
            pass


_INTERACTSH: dict[tuple, InteractshVerifier] = {}
_INTERACTSH_LOCK = threading.Lock()


def _close_all() -> None:
    for verifier in list(_INTERACTSH.values()):
        verifier.close()


def build_oast_verifier():
    server = os.getenv("INTERACTSH_SERVER", "").strip()
    if server:
        # One registration per process and configuration, shared by every run:
        # each verifier holds an RSA key, an HTTP client and a server-side
        # registration, and building one per run leaked all three.
        key = (server, os.getenv("INTERACTSH_TOKEN", "").strip(),
               float(os.getenv("OAST_TIMEOUT_S", "5")), float(os.getenv("OAST_WAIT_S", "5")))
        with _INTERACTSH_LOCK:
            if key not in _INTERACTSH:
                if not _INTERACTSH:
                    atexit.register(_close_all)
                _INTERACTSH[key] = InteractshVerifier(*key)
            return _INTERACTSH[key]
    public = os.getenv("OAST_PUBLIC_URL", "").strip()
    poll = os.getenv("OAST_POLL_URL", "").strip()
    if not public or not poll:
        return None
    return HttpOastVerifier(
        public, poll, os.getenv("OAST_API_TOKEN", "").strip(),
        float(os.getenv("OAST_TIMEOUT_S", "5")),
    )
