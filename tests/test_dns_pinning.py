"""DNS pinning closes the TOCTOU gap between scope validation and the actual
connection: ScopeValidator resolves+checks a host's IP, and the runner must
connect to *that exact IP*, not let httpx/the OS re-resolve (which an
attacker controlling DNS with a short TTL could answer differently)."""

import socket

from app.execution.http_runner import _pin_dns


def test_pin_dns_rewrites_only_the_pinned_host(monkeypatch):
    seen = []

    def fake_getaddrinfo(node, *args, **kwargs):
        seen.append(node)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (node, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with _pin_dns("api.example.com", "203.0.113.9"):
        socket.getaddrinfo("api.example.com", 443)  # pinned host -> rewritten to the IP
        socket.getaddrinfo("other.example.com", 443)  # different host -> untouched

    assert seen == ["203.0.113.9", "other.example.com"]


def test_pin_dns_restores_the_previous_resolver_after_the_block(monkeypatch):
    def fake_getaddrinfo(node, *args, **kwargs):
        return []

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with _pin_dns("api.example.com", "203.0.113.9"):
        assert socket.getaddrinfo is not fake_getaddrinfo  # patched for the duration
    assert socket.getaddrinfo is fake_getaddrinfo  # restored exactly, not the real resolver


def test_pin_dns_is_a_no_op_without_a_pinned_ip(monkeypatch):
    def fake_getaddrinfo(node, *args, **kwargs):
        return []

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with _pin_dns("api.example.com", None):
        assert socket.getaddrinfo is fake_getaddrinfo
    assert socket.getaddrinfo is fake_getaddrinfo


def test_pin_dns_is_a_no_op_without_a_host(monkeypatch):
    def fake_getaddrinfo(node, *args, **kwargs):
        return []

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with _pin_dns(None, "203.0.113.9"):
        assert socket.getaddrinfo is fake_getaddrinfo
