"""Scope validator — the single most important safety control in the platform.

A pentest tool that can be aimed anywhere is a weapon. Every outbound request
MUST pass through here first. The validator answers one question: *is it safe
and authorized to send a request to this host right now?*

Two properties that a naive hostname allow/block-list does NOT give you, and
that this module does:

1. DNS-aware blocking. `evil.com` can resolve to 169.254.169.254 (cloud
   metadata) or 127.0.0.1. We resolve the host and check the *IP*, not just the
   name. This defeats the classic SSRF bypass.

2. IP pinning. We return the exact IP we validated so the caller can pin the
   connection to it. Otherwise an attacker can pass validation with a benign
   IP, then have DNS return an internal IP on the real connection
   (DNS rebinding / TOCTOU).

Redirects are never auto-followed by the runner (a 302 is captured and
evaluated as-is), because a 302 to an internal host is the same attack
wearing a hat and the HTTP client re-resolving DNS to chase it would bypass
this validator entirely. See `HttpRunner._send` in `execution/http_runner.py`.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeResult:
    allowed: bool
    host: str
    resolved_ip: str | None
    reason: str

    def raise_if_blocked(self) -> None:
        if not self.allowed:
            raise ScopeViolation(self.reason)


class ScopeViolation(Exception):
    """Raised when a request target is outside the approved scope."""


# IP ranges that are never legitimate pentest targets over the public runner.
# link-local 169.254.0.0/16 covers the cloud metadata endpoint 169.254.169.254.
_ALWAYS_BLOCK_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + metadata
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),  # unique local
    ipaddress.ip_network("0.0.0.0/8"),
    # Ranges that are not public unicast but are not RFC1918 either. CGNAT is
    # where some clouds put metadata (Alibaba 100.100.100.200) and carrier-grade
    # NATs put internal services; the rest are never a legitimate target.
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved + broadcast
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
    ipaddress.ip_network("2002::/16"),  # 6to4 (embeds an arbitrary IPv4)
    ipaddress.ip_network("2001::/32"),  # Teredo (embeds an arbitrary IPv4)
]

# Ports reachable without an explicit allowance. Any other port on an allowed
# host could be SSH/Redis/Elasticsearch, so it must be named on purpose.
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass
class ScopePolicy:
    """The authorized testing scope. Loaded per engagement, never hardcoded.

    allowed_hosts: exact hostnames the tester is authorized to attack.
    allow_private_ranges: escape hatch for local labs (e.g. a demo target on
        127.0.0.1). Off by default — turning it on is an explicit, logged
        decision, never the default.
    allowed_ports: ports other than 80/443 the tester may reach. Lab mode
        (allow_private_ranges) waives this, since a demo API on :8100 is the
        whole point of it.
    """

    allowed_hosts: set[str] = field(default_factory=set)
    blocked_hosts: set[str] = field(default_factory=set)
    allow_private_ranges: bool = False
    allowed_ports: set[int] = field(default_factory=set)

    def with_allowed(self, *hosts: str) -> "ScopePolicy":
        return ScopePolicy(
            allowed_hosts=self.allowed_hosts | set(hosts),
            blocked_hosts=self.blocked_hosts,
            allow_private_ranges=self.allow_private_ranges,
            allowed_ports=self.allowed_ports,
        )


# IPv6 /96 prefixes known to carry a plain IPv4 address in their low 32 bits.
# For a /96 prefix the embedded address occupies the address exactly (no
# reserved "u" octet, unlike the shorter RFC 6052 prefixes), so extracting it
# is a straight bitmask — no per-prefix special-casing needed beyond listing
# the prefixes themselves.
_IPV4_EMBEDDING_NETS = [
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped (RFC 4291 2.5.5.2)
    ipaddress.ip_network("::/96"),  # IPv4-compatible, deprecated (RFC 4291 2.5.5.1)
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 well-known prefix (RFC 6052)
]


def _embedded_ipv4_addresses(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """Every IPv4 address `ip` carries in its low 32 bits, under any of the
    known embedding prefixes it happens to fall in (usually zero or one)."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    found = []
    for net in _IPV4_EMBEDDING_NETS:
        if ip in net:
            found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


# Injectable resolver so tests are deterministic and don't hit real DNS.
Resolver = "callable(str) -> str"


def _default_resolver(host: str) -> list[str]:
    """Resolve a hostname to every distinct IP string. Raises socket.gaierror.

    Every answer matters: a name with one public and one private A record would
    pass if only the first were inspected, and the connection could land on
    either. The validator checks all of them and pins a validated one.

    Uses getaddrinfo (not gethostbyname) so IPv6-only/AAAA-only hosts are
    resolved too, not silently treated as unresolvable — gethostbyname is
    IPv4-only and would let an operator believe an IPv6 host had no address
    at all rather than correctly evaluating it against the block-list."""
    infos = socket.getaddrinfo(host, None)
    return list(dict.fromkeys(info[4][0] for info in infos))


class ScopeValidator:
    def __init__(self, policy: ScopePolicy, resolver=_default_resolver) -> None:
        self._policy = policy
        self._resolve = resolver

    @property
    def policy(self) -> ScopePolicy:
        """Read access to the loaded policy, for callers that need to *show* the
        scope (the config UI, the readiness panel) rather than enforce it. The
        validator keeps sole responsibility for deciding — this exposes the
        inputs, not a second copy of the decision logic."""
        return self._policy

    def validate_url(self, url: str) -> ScopeResult:
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            return ScopeResult(False, url, None, f"Malformed URL: {exc}")
        if parsed.scheme not in _DEFAULT_PORTS:
            return ScopeResult(
                False, host or url, None,
                f"Scheme '{parsed.scheme}' is not allowed; only http and https are testable.",
            )
        if not host:
            return ScopeResult(False, url, None, "URL has no host component.")
        # Userinfo and backslashes are parser-differential bait: urlparse and the
        # HTTP client can disagree about which host `http://ok.com\@evil` means.
        if parsed.username is not None or parsed.password is not None or "\\" in url:
            return ScopeResult(False, host, None, "URL must not contain credentials or backslashes.")
        if port is not None and port != _DEFAULT_PORTS[parsed.scheme]:
            if port not in self._policy.allowed_ports and not self._policy.allow_private_ranges:
                return ScopeResult(
                    False, host, None,
                    f"Port {port} is not in the approved scope for '{host}' "
                    "(only 80/443 unless the port is allowed explicitly).",
                )
        return self.validate_host(host)

    def validate_host(self, host: str) -> ScopeResult:
        host = host.lower().strip()

        # 1. Explicit blocklist always wins.
        if host in self._policy.blocked_hosts:
            return ScopeResult(False, host, None, f"Host '{host}' is explicitly blocked.")

        # 2. Must be on the allowlist. Default-deny: no allowlist entry, no test.
        if host not in self._policy.allowed_hosts:
            return ScopeResult(
                False,
                host,
                None,
                f"Host '{host}' is not in the approved testing scope.",
            )

        # 3. Resolve and inspect EVERY answer (defeats DNS-based SSRF, including
        # a mixed public/private record set).
        try:
            answers = self._resolve(host)
        except OSError as exc:  # socket.gaierror is an OSError subclass
            return ScopeResult(False, host, None, f"DNS resolution failed for '{host}': {exc}")
        if isinstance(answers, str):
            answers = [answers]
        if not answers:
            return ScopeResult(False, host, None, f"DNS resolution returned no address for '{host}'.")

        ip_str = None
        for candidate_str in answers:
            blocked = self._check_address(host, candidate_str)
            if blocked is not None:
                return blocked
            if ip_str is None:
                ip_str = candidate_str

        # Allowed. resolved_ip is returned so the runner can PIN the connection
        # to this exact IP — no second, unvalidated DNS lookup.
        return ScopeResult(True, host, ip_str, "Target is within approved scope.")

    def _check_address(self, host: str, ip_str: str) -> "ScopeResult | None":
        """A refusal for one resolved address, or None when it is acceptable."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return ScopeResult(False, host, ip_str, f"Resolver returned invalid IP '{ip_str}'.")
        if self._policy.allow_private_ranges:
            return None
        # An IPv6 answer can *wrap* a blocked IPv4 address several ways — the
        # exact same address underneath, just encoded so a version-matched-only
        # check misses it: ::ffff:169.254.169.254 (IPv4-mapped),
        # ::169.254.169.254 (deprecated IPv4-compatible) or
        # 64:ff9b::169.254.169.254 (NAT64). Check the address as resolved AND
        # every IPv4 address it embeds.
        candidates = [ip, *_embedded_ipv4_addresses(ip)]
        for candidate in candidates:
            for net in _ALWAYS_BLOCK_NETS:
                if candidate.version == net.version and candidate in net:
                    return ScopeResult(
                        False,
                        host,
                        ip_str,
                        f"Host '{host}' resolves to blocked range {net} "
                        f"({candidate}, from resolved address {ip_str}). "
                        "Possible SSRF/metadata target.",
                    )
        return None
