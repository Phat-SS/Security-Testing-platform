"""Scope validator — the safety-critical control. Test it hardest.

Uses an injected fake resolver so DNS behaviour is deterministic and the SSRF /
rebinding bypasses can be exercised without touching the network.
"""

import pytest

from app.core.scope import ScopePolicy, ScopeValidator, ScopeViolation


def make(policy, mapping):
    return ScopeValidator(policy, resolver=lambda h: mapping[h])


def test_allowed_public_host_passes():
    policy = ScopePolicy(allowed_hosts={"api-staging.company.com"})
    v = make(policy, {"api-staging.company.com": "203.0.113.10"})
    r = v.validate_url("https://api-staging.company.com/customers/1")
    assert r.allowed
    assert r.resolved_ip == "203.0.113.10"  # returned for pinning


def test_host_not_on_allowlist_is_denied():
    policy = ScopePolicy(allowed_hosts={"api-staging.company.com"})
    v = make(policy, {"evil.com": "203.0.113.99"})
    r = v.validate_url("https://evil.com/")
    assert not r.allowed
    assert "not in the approved" in r.reason


def test_explicit_block_beats_allow():
    policy = ScopePolicy(allowed_hosts={"h.com"}, blocked_hosts={"h.com"})
    v = make(policy, {"h.com": "203.0.113.1"})
    assert not v.validate_url("https://h.com/").allowed


def test_ssrf_allowlisted_name_resolving_to_metadata_is_blocked():
    # The classic SSRF: name is on the allowlist but resolves to cloud metadata.
    policy = ScopePolicy(allowed_hosts={"api-staging.company.com"})
    v = make(policy, {"api-staging.company.com": "169.254.169.254"})
    r = v.validate_url("https://api-staging.company.com/")
    assert not r.allowed
    assert "169.254" in r.reason or "SSRF" in r.reason


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.9"])
def test_private_and_loopback_ranges_blocked_by_default(ip):
    policy = ScopePolicy(allowed_hosts={"h.com"})
    v = make(policy, {"h.com": ip})
    assert not v.validate_url("https://h.com/").allowed


@pytest.mark.parametrize("mapped_ip", [
    "::ffff:169.254.169.254",  # cloud metadata, IPv4-mapped
    "::ffff:127.0.0.1",        # loopback, IPv4-mapped
    "::ffff:10.1.2.3",         # RFC1918, IPv4-mapped
])
def test_ipv4_mapped_ipv6_cannot_bypass_the_ipv4_blocklist(mapped_ip):
    # A version-matched-only check (ip.version == net.version) would let an
    # IPv6 AAAA answer of ::ffff:<blocked-ipv4> sail past every IPv4 entry in
    # _ALWAYS_BLOCK_NETS. This became reachable once the resolver started
    # returning IPv6 addresses (getaddrinfo instead of gethostbyname).
    policy = ScopePolicy(allowed_hosts={"h.com"})
    v = make(policy, {"h.com": mapped_ip})
    r = v.validate_url("https://h.com/")
    assert not r.allowed
    assert "SSRF" in r.reason or "blocked range" in r.reason


@pytest.mark.parametrize("wrapped_ip", [
    "::169.254.169.254",       # deprecated IPv4-compatible form
    "::127.0.0.1",              # deprecated IPv4-compatible form, loopback
    "64:ff9b::169.254.169.254",  # NAT64 well-known prefix (RFC 6052)
    "64:ff9b::a01:203",          # NAT64 well-known prefix, 10.1.2.3
])
def test_other_ipv4_embedding_ipv6_forms_cannot_bypass_the_blocklist(wrapped_ip):
    # ::ffff:0:0/96 (IPv4-mapped) isn't the only IPv6 wrapper that carries a
    # plain IPv4 address in its low 32 bits. The deprecated IPv4-compatible
    # form and the NAT64 well-known prefix both do too, and both resolve to
    # the exact same address a hostname-only or single-prefix check would
    # miss.
    policy = ScopePolicy(allowed_hosts={"h.com"})
    v = make(policy, {"h.com": wrapped_ip})
    r = v.validate_url("https://h.com/")
    assert not r.allowed
    assert "SSRF" in r.reason or "blocked range" in r.reason


def test_private_range_allowed_only_with_explicit_optin():
    policy = ScopePolicy(allowed_hosts={"127.0.0.1"}, allow_private_ranges=True)
    v = make(policy, {"127.0.0.1": "127.0.0.1"})
    assert v.validate_url("http://127.0.0.1:8000/").allowed


def test_dns_failure_is_denied_not_crashed():
    def boom(host):
        raise OSError("nxdomain")

    policy = ScopePolicy(allowed_hosts={"h.com"})
    v = ScopeValidator(policy, resolver=boom)
    r = v.validate_url("https://h.com/")
    assert not r.allowed
    assert "DNS" in r.reason


def test_raise_if_blocked():
    policy = ScopePolicy(allowed_hosts=set())
    v = make(policy, {})
    with pytest.raises(ScopeViolation):
        v.validate_host("nope.com").raise_if_blocked()


# -- hardening: every DNS answer, extra ranges, port/scheme/userinfo ----------

def _multi(policy, answers):
    return ScopeValidator(policy, resolver=lambda h: answers)


def test_mixed_public_and_private_answers_are_refused():
    v = _multi(ScopePolicy(allowed_hosts={"h.com"}), ["203.0.113.5", "10.0.0.7"])
    r = v.validate_url("https://h.com/")
    assert not r.allowed
    assert "10.0.0.0/8" in r.reason


@pytest.mark.parametrize("ip", [
    "100.100.100.200",  # CGNAT: Alibaba metadata
    "198.18.0.1", "224.0.0.1", "240.0.0.1", "ff02::1",
    "2002:a00:1::1",  # 6to4 wrapping 10.0.0.1
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
])
def test_additional_non_public_ranges_are_blocked(ip):
    v = _multi(ScopePolicy(allowed_hosts={"h.com"}), [ip])
    assert not v.validate_url("https://h.com/").allowed


@pytest.mark.parametrize("url", [
    "ftp://h.com/", "file://h.com/etc/passwd", "gopher://h.com/",
    "https://user:pw@h.com/", r"https://h.com\@evil.com/",
])
def test_non_http_schemes_and_parser_tricks_are_refused(url):
    v = _multi(ScopePolicy(allowed_hosts={"h.com"}), ["203.0.113.5"])
    assert not v.validate_url(url).allowed


def test_non_default_port_needs_explicit_allowance():
    v = _multi(ScopePolicy(allowed_hosts={"h.com"}), ["203.0.113.5"])
    assert v.validate_url("https://h.com:443/").allowed
    assert not v.validate_url("https://h.com:6379/").allowed
    v = _multi(ScopePolicy(allowed_hosts={"h.com"}, allowed_ports={8443}), ["203.0.113.5"])
    assert v.validate_url("https://h.com:8443/").allowed
    assert not v.validate_url("https://h.com:22/").allowed


def test_lab_mode_waives_the_port_rule():
    v = _multi(ScopePolicy(allowed_hosts={"127.0.0.1"}, allow_private_ranges=True), ["127.0.0.1"])
    assert v.validate_url("http://127.0.0.1:8100/x").allowed
