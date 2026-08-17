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
