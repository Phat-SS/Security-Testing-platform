"""Connect to the exact address the scope validator approved.

Scope validation and the TCP connect are two separate DNS lookups. Between
them, an attacker who controls DNS for an approved host (short TTL, split
horizon) can answer with a public address for the check and a private one for
the connection — DNS rebinding, and it defeats the whole allow-list.

Pinning closes that window by reusing the address already validated instead of
letting the OS resolve again.

**Why this is not a `socket.getaddrinfo` patch any more.** It used to be: the
runner swapped the process-wide resolver for the duration of each send. That
worked, and cost more than it looked like.

  * It is process-global state, so it had to be serialised behind a lock — and
    that lock made every request in the whole process wait for every other one.
    Two assessments could not run at once, and a 300-test plan could never be
    anything but sequential.
  * Inside the pin window, *any* code in the process resolving that hostname
    got the pinned answer: the Jira connector, an OAST poll, a health check.
  * The patch was installed and removed around every send, from a worker
    thread, in an application that also serves requests.

Attaching the pin to the request instead makes it local to the request. The
connection goes to the IP; the `Host` header and the TLS SNI keep the original
hostname, so virtual hosting and certificate verification behave exactly as
they would without pinning — the certificate is still checked against the name,
never against the address.
"""

from __future__ import annotations

import httpx

#: Request extension carrying the validated address. An extension rather than a
#: header: it never goes on the wire, and httpx hands it to the transport
#: untouched.
PIN = "stp_pinned_ip"


def pin(ip: str | None) -> dict:
    """Extensions for a request that must go to `ip`. Empty when there is
    nothing to pin, so an unpinned request is unchanged rather than
    special-cased at every call site."""
    return {PIN: ip} if ip else {}


class PinnedTransport(httpx.BaseTransport):
    """Wraps a transport, redirecting each request to its pinned address.

    Wrapping rather than subclassing `HTTPTransport`: the runner's tests hand
    the client an ASGI transport to drive an in-process app, and that has to
    keep working — a request with nothing pinned passes straight through.
    """

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        ip = request.extensions.get(PIN)
        host = request.url.host
        if not ip or ip == host:
            return self._inner.handle_request(request)

        # httpx set the Host header from the original URL when the request was
        # built, and it is left exactly as it is — that is what keeps a
        # name-based virtual host serving the right site once the connection is
        # aimed at an address.
        request.extensions = {**request.extensions, "sni_hostname": host}
        original = request.url
        # `copy_with` brackets an IPv6 literal itself; doing it here would
        # double-bracket it.
        request.url = original.copy_with(host=ip)
        try:
            return self._inner.handle_request(request)
        finally:
            # Restored so anything that inspects the request afterwards — a
            # retry, a log line, a test — sees the URL that was asked for
            # rather than the address it happened to be sent to.
            request.url = original

    def close(self) -> None:
        self._inner.close()


def build_client(*, timeout, user_agent: str, verify: bool = True) -> httpx.Client:
    """The runner's HTTP client, with pinning installed.

    `follow_redirects=False` is load-bearing and not a default worth changing:
    a 302 to an internal host is the same attack wearing a hat, and a client
    chasing it would re-resolve DNS and bypass the validator entirely. A 3xx is
    captured and evaluated as-is.
    """
    return httpx.Client(
        transport=PinnedTransport(httpx.HTTPTransport(verify=verify)),
        follow_redirects=False,
        timeout=timeout,
        headers={"User-Agent": user_agent},
    )
