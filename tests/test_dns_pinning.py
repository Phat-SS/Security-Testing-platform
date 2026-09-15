"""Pinning closes the TOCTOU gap between scope validation and the connection.

`ScopeValidator` resolves a host and checks the address; the runner must then
connect to *that exact address* rather than let the OS resolve again, which an
attacker controlling DNS with a short TTL could answer differently.

These assert the property against a real socket. The mechanism used to be a
process-wide `socket.getaddrinfo` patch, and the tests for it asserted that the
patch was installed and removed — which proved the implementation, not the
behaviour, and went obsolete the moment the implementation did. What matters is
where the bytes went.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from app.execution.pinning import PIN, PinnedTransport, pin

# A name that resolves nowhere. Any request that reaches this server got there
# because the pin sent it, not because DNS did.
UNRESOLVABLE = "api.pinning.invalid"


@pytest.fixture()
def server():
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received["host"] = self.headers.get("Host")
            received["path"] = self.path
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.server_address[1], received
    finally:
        httpd.shutdown()


@pytest.fixture()
def client():
    with httpx.Client(transport=PinnedTransport(httpx.HTTPTransport()), timeout=5) as c:
        yield c


def test_the_request_goes_to_the_pinned_address(client, server):
    port, received = server

    response = client.get(f"http://{UNRESOLVABLE}:{port}/customers/1",
                          extensions=pin("127.0.0.1"))

    assert response.status_code == 200
    assert received["path"] == "/customers/1"


def test_without_a_pin_the_same_request_cannot_connect(client, server):
    """The control for the test above: it is the pin doing the work, not a
    resolver that happens to answer."""
    port, _ = server

    with pytest.raises(httpx.HTTPError):
        client.get(f"http://{UNRESOLVABLE}:{port}/customers/1")


def test_the_host_header_still_names_the_host(client, server):
    """A name-based virtual host has to keep serving the right site once the
    connection is aimed at an address."""
    port, received = server

    client.get(f"http://{UNRESOLVABLE}:{port}/x", extensions=pin("127.0.0.1"))

    assert received["host"] == f"{UNRESOLVABLE}:{port}"


def test_tls_still_verifies_against_the_name_not_the_address():
    """The certificate must be checked against the hostname. Pinning aims the
    socket; it must not weaken what the handshake proves."""
    transport = PinnedTransport(httpx.HTTPTransport())
    request = httpx.Client().build_request("GET", f"https://{UNRESOLVABLE}/x")
    request.extensions = {**request.extensions, **pin("203.0.113.9")}

    with pytest.raises(Exception):  # nothing listens on 203.0.113.9
        transport.handle_request(request)

    assert request.extensions["sni_hostname"] == UNRESOLVABLE


def test_the_url_is_restored_after_the_send(client, server):
    """Anything that looks at the request afterwards — a retry, a log line, the
    captured evidence — should see the URL that was asked for."""
    port, _ = server
    url = f"http://{UNRESOLVABLE}:{port}/x"

    response = client.get(url, extensions=pin("127.0.0.1"))

    assert str(response.request.url) == url


def test_an_unpinned_request_passes_straight_through():
    """The runner's tests drive an in-process ASGI app through this transport;
    a request with nothing pinned must be untouched."""
    seen = []

    class Recording(httpx.BaseTransport):
        def handle_request(self, request):
            seen.append((str(request.url), dict(request.extensions)))
            return httpx.Response(204)

    transport = PinnedTransport(Recording())
    request = httpx.Client().build_request("GET", "http://example.test/x")
    transport.handle_request(request)

    url, extensions = seen[0]
    assert url == "http://example.test/x"
    assert "sni_hostname" not in extensions


def test_pin_of_nothing_is_no_extension():
    """So an unpinned call site is unchanged rather than special-cased."""
    assert pin(None) == {}
    assert pin("") == {}
    assert pin("203.0.113.9") == {PIN: "203.0.113.9"}


def test_two_hosts_pinned_at_once_do_not_interfere(server):
    """The old mechanism was process-global and had to be serialised behind a
    lock precisely because this was not true of it — which is why a 300-test
    plan could never run anything in parallel."""
    port, received = server
    results = []

    def send(host_label, ip):
        with httpx.Client(transport=PinnedTransport(httpx.HTTPTransport()), timeout=5) as c:
            try:
                r = c.get(f"http://{host_label}:{port}/{host_label}", extensions=pin(ip))
                results.append((host_label, r.status_code))
            except httpx.HTTPError as exc:
                results.append((host_label, type(exc).__name__))

    threads = [
        threading.Thread(target=send, args=(UNRESOLVABLE, "127.0.0.1")),
        # Pinned to an address nothing listens on: it must fail on its own
        # terms without stealing or being given the other thread's answer.
        threading.Thread(target=send, args=("other.pinning.invalid", "203.0.113.9")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    outcomes = dict(results)
    assert outcomes[UNRESOLVABLE] == 200
    assert outcomes["other.pinning.invalid"] != 200
