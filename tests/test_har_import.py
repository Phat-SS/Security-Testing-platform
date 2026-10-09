"""Endpoints from a HAR capture: names only, one target host, never replayed."""

from __future__ import annotations

import json

import pytest

from app.adapters import har


def _entry(method, url, headers=(), body=None, mime="application/json"):
    req = {"method": method, "url": url,
           "headers": [{"name": n, "value": v} for n, v in headers],
           "queryString": []}
    if body is not None:
        req["postData"] = {"mimeType": mime, "text": json.dumps(body)}
    return {"request": req, "response": {"status": 200}}


def _har(*entries) -> str:
    return json.dumps({"log": {"version": "1.2", "entries": list(entries)}})


CAPTURE = _har(
    _entry("GET", "https://api.acme.test/v1/orders/8812?expand=items",
           headers=[("Authorization", "Bearer eyJsecret")]),
    _entry("GET", "https://api.acme.test/v1/orders/8813?page=2",
           headers=[("Authorization", "Bearer eyJsecret")]),
    _entry("POST", "https://api.acme.test/v1/orders/8812/refund",
           headers=[("Cookie", "sid=topsecret")],
           body={"amount": 10, "callback_url": "https://hooks.acme.test/x"}),
    _entry("GET", "https://api.acme.test/v1/users/3f2b1c9e-0d4a-4b6f-9a1e-2c3d4e5f6a7b"),
    _entry("GET", "https://api.acme.test/v1/notification-settings-overview"),
    _entry("GET", "https://api.acme.test/static/app.js"),
    _entry("GET", "https://www.google-analytics.com/collect?v=1"),
    _entry("OPTIONS", "https://api.acme.test/v1/orders/8812"),
)


def _by_sig(endpoints):
    return {e.signature: e for e in endpoints}


def test_it_is_recognised_as_a_har():
    assert har.looks_like_har(CAPTURE)
    assert not har.looks_like_har('{"openapi": "3.0.0", "paths": {}}')


def test_ids_are_templated_and_requests_to_one_route_merge():
    endpoints, summary = har.parse(CAPTURE)
    eps = _by_sig(endpoints)

    orders = eps["GET /v1/orders/{order_id}"]
    assert orders.object_id_params == ["order_id"]
    assert orders.query_params == ["expand", "page"]
    assert orders.auth_required is True
    assert "GET /v1/users/{user_id}" in eps
    # A long slug with no digits is a route, not an id.
    assert "GET /v1/notification-settings-overview" in eps
    assert summary["target_host"] == "api.acme.test"


def test_body_fields_writes_and_url_fields_are_read():
    refund = _by_sig(har.parse(CAPTURE)[0])["POST /v1/orders/{order_id}/refund"]
    assert refund.body_fields == ["amount", "callback_url"]
    assert refund.url_fields == ["callback_url"]
    assert refund.writes_properties and refund.auth_required  # a Cookie counts


def test_other_hosts_static_assets_and_preflights_are_skipped_and_listed():
    endpoints, summary = har.parse(CAPTURE)
    paths = {e.path for e in endpoints}
    assert not any("collect" in p or p.endswith(".js") for p in paths)
    assert any("google-analytics.com" in s for s in summary["skipped"])
    assert any("static asset/preflight" in s for s in summary["skipped"])


def test_no_header_value_cookie_or_body_value_survives():
    dumped = json.dumps([e.model_dump() for e in har.parse(CAPTURE)[0]])
    for secret in ("eyJsecret", "topsecret", "hooks.acme.test", "8812"):
        assert secret not in dumped


@pytest.mark.parametrize("text", ["not json", '{"log": {}}', _har()])
def test_a_bad_capture_is_refused_clearly(text):
    with pytest.raises(har.HarError):
        har.parse(text)


def test_a_har_imports_through_the_scope_form(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"dev": "https://api.acme.test"}, "active_environment": "dev",
        "scope": {"allowed_hosts": ["api.acme.test"]},
        "attacker": "agent_A", "victim": "agent_B",
        "personas": [{"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
                     {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {}}],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'har.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app, state

    with TestClient(app) as client:
        aid = client.post("/import", data={"issue_key": "CRM-1234"},
                          follow_redirects=True).url.path.rsplit("/", 1)[-1]
        r = client.post(f"/assessment/{aid}/openapi", data={"spec": CAPTURE})
        assert "HAR capture of api.acme.test" in r.text
        sigs = {e.signature for e in state.orch.get_analysis(aid).endpoints}
        assert "POST /v1/orders/{order_id}/refund" in sigs


@pytest.mark.parametrize("url, secret", [
    ("https://api.acme.test/verify/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "eyJhbGciOiJIUzI1NiJ9"),
    ("https://api.acme.test/reset/abcdefghijklmnopqrstuvwxyzABCD", "abcdefghijklmnopqrstuvwxyzABCD"),
    ("https://api.acme.test/u/john@x.com/orders/12", "john@x.com"),
])
def test_tokens_and_addresses_in_a_path_are_templated_not_kept(url, secret):
    """Magic-link, reset and invite tokens live in paths. Keeping one would write
    a live secret into the analysis, the report, the MCP output and AI prompts."""
    endpoints, _ = har.parse(_har(_entry("GET", url), _entry("GET", url)))
    assert secret not in json.dumps([e.model_dump() for e in endpoints])


@pytest.mark.parametrize("text", [
    "[]",
    json.dumps({"log": {"entries": ["not an object"]}}),
    json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "https://a.test/x",
                                                 "headers": {"Authorization": "x"}}}]}}),
])
def test_a_malformed_har_is_refused_or_read_never_a_crash(text):
    try:
        har.parse(text)
    except har.HarError:
        pass


def test_an_openapi_document_mentioning_log_and_entries_is_not_taken_for_a_har():
    spec = json.dumps({"openapi": "3.0.0", "tags": [{"name": "log"}],
                       "paths": {"/entries": {"get": {}}}})
    assert not har.looks_like_har(spec)
