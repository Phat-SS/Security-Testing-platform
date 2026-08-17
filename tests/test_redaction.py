from app.core.redaction import MASK, redact_any, redact_headers, redact_text, redact_url


def test_authorization_header_masked():
    out = redact_headers({"Authorization": "Bearer eyJabc.def.ghi", "Accept": "application/json"})
    assert out["Authorization"] == MASK
    assert out["Accept"] == "application/json"


def test_cookie_header_masked():
    out = redact_headers({"Cookie": "session=secretvalue"})
    assert out["Cookie"] == MASK


def test_bearer_inline_masked():
    assert "eyJ" not in redact_text("got Authorization: Bearer eyJx.y.z here")


def test_jwt_masked():
    text = "token=eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJ"
    assert "eyJhbGciOi" not in redact_text(text)


def test_password_key_masked_in_json():
    out = redact_text('{"password": "hunter2", "user": "bob"}')
    assert "hunter2" not in out
    assert "bob" in out


def test_client_secret_masked():
    out = redact_text("client_secret=abc123XYZ&grant_type=code")
    assert "abc123XYZ" not in out
    assert "grant_type" in out


def test_redact_any_nested():
    data = {"api_key": "K123", "nested": {"token": "T456", "safe": "ok"}}
    out = redact_any(data)
    assert out["api_key"] == MASK
    assert out["nested"]["token"] == MASK
    assert out["nested"]["safe"] == "ok"


def test_redact_url_masks_sensitive_query_params():
    out = redact_url("https://api.example.com/reset?token=abc123&user=bob")
    assert "abc123" not in out
    assert "user=bob" in out
    assert out.startswith("https://api.example.com/reset?")


def test_redact_url_leaves_urls_without_query_untouched():
    url = "https://api.example.com/customers/2002"
    assert redact_url(url) == url


def test_redact_url_masks_jwt_embedded_in_the_path():
    # A key-name-only check misses a token with no query key at all (a PoC
    # hitting /reset-password/<jwt> directly) — the shape-based pass catches it.
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx.SflKxwRJ"
    out = redact_url(f"https://api.example.com/reset-password/{jwt}")
    assert jwt not in out
    assert out == f"https://api.example.com/reset-password/{MASK}"


def test_redact_url_mask_is_not_percent_encoded():
    out = redact_url("https://api.example.com/reset?token=abc123")
    assert f"token={MASK}" in out
