from app.core.redaction import MASK, redact_any, redact_headers, redact_text


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
