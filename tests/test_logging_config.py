"""RedactingFilter is the second, independent guard against a secret leaking
through a log line instead of through storage/report/Jira (see module
docstring in app/core/logging_config.py) — test it directly against a
LogRecord rather than through pytest's own log-capture plumbing, which
attaches its own handler and would not exercise the filter this module
attaches to ITS handler.
"""

import logging
import sys
import types

from app.core.logging_config import RedactingFilter, configure_error_tracking, configure_logging


def _record(msg: str, args: tuple = ()) -> logging.LogRecord:
    return logging.LogRecord(
        name="app.test", level=logging.INFO, pathname=__file__, lineno=1,
        msg=msg, args=args, exc_info=None,
    )


def test_redacting_filter_masks_secret_shaped_values_after_formatting():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx.SflKxwRJ"
    record = _record("issued token=%s for user %s", (jwt, "bob"))

    kept = RedactingFilter().filter(record)

    assert kept is True
    assert jwt not in record.msg
    assert "bob" in record.msg
    # args were already folded into msg by getMessage(); leaving them in
    # place would re-apply %-formatting to an already-formatted string.
    assert record.args == ()


def test_redacting_filter_masks_key_value_secrets():
    record = _record('user login: {"password": "hunter2", "user": "bob"}')

    RedactingFilter().filter(record)

    assert "hunter2" not in record.msg
    assert "bob" in record.msg


def test_redacting_filter_survives_a_broken_format_string():
    # %s with no matching arg would raise inside getMessage() — a log call
    # with a bug must not be able to crash logging itself.
    record = _record("oops %s %s", ("only one",))

    kept = RedactingFilter().filter(record)

    assert kept is True


def test_configure_logging_is_idempotent():
    configure_logging()
    before = list(logging.getLogger().handlers)

    configure_logging()

    assert logging.getLogger().handlers == before


def test_error_tracking_stays_off_without_a_dsn(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    # If this tried to import sentry_sdk it would fail (not installed by
    # default) — reaching the end without raising proves it returned early.
    configure_error_tracking()


def test_error_tracking_warns_instead_of_crashing_when_sentry_sdk_is_missing(monkeypatch, caplog):
    monkeypatch.setenv("SENTRY_DSN", "https://example.invalid/1")
    monkeypatch.setitem(sys.modules, "sentry_sdk", None)  # forces ImportError on `import sentry_sdk`

    with caplog.at_level(logging.WARNING):
        configure_error_tracking()

    assert any("sentry-sdk" in r.getMessage() for r in caplog.records)


def test_error_tracking_scrubs_events_before_sending(monkeypatch):
    captured = {}
    fake_sentry_sdk = types.SimpleNamespace(
        init=lambda **kwargs: captured.update(kwargs)
    )
    monkeypatch.setenv("SENTRY_DSN", "https://example.invalid/1")
    monkeypatch.setitem(sys.modules, "sentry_sdk", fake_sentry_sdk)

    configure_error_tracking()

    assert captured["dsn"] == "https://example.invalid/1"
    scrubbed = captured["before_send"]({"extra": {"token": "eyJhbGciOiJIUzI1NiJ9.x.y"}}, {})
    assert scrubbed["extra"]["token"] != "eyJhbGciOiJIUzI1NiJ9.x.y"
