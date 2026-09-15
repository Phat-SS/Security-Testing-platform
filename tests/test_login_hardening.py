"""A rejected sign-in should cost something and leave a trace.

A 24-byte key is not guessable, and none of this pretends otherwise. What was
missing is the other half: a failed attempt cost nothing to repeat and wrote
nothing anywhere, so a sustained attempt against this server was invisible.
"""

from __future__ import annotations

import json
import logging

import pytest
from starlette.testclient import TestClient

from app.core.auth import AuthManager, User, hash_key

GOOD = "the-real-key-nobody-guesses"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "vera", "role": "tester", "api_key_sha256": hash_key(GOOD)},
    ]}))
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'login.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _attempt(client, key: str):
    return client.post("/login", data={"api_key": key}, follow_redirects=False)


# -- the lockout ------------------------------------------------------------


def test_repeated_failures_are_eventually_refused_without_checking_the_key(client):
    from app.api.main import state

    for _ in range(state.auth.MAX_FAILURES):
        _attempt(client, "wrong")

    assert state.auth.locked_out("testclient") > 0
    # And the right key is refused too while the lockout stands — a lockout
    # that the attacker's next guess could step around is not one.
    assert "Too%20many%20attempts" in _attempt(client, GOOD).headers["location"]


def test_a_success_clears_the_count(client):
    from app.api.main import state

    for _ in range(state.auth.MAX_FAILURES - 1):
        _attempt(client, "wrong")
    assert state.auth.locked_out("testclient") == 0

    _attempt(client, GOOD)

    assert state.auth.locked_out("testclient") == 0
    for _ in range(state.auth.MAX_FAILURES - 1):
        _attempt(client, "wrong")
    assert state.auth.locked_out("testclient") == 0, "the counter did not reset"


def test_the_lockout_expires_on_its_own(tmp_path):
    """Only recent failures count, so nobody has to go and unlock anything."""
    manager = AuthManager(config_path=str(tmp_path / "nope.json"))
    manager.MAX_FAILURES = 2
    manager.LOCKOUT_S = 0.05

    manager.note_failure("1.2.3.4")
    manager.note_failure("1.2.3.4")
    assert manager.locked_out("1.2.3.4") > 0

    import time

    time.sleep(0.08)
    assert manager.locked_out("1.2.3.4") == 0


def test_one_source_locking_out_does_not_lock_out_another(tmp_path):
    manager = AuthManager(config_path=str(tmp_path / "nope.json"))
    for _ in range(manager.MAX_FAILURES):
        manager.note_failure("1.2.3.4")

    assert manager.locked_out("1.2.3.4") > 0
    assert manager.locked_out("5.6.7.8") == 0


def test_failures_are_not_counted_when_authentication_is_off(tmp_path, monkeypatch):
    """Every key "succeeds" in single-user mode, so a rejection is impossible
    and a count would only ever be noise — or a way to lock the local demo out
    of itself."""
    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'open.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        for _ in range(30):
            c.post("/login", data={"api_key": "anything"}, follow_redirects=False)
        from app.api.main import state

        assert state.auth.locked_out("testclient") == 0


# -- the trace --------------------------------------------------------------


def test_a_rejected_attempt_is_logged_loudly_enough_to_find(client, caplog):
    """WARNING, not INFO: this is the line an operator greps for, and the only
    signal that anyone is trying keys at all."""
    with caplog.at_level(logging.WARNING, logger="app.core.auth"):
        _attempt(client, "wrong")

    assert any("failed sign-in" in r.message for r in caplog.records)
    assert all(r.levelno >= logging.WARNING for r in caplog.records
               if "failed sign-in" in r.message)


def test_the_log_line_never_carries_the_key_that_was_tried(client, caplog):
    """A rejected key is still a secret — it is very often a real credential
    for something else, typed into the wrong box."""
    with caplog.at_level(logging.WARNING, logger="app.core.auth"):
        _attempt(client, "sekrit-from-another-system")

    assert "sekrit-from-another-system" not in caplog.text


# -- sessions ---------------------------------------------------------------


def test_expired_sessions_are_dropped_rather_than_kept_forever(tmp_path):
    """Expiry was only ever noticed when a token was looked up, so a process
    that ran for months held one entry per login and released none."""
    manager = AuthManager(config_path=str(tmp_path / "nope.json"))
    manager._session_ttl_s = -1  # already expired the moment it is issued
    for _ in range(5):
        manager.issue_session(User("vera", "tester"))

    manager.issue_session(User("vera", "tester"))

    assert len(manager._sessions) == 1, "expired sessions were not evicted"
