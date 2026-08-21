"""Helpers behind the Config/MCP page's one-click Jira token refresh.

Pure filesystem logic — no live OAuth server or FastAPI app needed.
"""

import json
import time

from app.core.preflight import newest_mcp_auth_token, write_dotenv_value


def _token_file(base, subdir, name, mtime, access_token="tok"):
    d = base / subdir
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(json.dumps({"access_token": access_token}), encoding="utf-8")
    import os

    os.utime(p, (mtime, mtime))
    return p


def test_newest_mcp_auth_token_picks_the_most_recently_written_file(tmp_path):
    now = time.time()
    older = _token_file(tmp_path, "mcp-remote-0.1.27", "a_tokens.json", now - 3600)
    newer = _token_file(tmp_path, "mcp-remote-0.1.37", "b_tokens.json", now - 60)

    found = newest_mcp_auth_token(tmp_path)
    assert found == newer
    assert found != older


def test_newest_mcp_auth_token_honors_newer_than(tmp_path):
    now = time.time()
    _token_file(tmp_path, "mcp-remote-0.1.37", "old_tokens.json", now - 3600)

    # Nothing written after `now` — a stale cached token must not count as a
    # freshly completed login.
    assert newest_mcp_auth_token(tmp_path, newer_than=now) is None

    fresh = _token_file(tmp_path, "mcp-remote-0.1.37", "fresh_tokens.json", now + 5)
    assert newest_mcp_auth_token(tmp_path, newer_than=now) == fresh


def test_newest_mcp_auth_token_missing_dir_is_none(tmp_path):
    assert newest_mcp_auth_token(tmp_path / "does-not-exist") is None


def test_write_dotenv_value_appends_when_absent(tmp_path):
    env = tmp_path / ".env"
    env.write_text("OTHER=1\n", encoding="utf-8")

    write_dotenv_value("JIRA_MCP_TOKEN", "abc123", path=str(env))

    assert "JIRA_MCP_TOKEN=abc123" in env.read_text(encoding="utf-8")
    assert "OTHER=1" in env.read_text(encoding="utf-8")


def test_write_dotenv_value_replaces_an_existing_line(tmp_path):
    env = tmp_path / ".env"
    env.write_text("JIRA_MCP_TOKEN=old\nOTHER=1\n", encoding="utf-8")

    write_dotenv_value("JIRA_MCP_TOKEN", "new", path=str(env))

    text = env.read_text(encoding="utf-8")
    assert "JIRA_MCP_TOKEN=new" in text
    assert "JIRA_MCP_TOKEN=old" not in text
    assert text.count("JIRA_MCP_TOKEN=") == 1


def test_write_dotenv_value_replaces_a_commented_out_line(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# JIRA_MCP_TOKEN=\n", encoding="utf-8")

    write_dotenv_value("JIRA_MCP_TOKEN", "new", path=str(env))

    text = env.read_text(encoding="utf-8")
    assert "JIRA_MCP_TOKEN=new" in text
    assert "# JIRA_MCP_TOKEN=" not in text


def test_write_dotenv_value_is_idempotent(tmp_path):
    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")

    write_dotenv_value("JIRA_MCP_URL", "https://mcp.atlassian.com/v1/mcp", path=str(env))
    write_dotenv_value("JIRA_MCP_URL", "https://mcp.atlassian.com/v1/mcp", path=str(env))

    text = env.read_text(encoding="utf-8")
    assert text.count("JIRA_MCP_URL=") == 1


def test_write_dotenv_value_collapses_duplicate_keys(tmp_path):
    """The bug this guards: .env is last-one-wins, so replacing only the first
    of two copies wrote the fresh token *above* the stale one that actually got
    loaded — the Refresh token button appeared to do nothing."""
    env = tmp_path / ".env"
    env.write_text(
        "JIRA_MCP_TOKEN=first\nOTHER=1\nJIRA_MCP_TOKEN=stale-duplicate\n",
        encoding="utf-8",
    )

    write_dotenv_value("JIRA_MCP_TOKEN", "fresh", path=str(env))

    text = env.read_text(encoding="utf-8")
    assert text.count("JIRA_MCP_TOKEN=") == 1
    assert "JIRA_MCP_TOKEN=fresh" in text
    assert "stale-duplicate" not in text
    assert "OTHER=1" in text
    # Kept where the first copy was, not appended to the end.
    assert text.splitlines()[0] == "JIRA_MCP_TOKEN=fresh"


def test_write_dotenv_value_leaves_prose_comments_alone(tmp_path):
    """`#  KEY  what it does` documents the key; only a `KEY=` line is a value."""
    env = tmp_path / ".env"
    env.write_text(
        "#   JIRA_MCP_TOKEN  OAuth access token -> Authorization: Bearer <token>\n"
        "JIRA_MCP_TOKEN=old\n",
        encoding="utf-8",
    )

    write_dotenv_value("JIRA_MCP_TOKEN", "new", path=str(env))

    lines = env.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#   JIRA_MCP_TOKEN  OAuth access token")
    assert lines[1] == "JIRA_MCP_TOKEN=new"


def test_write_dotenv_value_preserves_crlf(tmp_path):
    """The real .env on Windows is CRLF; rewriting it must not churn every line."""
    env = tmp_path / ".env"
    env.write_bytes(b"OTHER=1\r\nJIRA_MCP_TOKEN=old\r\n")

    write_dotenv_value("JIRA_MCP_TOKEN", "new", path=str(env))

    assert env.read_bytes() == b"OTHER=1\r\nJIRA_MCP_TOKEN=new\r\n"


def test_reload_dotenv_last_occurrence_wins(tmp_path, monkeypatch):
    """Documents the precedence write_dotenv_value has to respect, and that
    scripts/security-ui.js's own parser already follows."""
    from app.core.preflight import reload_dotenv

    env = tmp_path / ".env"
    env.write_text("JIRA_MCP_TOKEN=first\nJIRA_MCP_TOKEN=last\n", encoding="utf-8")
    monkeypatch.delenv("JIRA_MCP_TOKEN", raising=False)

    reload_dotenv(str(env))

    import os

    assert os.environ["JIRA_MCP_TOKEN"] == "last"
