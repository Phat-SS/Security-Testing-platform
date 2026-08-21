"""`.env` has to reach the Python process that reads it.

It used to be parsed only by scripts/security-ui.js (the Node launcher) and by
docker-compose's `env_file`. Starting the app any other way — `uvicorn
app.api.main:app`, `python -m app.cli` — silently ignored the file, and the
symptom was a readiness panel blaming personas and Jira for settings the
operator had already written down.
"""

import os

from app.core.preflight import load_dotenv, parse_dotenv, reload_dotenv


def _write(tmp_path, text: str) -> str:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_parses_comments_quotes_and_blank_lines(tmp_path):
    path = _write(tmp_path, """
# a comment
JIRA_SITE_URL = https://example.atlassian.net
QUOTED="quoted value"
NOT_A_PAIR
""")
    assert parse_dotenv(path) == {
        "JIRA_SITE_URL": "https://example.atlassian.net",
        "QUOTED": "quoted value",
    }


def test_missing_file_is_not_an_error(tmp_path):
    assert parse_dotenv(str(tmp_path / "nope.env")) == {}
    assert load_dotenv(str(tmp_path / "nope.env")) == []


def test_the_real_environment_wins_over_the_file(tmp_path, monkeypatch):
    """Standard dotenv precedence, and the reason it matters here: a CI job or
    a compose file that sets DATABASE_URL must not be overridden by a developer
    .env that happens to be in the working directory."""
    path = _write(tmp_path, "DOTENV_TEST_A=from-file\nDOTENV_TEST_B=from-file\n")
    monkeypatch.setenv("DOTENV_TEST_A", "from-shell")
    monkeypatch.delenv("DOTENV_TEST_B", raising=False)
    try:
        applied = load_dotenv(path)
        assert applied == ["DOTENV_TEST_B"]
        assert os.environ["DOTENV_TEST_A"] == "from-shell"
        assert os.environ["DOTENV_TEST_B"] == "from-file"
    finally:
        os.environ.pop("DOTENV_TEST_B", None)


def test_reload_overrides_because_it_exists_to_replace_a_stale_token(monkeypatch, tmp_path):
    """`reload_dotenv` is the Reconnect path: a freshly refreshed Jira token in
    the file must beat the expired one this process is holding."""
    path = _write(tmp_path, "DOTENV_TEST_TOKEN=new\n")
    monkeypatch.setenv("DOTENV_TEST_TOKEN", "expired")
    reload_dotenv(path)
    assert os.environ["DOTENV_TEST_TOKEN"] == "new"
