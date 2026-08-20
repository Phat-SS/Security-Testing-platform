"""make_engine's pool configuration.

SQLAlchemy's engine defaults (pool_size=5, no pre-ping) silently exhaust
under a handful of concurrent requests and go blind to a connection Postgres
already dropped — real risks for a server database, meaningless for SQLite
(no server-side pool, no separate process to go stale behind). This pins the
branch so a Postgres deployment actually gets pool_pre_ping/size/overflow/
recycle, without needing a real Postgres driver installed to test it: the
driver import only happens inside `create_engine` itself, which is
monkeypatched here rather than called for real.
"""

import app.database.models as models


def test_sqlite_engine_gets_check_same_thread_and_no_pool_options(monkeypatch):
    captured = {}

    def fake_create_engine(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return "engine"

    monkeypatch.setattr(models, "create_engine", fake_create_engine)

    result = models.make_engine("sqlite:///somewhere.db")

    assert result == "engine"
    assert captured["kwargs"]["connect_args"] == {"check_same_thread": False}
    assert "pool_size" not in captured["kwargs"]
    assert "pool_pre_ping" not in captured["kwargs"]


def test_postgres_engine_gets_pre_ping_and_pool_sizing(monkeypatch):
    captured = {}

    def fake_create_engine(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return "engine"

    monkeypatch.setattr(models, "create_engine", fake_create_engine)
    monkeypatch.delenv("DB_POOL_SIZE", raising=False)
    monkeypatch.delenv("DB_MAX_OVERFLOW", raising=False)
    monkeypatch.delenv("DB_POOL_RECYCLE_S", raising=False)

    models.make_engine("postgresql+psycopg://user:pw@host/db")

    kwargs = captured["kwargs"]
    assert kwargs["pool_pre_ping"] is True
    assert kwargs["pool_size"] == 10
    assert kwargs["max_overflow"] == 20
    assert kwargs["pool_recycle"] == 1800
    assert "connect_args" not in kwargs


def test_postgres_pool_sizing_is_env_tunable(monkeypatch):
    captured = {}
    monkeypatch.setattr(models, "create_engine", lambda url, **kw: captured.update(kw) or "engine")
    monkeypatch.setenv("DB_POOL_SIZE", "25")
    monkeypatch.setenv("DB_MAX_OVERFLOW", "50")
    monkeypatch.setenv("DB_POOL_RECYCLE_S", "600")

    models.make_engine("postgresql+psycopg://user:pw@host/db")

    assert captured["pool_size"] == 25
    assert captured["max_overflow"] == 50
    assert captured["pool_recycle"] == 600
