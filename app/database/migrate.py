"""Wires the Alembic migrations under migrations/ into init_db().

Why this exists: `Base.metadata.create_all(engine)` (what init_db() has always
done) only creates tables that do not exist yet — it never alters one that
already does. A database created before a later migration (e.g.
0002_test_case_query_columns, which adds columns to an existing table)
therefore stays on the old schema forever unless something explicitly runs
that migration against it. This module is that "something," run once right
after create_all() on every app/CLI startup, so the situation that caused
"no such column: test_cases.severity" against a pre-existing sectest.db
cannot recur silently the next time a migration adds something new.

Deliberately does NOT build its Alembic `Config` from alembic.ini: loading
that file would run migrations/env.py's `fileConfig()` call, which reassigns
the root logger's handlers per alembic.ini's own `[logger_root]` section —
inside this process, that would strip the app's `RedactingFilter`-carrying
handler installed by `app.core.logging_config.configure_logging()`, a
redaction regression, not just a cosmetic one. Setting `script_location` and
`sqlalchemy.url` directly on a bare `Config()` (leaving `config_file_name`
unset) skips that branch entirely, while `alembic upgrade head` run by hand
from a terminal is untouched and still reads alembic.ini as before.
"""

from __future__ import annotations

from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MIGRATIONS_DIR = _PROJECT_ROOT / "migrations"


def is_memory_sqlite(url: str) -> bool:
    return url.startswith("sqlite") and ":memory:" in url


def bootstrap_alembic(engine, was_fresh: bool) -> None:
    """Call once, immediately after `Base.metadata.create_all(engine)`.

    `was_fresh`: True if the database had no tables at all before create_all()
    ran, meaning create_all() alone just built the complete current schema —
    this database is at Alembic's `head` by construction, so it only needs
    stamping, never a real upgrade (running a migration's `upgrade()` against
    columns create_all() already added would fail as a duplicate). False means
    tables already existed (a database from before this migration, possibly
    from before Alembic existed in this project at all), which needs the
    baseline stamp first so `upgrade head` applies only the real deltas that
    follow it — the exact recipe migrations/versions/0001_baseline.py's own
    docstring describes for the manual case.

    A no-op beyond a plain `upgrade head` once a database already has an
    `alembic_version` row — safe to call on every single startup.

    Skipped entirely for sqlite ':memory:': a fresh, process-local database
    with no history to migrate from, and every new connection to it is its
    own independent, empty database anyway — running Alembic against the URL
    string would migrate a throwaway instance the app's own engine never
    touches.
    """
    url = str(engine.url)
    if is_memory_sqlite(url):
        return

    from alembic import command
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext

    with engine.connect() as conn:
        current = MigrationContext.configure(conn).get_current_revision()

    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", url)

    if current is not None:
        command.upgrade(cfg, "head")
    elif was_fresh:
        command.stamp(cfg, "head")
    else:
        command.stamp(cfg, "0001_baseline")
        command.upgrade(cfg, "head")
