"""baseline: schema as of before Alembic was introduced

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-19
"""

from __future__ import annotations

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Deliberately empty — this revision exists to be *stamped*, not run.

    Every database that predates Alembic in this project already has this
    schema (assessments/test_cases/executions/findings/agent_records/
    audit_log, all created by `app.database.models.init_db`, i.e.
    `Base.metadata.create_all`). Point such a database here with
    `alembic stamp 0001_baseline`, then `alembic upgrade head` applies only
    the real migrations that follow — never this one's upgrade(), which must
    stay a no-op, because running it for real (CREATE TABLE) against the
    existing database it exists to describe would fail on tables that are
    already there.

    A brand-new database does not need this step at all: `init_db()` already
    creates the current schema (including everything later revisions add),
    so `alembic stamp head` — not `upgrade head` — is what tells Alembic that
    database is already caught up.
    """


def downgrade() -> None:
    pass
