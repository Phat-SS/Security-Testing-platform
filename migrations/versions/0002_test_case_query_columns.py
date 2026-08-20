"""add queryable projection columns to test_cases

Adds severity / is_destructive / source / path / search_text as real columns
on test_cases, denormalized from data_json, so Repository.query_test_cases
can filter/sort/paginate a large plan in SQL instead of loading every row's
JSON into Python first. See TestCaseRow's docstring in app/database/models.py.

Revision ID: 0002_test_case_query_columns
Revises: 0001_baseline
Create Date: 2026-08-19
"""

from __future__ import annotations

import json as _json

import sqlalchemy as sa
from alembic import op

revision = "0002_test_case_query_columns"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("test_cases", sa.Column("severity", sa.String(16), nullable=False, server_default=""))
    op.add_column(
        "test_cases", sa.Column("is_destructive", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column("test_cases", sa.Column("source", sa.String(32), nullable=False, server_default=""))
    op.add_column("test_cases", sa.Column("path", sa.String(512), nullable=False, server_default=""))
    op.add_column("test_cases", sa.Column("search_text", sa.Text(), nullable=False, server_default=""))

    op.create_index("ix_test_cases_assessment_severity", "test_cases", ["assessment_id", "severity"])
    op.create_index(
        "ix_test_cases_assessment_destructive", "test_cases", ["assessment_id", "is_destructive"]
    )
    op.create_index("ix_test_cases_assessment_source", "test_cases", ["assessment_id", "source"])

    _backfill()


def downgrade() -> None:
    op.drop_index("ix_test_cases_assessment_source", table_name="test_cases")
    op.drop_index("ix_test_cases_assessment_destructive", table_name="test_cases")
    op.drop_index("ix_test_cases_assessment_severity", table_name="test_cases")
    op.drop_column("test_cases", "search_text")
    op.drop_column("test_cases", "path")
    op.drop_column("test_cases", "source")
    op.drop_column("test_cases", "is_destructive")
    op.drop_column("test_cases", "severity")


def _backfill() -> None:
    """`server_default` only shapes the ADD COLUMN statement for existing
    rows (empty string / false) — it does not know what a row's own
    data_json actually says, so every pre-existing row needs its projection
    computed once, here, from the JSON it already has.

    This logic is intentionally a standalone copy of
    `app.database.repository._derived_columns`, not an import of it: a
    migration must keep working exactly as written even after that function
    changes shape in a later version of the app.
    """
    conn = op.get_bind()
    test_cases = sa.table(
        "test_cases",
        sa.column("id", sa.Integer),
        sa.column("data_json", sa.JSON),
        sa.column("severity", sa.String),
        sa.column("is_destructive", sa.Boolean),
        sa.column("source", sa.String),
        sa.column("path", sa.String),
        sa.column("search_text", sa.Text),
    )
    rows = conn.execute(sa.select(test_cases.c.id, test_cases.c.data_json)).fetchall()
    for row_id, data_json in rows:
        data = data_json if isinstance(data_json, dict) else _json.loads(data_json)
        request = data.get("request") or {}
        path = str(request.get("path", ""))
        search_text = " ".join(
            str(part) for part in (
                data.get("test_id", ""),
                data.get("title", ""),
                data.get("objective", ""),
                (data.get("attack_mutation") or {}).get("kind", ""),
                request.get("method", ""),
                path,
            ) if part
        ).lower()
        conn.execute(
            test_cases.update().where(test_cases.c.id == row_id).values(
                severity=str(data.get("severity", "")),
                is_destructive=bool(data.get("is_destructive")),
                source=str(data.get("source", "")),
                path=path,
                search_text=search_text,
            )
        )
