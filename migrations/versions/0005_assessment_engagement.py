"""which engagement each assessment belongs to

Revision ID: 0005_assessment_engagement
Revises: 0004_run_snapshots
Create Date: 2026-09-15
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_assessment_engagement"
down_revision = "0004_run_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Empty for every existing row, and read as "whichever engagement is
    # current" — which is exactly what those assessments already meant when
    # there was only one. Nothing needs backfilling, and an install that never
    # adds a second engagement never notices this column.
    op.add_column(
        "assessments",
        sa.Column("engagement", sa.String(length=64), nullable=False, server_default=""),
    )
    op.create_index("ix_assessments_engagement", "assessments", ["engagement"])


def downgrade() -> None:
    op.drop_index("ix_assessments_engagement", table_name="assessments")
    op.drop_column("assessments", "engagement")
