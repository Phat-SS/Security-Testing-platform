"""the authorization context each run was sent under

Revision ID: 0004_run_snapshots
Revises: 0003_jobs
Create Date: 2026-09-15
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_run_snapshots"
down_revision = "0003_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_snapshots",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("assessment_id", sa.String(length=64), nullable=False),
        # sha256 of the captured context; also what each execution carries, so
        # a record can be traced back to the authorization it ran under.
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("data_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"]),
        sa.PrimaryKeyConstraint("id"),
        # One row per distinct configuration per assessment: re-running under
        # an unchanged engagement should not accumulate identical copies, and
        # the same fingerprint must always mean the same context.
        sa.UniqueConstraint("assessment_id", "fingerprint",
                            name="uq_run_snapshots_assessment_fingerprint"),
    )
    op.create_index("ix_run_snapshots_assessment_id", "run_snapshots", ["assessment_id"])
    op.create_index("ix_run_snapshots_fingerprint", "run_snapshots", ["fingerprint"])


def downgrade() -> None:
    op.drop_table("run_snapshots")
