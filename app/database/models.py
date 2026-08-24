"""Persistence models (SQLAlchemy 2.0).

Pragmatic MVP shape: the rich domain objects (analysis, test cases, executions,
findings) are validated Pydantic models, stored as JSON columns keyed by
assessment. This keeps the schema small and lets the contract evolve in the
Pydantic layer without migrations for every field. Normalizing into per-field
columns is a Phase-2 concern.

Default engine is SQLite (file), so the platform runs with zero infrastructure.
Set DATABASE_URL to a Postgres DSN for production; the models are dialect-neutral.
"""

from __future__ import annotations

import os

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy import create_engine


class Base(DeclarativeBase):
    pass


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    issue_key: Mapped[str] = mapped_column(String(64), index=True)
    project_key: Mapped[str] = mapped_column(String(64), default="")
    target_base_url: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(32), default="CREATED")
    analysis_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    coverage_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    test_cases: Mapped[list["TestCaseRow"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    executions: Mapped[list["ExecutionRow"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    agent_records: Mapped[list["AgentRecordRow"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    jobs: Mapped[list["JobRow"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class TestCaseRow(Base):
    """`severity`/`is_destructive`/`source`/`path`/`search_text` are
    denormalized copies of fields already inside `data_json`, promoted to
    real columns for the same reason `owasp_category`/`approval_status`
    were: `Repository.query_test_cases` filters, sorts and paginates a plan
    that can be several hundred rows, and doing that in SQL instead of by
    loading every row's JSON into Python is what makes it scale. Kept in
    sync by the repository on every write (`save_test_cases`,
    `replace_test_cases`, `update_test_request`, `set_approval_bulk`) —
    `data_json` remains the source of truth; these columns are a queryable
    projection of it, not a second copy that can independently drift on read.
    """

    __tablename__ = "test_cases"
    __table_args__ = (
        Index("ix_test_cases_assessment_severity", "assessment_id", "severity"),
        Index("ix_test_cases_assessment_destructive", "assessment_id", "is_destructive"),
        Index("ix_test_cases_assessment_source", "assessment_id", "source"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    test_id: Mapped[str] = mapped_column(String(64), index=True)
    owasp_category: Mapped[str] = mapped_column(String(16))
    approval_status: Mapped[str] = mapped_column(String(16), default="PENDING")
    severity: Mapped[str] = mapped_column(String(16), default="")
    is_destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(32), default="")
    path: Mapped[str] = mapped_column(String(512), default="")
    search_text: Mapped[str] = mapped_column(Text, default="")
    data_json: Mapped[dict] = mapped_column(JSON)

    assessment: Mapped[Assessment] = relationship(back_populates="test_cases")


class ExecutionRow(Base):
    __tablename__ = "executions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    execution_id: Mapped[str] = mapped_column(String(64), index=True)
    test_id: Mapped[str] = mapped_column(String(64))
    result: Mapped[str] = mapped_column(String(16))
    evidence_hash: Mapped[str] = mapped_column(String(64), default="")
    data_json: Mapped[dict] = mapped_column(JSON)

    assessment: Mapped[Assessment] = relationship(back_populates="executions")


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    finding_id: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    data_json: Mapped[dict] = mapped_column(JSON)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")


class AgentRecordRow(Base):
    """What a reviewing agent said, kept beside the run rather than inside it.

    A new table, deliberately, rather than new columns on `assessments`:
    `init_db` is `create_all`, which creates a missing *table* on an existing
    database but never adds a missing *column*. Putting the plan review and the
    run assessment here means an existing `sectest.db` picks the feature up on
    the next boot instead of raising OperationalError on every read.

    One row per (assessment, kind, write). History is kept — a plan reviewed
    before and after an endpoint edit is two opinions about two different plans,
    and overwriting the first would erase the record of what was said when the
    tester approved.
    """

    __tablename__ = "agent_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    # "plan_review" | "run_assessment"
    kind: Mapped[str] = mapped_column(String(32), index=True)
    data_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())

    assessment: Mapped[Assessment] = relationship(back_populates="agent_records")


class AuditLog(Base):
    """Who did what, when, to which issue/target/test. Never stores secrets."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(64))
    assessment_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())


class JobRow(Base):
    """Persistent lifecycle for expensive operations and request deduplication."""

    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("assessment_id", "kind", "idempotency_key",
                         name="uq_jobs_assessment_kind_idempotency"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    state: Mapped[str] = mapped_column(String(16), index=True, default="QUEUED")
    idempotency_key: Mapped[str] = mapped_column(String(128))
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped["DateTime"] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    assessment: Mapped[Assessment] = relationship(back_populates="jobs")


def default_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///sectest.db")


def make_engine(url: str | None = None):
    url = url or default_database_url()
    if url.startswith("sqlite"):
        # SQLite has no server-side connection pool to configure and no
        # separate process to go stale behind a failover, so none of the
        # options below apply to it. check_same_thread=False: the platform
        # shares one engine across request threads (each session opens/closes
        # its own connection; SQLAlchemy's own locking, not a raw shared
        # connection, protects it).
        return create_engine(url, connect_args={"check_same_thread": False}, future=True)
    # Postgres (or any server DB): SQLAlchemy's engine defaults (pool_size=5,
    # no pre-ping) silently exhaust under a handful of concurrent requests —
    # a race-condition/adaptive probe alone can hold several connections open
    # at once — and go blind to a connection Postgres or a proxy in front of
    # it already dropped (failover, idle timeout), surfacing as an opaque
    # "server closed the connection unexpectedly" on the next request rather
    # than a clean retry. All four are tunable via env vars because the right
    # pool size depends on the deployment, not on this code.
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE_S", "1800")),
        future=True,
    )


def make_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db(engine) -> None:
    from sqlalchemy import inspect

    from app.database.migrate import bootstrap_alembic

    was_fresh = not inspect(engine).get_table_names()
    # Migrations run against the database's true pre-existing schema first,
    # so a migration that creates a brand-new table (e.g. 0003_jobs) is the
    # one thing that creates it. Running create_all() beforehand would create
    # that same table ahead of the migration (its model already lives in
    # Base.metadata by the time the migration exists), leaving alembic_version
    # stuck behind head and the migration failing with "table already exists"
    # on every subsequent startup. create_all() runs after purely as a
    # catch-all for tables that don't have a migration at all yet; it no-ops
    # on anything migrations already created.
    bootstrap_alembic(engine, was_fresh=was_fresh)
    Base.metadata.create_all(engine)
