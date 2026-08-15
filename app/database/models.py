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

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, func
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


class TestCaseRow(Base):
    __tablename__ = "test_cases"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    test_id: Mapped[str] = mapped_column(String(64), index=True)
    owasp_category: Mapped[str] = mapped_column(String(16))
    approval_status: Mapped[str] = mapped_column(String(16), default="PENDING")
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


class AuditLog(Base):
    """Who did what, when, to which issue/target/test. Never stores secrets."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(64))
    assessment_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), server_default=func.now())


def default_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///sectest.db")


def make_engine(url: str | None = None):
    url = url or default_database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, future=True)


def make_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db(engine) -> None:
    Base.metadata.create_all(engine)
