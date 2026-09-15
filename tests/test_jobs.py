from app.database import Repository, init_db, make_engine, make_session_factory
from app.database.migrate import bootstrap_alembic, current_revision, head_revision, head_revisions
from sqlalchemy import inspect, text


def _repo() -> Repository:
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    return Repository(make_session_factory(engine))


def test_jobs_are_idempotent_and_follow_the_state_machine():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM")

    job, created = repo.create_job("A-1", "execute", "request-123")
    duplicate, duplicate_created = repo.create_job("A-1", "execute", "request-123")

    assert created is True
    assert duplicate_created is False
    assert duplicate.job_id == job.job_id
    assert job.state == "QUEUED"
    assert repo.transition_job(job.job_id, "RUNNING").state == "RUNNING"
    done = repo.transition_job(job.job_id, "SUCCEEDED", result={"count": 3})
    assert done.state == "SUCCEEDED"
    assert repo.get_job(job.job_id).result == {"count": 3}


def test_terminal_job_cannot_be_reopened():
    repo = _repo()
    repo.create_assessment("A-1", "CRM-1", "CRM")
    job, _ = repo.create_job("A-1", "execute", "once")
    repo.transition_job(job.job_id, "RUNNING")
    repo.transition_job(job.job_id, "FAILED", error="timeout")

    try:
        repo.transition_job(job.job_id, "RUNNING")
    except ValueError as exc:
        assert "FAILED -> RUNNING" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("terminal job was reopened")


def test_the_migration_history_has_not_branched():
    """Two migrations written against the same parent leave `upgrade head` with
    nothing to choose between, and it refuses rather than guessing. Cheaper to
    learn here than during a deployment."""
    assert head_revisions() == [head_revision()]


def test_a_fresh_database_is_stamped_at_head(tmp_path):
    """Asserted against alembic's own head rather than a literal revision id.
    The literal was the thing that went stale on every migration — and a test
    that has to be edited to stay green stops being read as a claim."""
    engine = make_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    init_db(engine)

    assert "jobs" in inspect(engine).get_table_names()
    assert current_revision(engine) == head_revision()


def test_existing_baseline_database_is_upgraded_on_the_engine_that_was_passed(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE assessments (id VARCHAR(64) PRIMARY KEY)"))
        connection.execute(text(
            "CREATE TABLE test_cases (id INTEGER PRIMARY KEY, assessment_id VARCHAR(64), "
            "test_id VARCHAR(64), owasp_category VARCHAR(16), approval_status VARCHAR(16), "
            "data_json JSON NOT NULL)"
        ))

    bootstrap_alembic(engine, was_fresh=False)

    tables = inspect(engine).get_table_names()
    columns = {column["name"] for column in inspect(engine).get_columns("test_cases")}
    assert "jobs" in tables
    assert {"severity", "is_destructive", "source", "path", "search_text"} <= columns
    assert current_revision(engine) == head_revision()
