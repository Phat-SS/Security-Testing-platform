"""Structured logging with the same redaction guarantee everything else gets.

`app.core.redaction` runs before anything is stored, reported or posted to
Jira — but a stray `logger.info(f"...{token}...")` (or an unredacted
traceback whose locals include a bearer token) bypasses all of that by going
straight to stdout/a log file. `RedactingFilter` is the second, independent
guard: it runs on every record any logger in this process emits, regardless
of which module wrote it or whether that module remembered to redact first.
"""

from __future__ import annotations

import logging
import os

from app.core.redaction import redact_any, redact_text


class RedactingFilter(logging.Filter):
    """Redacts the formatted message of every log record in place.

    Filters run *before* a handler formats a record, but `record.getMessage()`
    (which applies `%`-style args) already gives the final string — so this
    redacts that and collapses `msg`/`args` to the already-safe result, rather
    than trying to redact a format string and its args separately and risk
    missing a secret that only exists after interpolation.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken %-format must not break logging
            return True
        record.msg = redact_text(message) or ""
        record.args = ()
        return True


_configured = False


def configure_logging(level: str | None = None) -> None:
    """Idempotent: safe to call from both the CLI entrypoint and the web app's
    startup path without installing duplicate handlers.

    The filter is attached to the HANDLER, not the root logger: a logging
    Filter attached to a Logger object only runs for records logged directly
    against *that* logger, while records from `logging.getLogger("app.foo")`
    propagate up and are only ever checked against each HANDLER's own
    filters along the way. Attaching to the root logger itself would
    silently exempt every module-level `logging.getLogger(__name__)` call in
    the codebase — which is all of them.
    """
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger()
    level_name = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    root.setLevel(getattr(logging, level_name, logging.INFO))

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z",
    ))
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)


def configure_error_tracking() -> None:
    """Optional Sentry integration: on only if SENTRY_DSN is set AND the
    `sentry-sdk` package (not installed by default — see requirements.txt) is
    importable. No DSN, no import attempt, no network calls — same
    feature-gated-by-env-var shape as USE_AI/JIRA_MCP_URL/DATABASE_URL.

    `before_send` runs every event through `redact_any` first: Sentry's own
    payload (request bodies, exception locals) is exactly the kind of place a
    captured token would otherwise reach a third-party service unredacted,
    the same failure mode `app.core.redaction` exists to close everywhere
    else in this platform.
    """
    dsn = os.getenv("SENTRY_DSN")
    if not dsn:
        return
    try:
        import sentry_sdk
    except ImportError:
        logging.getLogger(__name__).warning(
            "SENTRY_DSN is set but the sentry-sdk package is not installed — "
            "error tracking stays off (pip install sentry-sdk)"
        )
        return

    sentry_sdk.init(
        dsn=dsn,
        before_send=lambda event, hint: redact_any(event),
        traces_sample_rate=0.0,  # error tracking only; no perf/APM transaction sampling
    )
