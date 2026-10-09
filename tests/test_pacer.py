"""The run-wide request clock: a rate ceiling, and backing off after a 429.

Neither may change what a probe measures. A rate-limit or race burst goes out
unpaced, and a 429 is recorded as the answer it is — nothing is resent.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from app.core.config import RunnerLimits, Settings, settings_with_overrides
from app.execution.http_runner import Pacer, retry_after_seconds


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.slept.append(round(s, 3))
        self.now += s


def test_no_ceiling_means_no_waiting():
    clock = _Clock()
    pacer = Pacer(0, clock=clock, sleep=clock.sleep)
    for _ in range(5):
        pacer.wait()
    assert clock.slept == []


def test_a_ceiling_spaces_requests_evenly():
    clock = _Clock()
    pacer = Pacer(4, clock=clock, sleep=clock.sleep)  # 4/s → 0.25s apart
    for _ in range(4):
        pacer.wait()
    assert clock.slept == [0.25, 0.25, 0.25]


def test_a_429_holds_every_later_request_but_is_capped():
    clock = _Clock()
    pacer = Pacer(0, max_pause_s=10, clock=clock, sleep=clock.sleep)
    pacer.hold(3)
    pacer.wait()
    assert clock.slept == [3.0]
    pacer.hold(600)  # a hostile Retry-After cannot stall the run for ten minutes
    pacer.wait()
    assert clock.slept[-1] == 10.0


def test_the_clock_is_shared_safely_across_threads():
    pacer = Pacer(1000)
    errors = []

    def worker():
        try:
            for _ in range(50):
                pacer.wait()
        except Exception as exc:  # pragma: no cover - would fail the test
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


@pytest.mark.parametrize("headers, expected", [
    ({}, 2.0),
    ({"retry-after": "7"}, 7.0),
    ({"retry-after": "soon"}, 2.0),
    ({"retry-after": "-5"}, 0.0),
])
def test_retry_after_is_read_as_seconds(headers, expected):
    assert retry_after_seconds(headers) == expected


def test_retry_after_accepts_an_http_date():
    when = datetime.now(timezone.utc) + timedelta(seconds=20)
    assert 15 <= retry_after_seconds({"retry-after": format_datetime(when, usegmt=True)}) <= 20


def test_the_ceiling_is_an_engagement_override(monkeypatch):
    monkeypatch.delenv("RUNNER_MAX_RPS", raising=False)
    assert Settings.from_env().limits.max_requests_per_second == 0
    assert settings_with_overrides({"max_requests_per_second": "2.5"}).limits \
        .max_requests_per_second == 2.5
    assert RunnerLimits().max_throttle_pause_s == 30.0


def test_a_429_response_slows_the_next_request_without_resending():
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from app.core.scope import ScopePolicy, ScopeValidator
    from app.execution.http_runner import HttpRunner
    from app.vault.personas import PersonaVault

    sent = []

    async def endpoint(request):
        sent.append(request.url.path)
        if len(sent) == 1:
            return JSONResponse({}, status_code=429, headers={"retry-after": "4"})
        return JSONResponse({})

    app = Starlette(routes=[Route("/a", endpoint), Route("/b", endpoint)])
    client = TestClient(app, base_url="https://api.example.com")
    runner = HttpRunner(
        "https://api.example.com",
        ScopeValidator(ScopePolicy(allowed_hosts={"api.example.com"}),
                       resolver=lambda h: "203.0.113.10"),
        PersonaVault(), Settings.from_env(), client=client,
    )
    clock = _Clock()
    runner._pacer = Pacer(0, clock=clock, sleep=clock.sleep)
    runner._send("GET", "https://api.example.com/a", {}, {}, None, None)
    runner._send("GET", "https://api.example.com/b", {}, {}, None, None)

    assert sent == ["/a", "/b"], "the 429 must not be resent"
    assert clock.slept == [4.0]


def test_a_zero_engagement_ceiling_overrides_a_dotenv_cap(monkeypatch):
    monkeypatch.setenv("RUNNER_MAX_RPS", "5")
    assert settings_with_overrides({"max_requests_per_second": 0}).limits.max_requests_per_second == 0
    # ...but a zero timeout would disable execution, so it is still ignored.
    assert settings_with_overrides({"timeout_s": 0}).limits.timeout_s > 0
