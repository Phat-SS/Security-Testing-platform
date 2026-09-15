"""The live run panel.

A run used to be invisible while it happened: the browser sat on a POST until
the last test had been sent, then redirected to a finished page. The only
signals available were a spinner and, if a proxy gave up first, a timeout page
in front of a run that was still going.

This is what replaces that — verdict counts as they land and the failures
themselves the moment they are decided. It is a *view* of the run, not a
control over it: nothing here can change what is sent.

The panel refreshes by fetching its own markup and swapping it in, rather than
by re-rendering from JSON in the browser. One renderer, server-side, in the
language the viewer chose — the alternative is a second copy of every verdict
colour and label living in a script, drifting from this one.
"""

from __future__ import annotations

from app.api import ui
from app.api.ui import attr, e
from app.core.i18n import VI, tt as _t

#: Verdicts in the order the strip shows them: what broke first, what needs a
#: person next, and what held up last. A run whose bar is mostly grey is a
#: configuration problem, and that reads at a glance.
_ORDER = (
    ("FAIL", "crit"),
    ("INCONCLUSIVE", "med"),
    ("PASS", "low"),
    ("BLOCKED", "info"),
    ("ERROR", "high"),
)

RUNNING_STATES = ("QUEUED", "RUNNING")


def _bar(verdicts: dict, done: int) -> str:
    if not done:
        return '<div class="runbar"></div>'
    segments = "".join(
        f'<span style="width:{100 * verdicts.get(name, 0) / done:.4f}%;'
        f'background:var(--{tone})"></span>'
        for name, tone in _ORDER if verdicts.get(name)
    )
    return f'<div class="runbar">{segments}</div>'


def _legend(verdicts: dict) -> str:
    cells = "".join(
        f'<span class="runleg"><i style="background:var(--{tone})"></i>'
        f'{e(_t(name.title()))}<b>{verdicts.get(name, 0)}</b></span>'
        for name, tone in _ORDER
    )
    return f'<div class="runlegs">{cells}</div>'


def _feed_rows(recent: list[dict]) -> str:
    """Most recent first — the row a watcher wants is the one that just
    happened, not the one from four minutes ago."""
    if not recent:
        return f'<div class="runrow only-muted">{_t("Nothing has come back yet.")}</div>'
    out = ""
    for row in reversed(recent):
        result = str(row.get("result") or "")
        tone = ui.VERDICT_CLASS.get(result, "info")
        status = row.get("status")
        ms = row.get("ms")
        out += (
            f'<div class="runrow{" fail" if result in ("FAIL", "ERROR") else ""}">'
            f'<span class="mono b">{e(row.get("test_id") or "")}</span>'
            f'<span class="pill {tone}">{e(result)}</span>'
            f'<span class="reason">{e(row.get("reason") or "")}</span>'
            f'<span class="mono muted">{e(status if status is not None else "—")}</span>'
            f'<span class="mono muted">{e(f"{ms} ms" if ms is not None else "—")}</span>'
            "</div>"
        )
    return out


def panel_fragment(aid: str, job) -> str:
    """Everything that changes while a run is in flight.

    Fetched whole by the poll below and swapped in, so the served markup and
    the refreshed markup are the same markup.
    """
    if job is None or job.kind != "execute":
        return ""
    progress = dict(getattr(job, "result", None) or {})
    verdicts = dict(progress.get("verdicts") or {})
    done = int(progress.get("done") or 0)
    total = int(progress.get("total") or 0)
    running = job.state in RUNNING_STATES

    if running:
        heading, tone = _t("Running"), "warn"
    elif job.state == "FAILED":
        heading, tone = _t("Run failed"), "err"
    else:
        heading, tone = _t("Run finished"), "flash"

    eta = ""
    if running and progress.get("eta_s") is not None:
        eta = _t("about {n}s left").format(n=progress["eta_s"])
    elif progress.get("elapsed_s"):
        eta = _t("took {n}s").format(n=progress["elapsed_s"])

    error = ""
    if job.state == "FAILED" and job.error:
        error = f'<p class="muted mono" style="margin:8px 0 0">{e(job.error)}</p>'

    # The poll reads this to know the run has settled. A data attribute on the
    # host would not survive `innerHTML`, which replaces only the children.
    finished = "" if running else '<span id="run-finished" hidden></span>'

    return f"""{finished}<div class="card pad {tone}" style="margin-bottom:14px">
<div class="row" style="justify-content:space-between;align-items:baseline">
<div class="row" style="gap:8px;align-items:baseline">
<b>{e(heading)}</b>
<span class="mono" style="font-size:18px;font-weight:700">{done}<span class="muted"
 style="font-size:13px;font-weight:400"> / {total} {_t("sent")}</span></span>
</div>
<span class="muted mono" style="font-size:12.5px">{e(eta)}</span>
</div>
{_bar(verdicts, done)}
{_legend(verdicts)}
{error}
</div>
<div class="card" style="margin-bottom:14px">
<div class="runfeed-head">{_t("As they land")}</div>
{_feed_rows(progress.get("recent") or [])}
</div>"""


def live_panel(aid: str, job) -> str:
    """The panel plus the poll that keeps it current.

    Rendered even for a run that has already finished: arriving at a completed
    run should show its counts, not an empty frame a script then fills in — and
    a browser with JavaScript off still gets everything except the updates.
    """
    fragment = panel_fragment(aid, job)
    if not fragment:
        return ""
    running = job.state in RUNNING_STATES
    return (
        f'<div id="run-live" data-aid="{attr(aid)}" data-running="{"1" if running else "0"}">'
        f"{fragment}</div>{_POLL_JS}"
    )


_POLL_JS = """
<script>
(function () {
  var host = document.getElementById('run-live');
  if (!host || host.dataset.running !== '1') return;
  var aid = host.dataset.aid;
  var inFlight = false;
  // A fixed interval, not a backoff: a run is minutes at most, and the person
  // watching is waiting for the FAIL the moment it is decided.
  var timer = setInterval(function () {
    if (inFlight) return;
    inFlight = true;
    fetch('/assessment/' + encodeURIComponent(aid) + '/run-panel')
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        if (html === null) return;
        host.innerHTML = html;
        if (host.dataset.done === '1') return;
        if (document.getElementById('run-finished')) {
          host.dataset.done = '1';
          clearInterval(timer);
          // The findings are only assembled once the run ends, so this is the
          // handover to the finished page rather than a refresh of this one.
          window.location.href =
            '/assessment/' + encodeURIComponent(aid) + '?phase=results';
        }
      })
      .catch(function () {})
      .then(function () { inFlight = false; });
  }, 1500);
})();
</script>
"""

VI.update({
    "Running": "Đang chạy", "Run finished": "Đã chạy xong", "Run failed": "Chạy thất bại",
    "sent": "đã gửi", "As they land": "Kết quả về dần",
    "Nothing has come back yet.": "Chưa có kết quả nào.",
    "about {n}s left": "còn khoảng {n}s", "took {n}s": "mất {n}s",
    "Fail": "Lỗi", "Inconclusive": "Chưa kết luận", "Pass": "Đạt",
    "Blocked": "Bị chặn", "Error": "Lỗi hệ thống",
})
