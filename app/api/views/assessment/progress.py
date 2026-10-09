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

import math

from app.api import ui
from app.api.ui import attr, e
from app.core.i18n import VI, tt as _t

#: Verdicts in the order the strip shows them: what broke first, what needs a
#: person next, and what held up last. A run whose bar is mostly grey is a
#: configuration problem, and that reads at a glance.
_ORDER = (
    ("FAIL", "crit"),
    ("INCONCLUSIVE", "med"),
    ("PASS", "ok"),
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


def _radar(verdicts: dict, done: int) -> str:
    """The Sentinel mark at run scale: the sweep turns while the run is live
    (CSS, `.runcard.live`), and each verdict lands as a blip. Blip positions
    are fixed per index so the picture does not jump on every poll; colours
    come from the same tones as the bar and legend."""
    blips = []
    i = 0
    for name, tone in _ORDER:
        for _ in range(min(verdicts.get(name, 0), 24 - len(blips))):
            # A golden-angle spiral: even spread, stable for a given index.
            angle = i * 2.39996
            radius = 14 + (i * 37 % 34)
            x, y = 60 + radius * math.cos(angle), 60 + radius * math.sin(angle)
            blips.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.2" fill="var(--{tone})"/>')
            i += 1
    return (
        '<svg class="radar" viewBox="0 0 120 120" width="112" height="112" aria-hidden="true">'
        '<circle cx="60" cy="60" r="54" fill="var(--bg)" stroke="var(--border)"/>'
        '<circle cx="60" cy="60" r="36" fill="none" stroke="var(--border)"/>'
        '<circle cx="60" cy="60" r="18" fill="none" stroke="var(--border)"/>'
        '<g class="sweep"><path d="M60 60 L60 6 A54 54 0 0 1 106.8 33 Z" '
        'fill="var(--accent)" opacity=".18"/></g>'
        + "".join(blips)
        + '<circle cx="60" cy="60" r="3" fill="var(--accent)"/></svg>'
    )


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
        heading, tone = _t("Run Failed"), "err"
    else:
        heading, tone = _t("Run Finished"), "flash"

    eta = ""
    if running and progress.get("eta_s") is not None:
        eta = _t("about {n}s left").format(n=progress["eta_s"])
    elif progress.get("elapsed_s"):
        eta = _t("took {n}s").format(n=progress["elapsed_s"])

    error = ""
    if job.state == "FAILED" and job.error:
        error = f'<p class="muted mono" style="margin:8px 0 0">{e(job.error)}</p>'

    # The poll reads this to know the run has settled, and whether it settled
    # well enough to hand over to the report. A data attribute on the host would
    # not survive `innerHTML`, which replaces only the children.
    if running:
        finished = ""
    else:
        ok = "0" if job.state == "FAILED" else "1"
        finished = f'<span id="run-finished" data-ok="{ok}" hidden></span>'

    return f"""{finished}<div class="card pad {tone} runcard{' live' if running else ''}" style="margin-bottom:14px">
{_radar(verdicts, done)}
<div class="runinfo">
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
</div></div>
<div class="card" style="margin-bottom:14px">
<div class="runfeed-head">{_t("As They Land")}</div>
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
        // The swap replaces the radar every poll; a negative delay keeps the
        // sweep's phase continuous instead of snapping back to 12 o'clock.
        var sweep = host.querySelector('.radar .sweep');
        if (sweep) sweep.style.animationDelay = '-' + (performance.now() % 2600) + 'ms';
        if (host.dataset.done === '1') return;
        var end = document.getElementById('run-finished');
        if (end) {
          host.dataset.done = '1';
          clearInterval(timer);
          // The findings are only assembled once the run ends, so this is the
          // handover to the report rather than a refresh of this panel. A
          // failed run stays here: its error is on this panel, and the report
          // would have nothing to show for it.
          if (end.dataset.ok === '1') {
            window.location.href =
              '/assessment/' + encodeURIComponent(aid) + '/report';
          }
        }
      })
      .catch(function () {})
      .then(function () { inFlight = false; });
  }, 1500);
})();
</script>
"""

VI.update({
    "Running": "Đang Chạy", "Run Finished": "Đã Chạy Xong", "Run Failed": "Chạy Thất Bại",
    "sent": "đã gửi", "As They Land": "Kết Quả Về Dần",
    "Nothing has come back yet.": "Chưa có kết quả nào.",
    "about {n}s left": "còn khoảng {n}s", "took {n}s": "mất {n}s",
    "Fail": "Lỗi", "Inconclusive": "Chưa Kết Luận", "Pass": "Đạt",
    "Blocked": "Bị Chặn", "Error": "Lỗi Hệ Thống",
})
