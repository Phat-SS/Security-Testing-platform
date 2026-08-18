"""Shared UI primitives for the server-rendered views.

Split out of `views.py` so the page builders read as page structure rather than
as a wall of inline markup, and so the pieces that have to behave *identically*
everywhere — the tooltip, a collapsible section, a scrollable table with a
sticky header — have exactly one implementation.

Everything here is dependency-free: no build step, no CDN, no framework. The
interactive parts are progressive enhancement over markup that already works
without JavaScript (a `<details>` still opens, a filter form is still a GET).
"""

from __future__ import annotations

import html

# -- escaping ---------------------------------------------------------------


def e(v) -> str:
    return html.escape(str(v))


def attr(v) -> str:
    """Escape for use inside a double-quoted attribute, quotes included."""
    return html.escape(str(v), quote=True)


# -- tooltips ---------------------------------------------------------------
#
# A CSS-only tooltip cannot be used here. Every table on these pages lives in a
# horizontally scrollable wrapper, and `overflow-x: auto` forces `overflow-y` to
# a scrolling value too — an absolutely-positioned bubble anchored to a `<th>`
# is therefore clipped by the wrapper instead of overflowing it. So there is one
# shared `position: fixed` bubble, placed from getBoundingClientRect(), which no
# ancestor can clip.


def info(text: str, label: str = "") -> str:
    """The small ⓘ affix that explains a column or a control.

    `title` is set as well as `data-tip`, so the explanation survives with
    JavaScript disabled and is what a screen reader announces.
    """
    aria = label or "More information"
    return (
        f'<span class="i" tabindex="0" role="note" aria-label="{attr(aria + ": " + text)}" '
        f'title="{attr(text)}" data-tip="{attr(text)}">i</span>'
    )


TOOLTIP_JS = """
(function () {
  var tip = null;
  function bubble() {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'tipbox';
      tip.setAttribute('role', 'tooltip');
      document.body.appendChild(tip);
    }
    return tip;
  }
  function show(el) {
    var text = el.getAttribute('data-tip');
    if (!text) return;
    var b = bubble();
    b.textContent = text;
    b.style.display = 'block';
    // Measure after the text is in, then clamp inside the viewport. Fixed
    // positioning is what keeps the bubble out of every scroll container's
    // clipping box.
    var r = el.getBoundingClientRect();
    var w = b.offsetWidth, h = b.offsetHeight;
    var left = Math.min(Math.max(8, r.left + r.width / 2 - w / 2), window.innerWidth - w - 8);
    var top = r.top - h - 8;
    if (top < 8) top = r.bottom + 8;          // no room above → flip below
    b.style.left = left + 'px';
    b.style.top = top + 'px';
  }
  function hide() { if (tip) tip.style.display = 'none'; }
  function bind(root) {
    root.querySelectorAll('[data-tip]').forEach(function (el) {
      if (el.dataset.tipBound) return;
      el.dataset.tipBound = '1';
      el.addEventListener('mouseenter', function () { show(el); });
      el.addEventListener('mouseleave', hide);
      el.addEventListener('focus', function () { show(el); });
      el.addEventListener('blur', hide);
    });
  }
  bind(document);
  window.__bindTips = bind;
  document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') hide(); });
  window.addEventListener('scroll', hide, true);
  window.addEventListener('resize', hide);
})();
"""


# -- theme ------------------------------------------------------------------
#
# `prefers-color-scheme` alone means a tester on a light OS cannot get the dark
# page they want for a long review session. The toggle writes `data-theme` on
# <html>, which the CSS honours over the media query in both directions, and
# remembers the choice.

THEME_TOGGLE_HTML = (
    '<button type="button" class="btn ghost iconbtn" id="theme-toggle" '
    'aria-label="Switch between light and dark" data-tip="Switch between light and dark">'
    '<span aria-hidden="true" id="theme-glyph">◐</span></button>'
)

THEME_JS = """
(function () {
  var root = document.documentElement;
  var stored = null;
  try { stored = localStorage.getItem('stp-theme'); } catch (err) {}
  if (stored === 'dark' || stored === 'light') root.setAttribute('data-theme', stored);
  var btn = document.getElementById('theme-toggle');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var dark = root.getAttribute('data-theme') === 'dark' ||
      (!root.hasAttribute('data-theme') &&
        window.matchMedia('(prefers-color-scheme: dark)').matches);
    var next = dark ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('stp-theme', next); } catch (err) {}
  });
})();
"""


# -- sections ---------------------------------------------------------------


def section(
    sid: str,
    number: str,
    title: str,
    body: str,
    *,
    summary: str = "",
    actions: str = "",
    open: bool = True,
    tip: str = "",
    tone: str = "",
) -> str:
    """A numbered, collapsible step of the workflow.

    Collapsing is the answer to the page being long: a finished step folds down
    to one line that still says what it produced. `<details>` does the work, so
    it survives with JavaScript off; the JS only remembers the open/closed state
    per assessment.
    """
    tip_html = " " + info(tip, title) if tip else ""
    sum_html = f'<span class="s-sum">{summary}</span>' if summary else ""
    act_html = f'<div class="s-act">{actions}</div>' if actions else ""
    return f"""<details class="sect {e(tone)}" id="{attr(sid)}" data-sect="{attr(sid)}"{" open" if open else ""}>
<summary class="s-head"><span class="s-chev" aria-hidden="true"></span>
<span class="s-num">{e(number)}</span><span class="s-title">{e(title)}</span>{tip_html}
{sum_html}</summary>
<div class="s-body">{act_html}{body}</div>
</details>"""


SECTION_JS = """
(function () {
  // Remember which steps a tester had open, keyed per page, so navigating back
  // does not silently re-collapse the section they were working in.
  var key = 'stp-open:' + location.pathname;
  var open = {};
  try { open = JSON.parse(localStorage.getItem(key) || '{}'); } catch (err) {}
  document.querySelectorAll('details[data-sect]').forEach(function (d) {
    var id = d.dataset.sect;
    if (Object.prototype.hasOwnProperty.call(open, id)) d.open = !!open[id];
    d.addEventListener('toggle', function () {
      open[id] = d.open;
      try { localStorage.setItem(key, JSON.stringify(open)); } catch (err) {}
    });
  });
  // A link to a collapsed section has to open it, or the jump lands on a
  // one-line summary and looks broken.
  function reveal(hash) {
    if (!hash) return;
    var target = document.querySelector(hash);
    if (!target) return;
    var d = target.closest('details[data-sect]') || target;
    if (d.tagName === 'DETAILS') d.open = true;
    target.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }
  document.querySelectorAll('a[href^="#"]').forEach(function (a) {
    a.addEventListener('click', function (ev) {
      var hash = a.getAttribute('href');
      if (hash.length < 2) return;
      ev.preventDefault();
      reveal(hash);
      history.replaceState(null, '', hash);
    });
  });
  if (location.hash) setTimeout(function () { reveal(location.hash); }, 0);
})();
"""


# -- stat strip -------------------------------------------------------------


def stats(cells: list[tuple[str, str, str, str]]) -> str:
    """The run-at-a-glance strip: (value, label, tooltip, href).

    Each cell is a link into the section that owns the number, so the strip is
    also the page's table of contents.
    """
    out = ""
    for value, label, tip, href in cells:
        inner = (
            f'<div class="num">{value}</div>'
            f'<div class="lbl">{e(label)}{" " + info(tip, label) if tip else ""}</div>'
        )
        out += (
            f'<a class="cell" href="{attr(href)}">{inner}</a>' if href
            else f'<div class="cell">{inner}</div>'
        )
    return f'<div class="summary-row">{out}</div>'


# -- tables -----------------------------------------------------------------


def table(
    headers: list[str],
    rows: str,
    *,
    empty: str = "",
    scroll: bool = False,
    cls: str = "",
    caption: str = "",
) -> str:
    """A table with a real `<thead>`.

    `scroll=True` caps the height and pins the header row, so a 300-test plan
    scrolls inside its own box instead of turning the page into a mile of rows.
    """
    n = len(headers)
    head = "".join(f'<th scope="col">{h}</th>' for h in headers)
    body = rows or (
        f'<tr><td colspan="{n}" class="muted empty">{empty or "Nothing here yet."}</td></tr>'
    )
    cap = f"<caption>{e(caption)}</caption>" if caption else ""
    wrap_cls = "tblwrap scroll" if scroll else "tblwrap"
    return (
        f'<div class="{wrap_cls}"><table class="{e(cls)}">{cap}'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def bar(pct: int, tone: str, label: str) -> str:
    return (
        f'<div class="bar" role="img" aria-label="{attr(label)}" data-tip="{attr(label)}">'
        f'<div class="fill" style="width:{max(0, min(100, pct))}%;background:var(--{e(tone)})"></div></div>'
    )


def pill(text: str, tone: str, tip: str = "") -> str:
    tip_attr = f' data-tip="{attr(tip)}" tabindex="0"' if tip else ""
    return f'<span class="pill {e(tone)}"{tip_attr}>{e(text)}</span>'


# -- CSS --------------------------------------------------------------------
#
# Appended to the base stylesheet in views.py. Light values live on bare
# :root; the dark overrides are declared twice — once under the media query
# (guarded so an explicit light choice wins) and once under [data-theme="dark"]
# (so the toggle wins in both directions).

CSS = """
:root{
  --radius-lg:10px;
  --space:8px;
  --tip-bg:#1b2426;--tip-fg:#f2f7f6;
  --zebra:#fbfcfc;
  --sticky-bg:#f2f5f4;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --tip-bg:#e8f1ef;--tip-fg:#0d1517;
  --zebra:#151e20;
  --sticky-bg:#182224;
}}
:root[data-theme="dark"]{
  --bg:#0b1113;--surface:#121a1c;--fg:#e6efed;--muted:#8ea3a1;--faint:#5e7472;
  --border:#223032;--border-strong:#2c3d3e;
  --accent:#34c2bd;--accent-ink:#06201f;--accent-soft:#163333;--accent-border:#1f4b48;
  --crit:#e05a68;--high:#e08a4a;--med:#d4af37;--low:#4caf7d;--info:#8b98a3;
  --crit-soft:#2a1418;--high-soft:#2a1f11;--med-soft:#2a250f;--low-soft:#122a1c;--info-soft:#1a2022;
  --shadow:0 1px 2px rgba(0,0,0,.3);
  --tip-bg:#e8f1ef;--tip-fg:#0d1517;
  --zebra:#151e20;
  --sticky-bg:#182224;
}
:root[data-theme="light"]{
  --bg:#f6f7f6;--surface:#ffffff;--fg:#12181b;--muted:#5b6b6d;--faint:#8a9698;
  --border:#dde3e2;--border-strong:#c7d0cf;
  --accent:#0d6e6e;--accent-ink:#ffffff;--accent-soft:#e3f2f1;--accent-border:#bfe0de;
  --crit:#b4232a;--high:#c8500f;--med:#96700a;--low:#2f7a4f;--info:#5c6b74;
  --crit-soft:#fbe6e8;--high-soft:#fbead9;--med-soft:#f7edd0;--low-soft:#e1f2e7;--info-soft:#eaecee;
  --shadow:0 1px 2px rgba(20,30,30,.05),0 1px 1px rgba(20,30,30,.04);
  --tip-bg:#1b2426;--tip-fg:#f2f7f6;
  --zebra:#fbfcfc;
  --sticky-bg:#f2f5f4;
}

/* the ⓘ affix + its shared bubble */
.i{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;
  border-radius:50%;border:1px solid var(--border-strong);color:var(--faint);
  font-size:9.5px;font-weight:700;font-style:normal;line-height:1;cursor:help;
  vertical-align:1px;margin-left:4px;text-transform:none;letter-spacing:0;flex:none;}
.i:hover,.i:focus{color:var(--accent);border-color:var(--accent);outline:none;}
.tipbox{position:fixed;display:none;z-index:60;max-width:320px;background:var(--tip-bg);
  color:var(--tip-fg);font-size:12.5px;line-height:1.45;font-weight:400;text-transform:none;
  letter-spacing:0;padding:8px 10px;border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,.22);
  pointer-events:none;}

/* page head — distinct from the app topbar it used to borrow */
.pagehead{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
  flex-wrap:wrap;margin-bottom:16px;}
.pagehead h1{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.iconbtn{padding:6px 8px;font-size:15px;line-height:1;}
.copy{background:none;border:0;color:var(--faint);cursor:pointer;padding:0 4px;font-size:12px;}
.copy:hover{color:var(--accent);}

/* stat strip */
.summary-row a.cell{text-decoration:none;color:inherit;transition:background .12s;}
.summary-row a.cell:hover{background:var(--accent-soft);}
.summary-row .num{display:flex;align-items:baseline;gap:5px;flex-wrap:wrap;}
.summary-row .lbl{display:flex;align-items:center;}
.sevdots{display:inline-flex;gap:3px;align-items:center;font-size:12px;font-weight:700;}
.sevdots span{display:inline-flex;align-items:center;gap:2px;}

/* step nav */
.stepnav{position:sticky;top:0;z-index:30;display:flex;gap:2px;overflow-x:auto;
  background:var(--bg);border-bottom:1px solid var(--border);margin:0 0 18px;padding:6px 0;
  scrollbar-width:thin;}
.stepnav a{display:flex;align-items:center;gap:6px;white-space:nowrap;text-decoration:none;
  color:var(--muted);font-size:12.5px;font-weight:600;padding:5px 10px;border-radius:999px;}
.stepnav a:hover{background:var(--surface);color:var(--fg);}
.stepnav a.on{background:var(--surface);color:var(--fg);border:1px solid var(--border);}
.stepnav a .dot{width:7px;height:7px;border-radius:50%;background:var(--border-strong);flex:none;}
.stepnav a.done .dot{background:var(--low);}
.stepnav a.current .dot{background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);}
.stepnav a .n{color:var(--faint);font-weight:600;font-variant-numeric:tabular-nums;}

/* collapsible section */
.sect{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);
  box-shadow:var(--shadow);margin-bottom:14px;overflow:hidden;}
.sect.attn{border-color:var(--accent-border);}
.s-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding:13px 16px;cursor:pointer;
  list-style:none;user-select:none;}
.s-head::-webkit-details-marker{display:none;}
.s-head:hover{background:var(--accent-soft);}
.s-chev{width:0;height:0;border:5px solid transparent;border-left-color:var(--faint);
  margin-left:2px;transition:transform .15s;flex:none;}
.sect[open] .s-chev{transform:rotate(90deg) translateX(-1px);}
.s-num{font-size:11px;font-weight:700;color:var(--accent);background:var(--accent-soft);
  border-radius:4px;padding:2px 6px;font-variant-numeric:tabular-nums;flex:none;}
.s-title{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;}
.s-sum{margin-left:auto;font-size:12.5px;color:var(--muted);text-align:right;}
.s-body{padding:0 16px 16px;border-top:1px solid var(--border);padding-top:14px;}
.s-act{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;}
@media (prefers-reduced-motion:reduce){.s-chev{transition:none;}}

/* tables */
table thead th{background:var(--sticky-bg);}
.tblwrap.scroll{max-height:60vh;overflow:auto;}
.tblwrap.scroll thead th{position:sticky;top:0;z-index:2;}
tbody tr:nth-child(even){background:var(--zebra);}
tbody tr:hover{background:var(--accent-soft);}
td.empty{text-align:center;padding:22px 10px;}
table.compact th,table.compact td{padding:5px 8px;font-size:13px;}
td .trunc{display:inline-block;max-width:280px;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;vertical-align:bottom;}
.rowact{display:flex;gap:4px;justify-content:flex-end;}
.bar{position:relative;}

/* toolbar above a big table */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;
  padding:0 0 12px;border-bottom:1px solid var(--border);margin-bottom:12px;}
.toolbar .grow{flex:1;min-width:180px;}
.toolbar select,.toolbar input{width:auto;}
.toolbar label.field span{white-space:nowrap;}
.selbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:9px 12px;
  background:var(--accent-soft);border:1px solid var(--accent-border);
  border-radius:var(--radius);margin-bottom:12px;}
.selbar.off{display:none;}
.selbar b{font-variant-numeric:tabular-nums;}
.pager{display:flex;gap:4px;align-items:center;justify-content:center;flex-wrap:wrap;
  padding-top:12px;margin-top:12px;border-top:1px solid var(--border);}
.pager a,.pager span{min-width:30px;text-align:center;padding:4px 8px;border-radius:5px;
  font-size:13px;text-decoration:none;color:var(--muted);}
.pager a:hover{background:var(--accent-soft);color:var(--fg);}
.pager .on{background:var(--accent);color:var(--accent-ink);font-weight:700;}
.pager .gap{color:var(--faint);}
.count{font-size:12.5px;color:var(--faint);white-space:nowrap;}

/* inline editing row */
tr.editing{background:var(--accent-soft);}
tr.editing input,tr.editing select{padding:5px 7px;font-size:13px;}
.addrow{background:var(--bg);}
.kchip{display:inline-block;background:var(--info-soft);color:var(--info);border-radius:4px;
  padding:1px 6px;font-size:11.5px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
  margin-right:3px;}
.flagdot{display:inline-block;width:8px;height:8px;border-radius:50%;}
.flagdot.on{background:var(--low);}
.flagdot.off{background:var(--border-strong);}

/* assessment cards */
.a-card{display:flex;flex-direction:column;}
.cardact{position:relative;z-index:1;display:flex;gap:6px;flex-wrap:wrap;
  margin-top:auto;padding-top:12px;}
.a-card .id{color:var(--faint);font-size:11px;margin-top:2px;}

/* misc */
.legend{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:10px;}
.stale{border-color:var(--med);}
.kbd{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;
  border:1px solid var(--border-strong);border-bottom-width:2px;border-radius:4px;
  padding:0 4px;color:var(--muted);}
details.sect summary:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;}
"""


# -- shared colour vocabulary ------------------------------------------------
#
# Severity, coverage state and approval status all reuse the same five-colour
# palette, so a reader has to learn one vocabulary instead of three.

SEV_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}
STATE_CLASS = {"COVERED": "low", "PARTIAL": "med", "MISSING": "crit", "NOT_APPLICABLE": "info",
               "UNKNOWN": "info"}
APPROVAL_CLASS = {"APPROVED": "low", "PENDING": "med", "REJECTED": "crit", "DISABLED": "info"}
STATUS_PILL = {
    "CREATED": ("Imported", "info"),
    "ANALYZED": ("Analyzed", "med"),
    "EXECUTED": ("Executed", "low"),
}
VERDICT_CLASS = {"FAIL": "crit", "PASS": "low", "INCONCLUSIVE": "med",
                 "BLOCKED": "info", "ERROR": "high"}
