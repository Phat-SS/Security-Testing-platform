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
    'aria-label="Switch Between Light And Dark" data-tip="Switch Between Light And Dark">'
    '<span class="th-dark" aria-hidden="true">'
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"/></svg></span>'
    '<span class="th-light" aria-hidden="true">'
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4'
    'M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4"/></svg></span></button>'
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


# -- confirm dialog -----------------------------------------------------------
#
# The browser's own confirm()/prompt() cannot be styled, cannot say which
# button is the dangerous one, blocks the whole tab, and on a destructive run
# showed the issue key to type in a box no wider than the key. This is one
# <dialog> built on demand. Text goes in with textContent, never innerHTML: a
# message can carry an endpoint path or an issue key, which are data.
#
#   stpConfirm(message, {danger, requireText, ok}) -> Promise<bool>
#   stpConfirmSubmit(form, event, message, opts) -> bool
#
# `stpConfirmSubmit` is for a submit handler: it stops the first submit, asks,
# and on yes re-submits the form with `requestSubmit()` so the handler runs a
# second time and sees the form already confirmed (returning true), which is
# where a caller puts its spinner.

DIALOG_JS = """
(function () {
  var root = document.documentElement;
  function lbl(k, d) { return root.getAttribute('data-lbl-' + k) || d; }
  window.stpConfirm = function (message, opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      var dlg = document.createElement('dialog');
      dlg.className = 'stp-dlg';
      var msg = document.createElement('p');
      msg.className = 'stp-dlg-msg';
      msg.textContent = message;
      dlg.appendChild(msg);
      var input = null;
      if (opts.requireText) {
        input = document.createElement('input');
        input.setAttribute('autocomplete', 'off');
        input.setAttribute('spellcheck', 'false');
        input.setAttribute('aria-label', message);
        input.placeholder = opts.requireText;
        dlg.appendChild(input);
      }
      var row = document.createElement('div');
      row.className = 'stp-dlg-row';
      var cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'btn ghost';
      cancel.textContent = lbl('cancel', 'Cancel');
      var ok = document.createElement('button');
      ok.type = 'button';
      ok.className = 'btn' + (opts.danger ? ' danger-fill' : '');
      ok.textContent = opts.ok || lbl('ok', 'Confirm');
      row.appendChild(cancel);
      row.appendChild(ok);
      dlg.appendChild(row);
      document.body.appendChild(dlg);
      function sync() { ok.disabled = !!input && input.value.trim() !== opts.requireText; }
      if (input) { input.addEventListener('input', sync); sync(); }
      var answered = false;
      function done(v) {
        if (answered) return;
        answered = true;
        try { dlg.close(); } catch (e) {}
        dlg.remove();
        resolve(v);
      }
      cancel.addEventListener('click', function () { done(false); });
      ok.addEventListener('click', function () { if (!ok.disabled) done(true); });
      dlg.addEventListener('cancel', function (ev) { ev.preventDefault(); done(false); });
      if (input) input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') { ev.preventDefault(); if (!ok.disabled) done(true); }
      });
      if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
      (input || cancel).focus();
    });
  };
  window.stpConfirmSubmit = function (form, ev, message, opts) {
    if (form.dataset.confirmed === '1') { delete form.dataset.confirmed; return true; }
    ev.preventDefault();
    window.stpConfirm(message, opts).then(function (yes) {
      if (!yes) return;
      form.dataset.confirmed = '1';
      if (form.requestSubmit) form.requestSubmit(); else form.submit();
    });
    return false;
  };
})();
"""


# -- language -----------------------------------------------------------------
#
# Unlike the theme toggle, this is resolved server-side (see
# app.core.i18n.get_lang / main.py's lang_middleware): the choice has to be
# known before the page is rendered, not patched in afterwards by JS, since it
# changes which strings the page builders emit in the first place. The links
# just reload the current URL with `?lang=` swapped — the middleware persists
# that as a cookie, so every page after this one keeps the choice without it
# needing to appear in every link on the site.

def lang_toggle_html(current_lang: str) -> str:
    def _link(code: str, label: str) -> str:
        cls = " active" if current_lang == code else ""
        return f'<a class="lang-link{cls}" href="#" data-lang="{attr(code)}">{label}</a>'

    return (
        f'<span class="lang-switch">{_link("en", "EN")}<span class="lang-sep">/</span>'
        f'{_link("vi", "VI")}</span>'
    )


LANG_JS = """
(function () {
  document.querySelectorAll('a[data-lang]').forEach(function (a) {
    a.addEventListener('click', function (ev) {
      ev.preventDefault();
      var url = new URL(location.href);
      url.searchParams.set('lang', a.getAttribute('data-lang'));
      location.href = url.toString();
    });
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
    """A collapsible section, optionally numbered.

    Collapsing is the answer to a pane holding more than one thing: a finished
    section folds down to one line that still says what it produced.
    `<details>` does the work, so it survives with JavaScript off; the JS only
    remembers the open/closed state per assessment.

    `number` is empty for the assessment's sections now that the phase rail
    carries the ordering — a "4" beside the plan was the fourth of six steps
    that no longer exist, and two sections numbered 2 and 4 sitting together in
    one phase reads as a rendering fault.
    """
    num_html = f'<span class="s-num">{e(number)}</span>' if number else ""
    tip_html = " " + info(tip, title) if tip else ""
    sum_html = f'<span class="s-sum">{summary}</span>' if summary else ""
    act_html = f'<div class="s-act">{actions}</div>' if actions else ""
    return f"""<details class="sect {e(tone)}" id="{attr(sid)}" data-sect="{attr(sid)}"{" open" if open else ""}>
<summary class="s-head"><span class="s-chev" aria-hidden="true"></span>
{num_html}<span class="s-title">{e(title)}</span>{tip_html}
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


#: Words that keep their own spelling when a data value is shown as a label.
_ACRONYMS = {"ai": "AI", "poc": "PoC", "api": "API", "jwt": "JWT", "url": "URL", "mcp": "MCP",
             "oast": "OAST", "xhigh": "XHigh", "ssrf": "SSRF", "id": "ID", "openapi": "OpenAPI",
             "cli": "CLI", "jira": "Jira", "http": "HTTP"}


def titleize(value) -> str:
    """A stored value (`import_openapi`, `poc`, `xhigh`) as a Title Case label.

    For data that reaches the page as-is — audit actions, facet values, enum
    options — where there is no literal to rewrite. Already-uppercase values
    (`HIGH`, `APPROVED`) are left alone: they are verdict/enum vocabulary.
    """
    text = str(value or "")
    if not text or text.isupper():
        return text
    words = text.replace("_", " ").split(" ")
    return " ".join(_ACRONYMS.get(w.lower(), w[:1].upper() + w[1:]) for w in words if w)


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
*{box-sizing:border-box;}
body{font:var(--font);margin:0;background:var(--bg);color:var(--fg);-webkit-font-smoothing:antialiased;}
a{color:var(--accent);}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums;}
.muted{color:var(--muted);}
h1,h2,h3{font-family:var(--display);}
h1{font-size:22px;font-weight:700;margin:0 0 4px;letter-spacing:-.015em;}
h2.section{font-size:15px;color:var(--fg);font-weight:600;margin:26px 0 10px;border:0;padding:0;}
h2.section:first-child{margin-top:0;}
.sub{color:var(--muted);margin:0 0 16px;}

.lang-switch{font-size:12.5px;color:var(--muted);white-space:nowrap;}
.lang-link{color:var(--muted);text-decoration:none;padding:2px 3px;}
.lang-link.active{color:var(--fg);font-weight:700;}
.lang-link:not(.active):hover{color:var(--fg);}
.lang-sep{margin:0 2px;color:var(--border);}
.chips{display:flex;gap:8px;flex-wrap:wrap;}
.chip{display:inline-flex;align-items:center;font-size:11.5px;color:var(--muted);background:var(--surface);
  border:1px solid var(--border);border-radius:999px;padding:4px 10px;}
.chip b{color:var(--fg);font-weight:600;margin-left:4px;}
.chip-warn{gap:5px;text-decoration:none;color:var(--med);background:var(--med-soft);
  border-color:var(--med);cursor:help;}
.chip-warn b{color:var(--med);}
.chip-warn:hover{border-color:var(--high);}

.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);box-shadow:var(--shadow);
  animation:rise var(--t-slow) var(--ease) backwards;}
.pad{padding:16px 18px;}
.flash{border-color:var(--accent);margin-bottom:16px;}
.warn{border-color:var(--high);margin-bottom:16px;}
.err{border-color:var(--crit);margin-bottom:16px;}

.btn{display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:var(--accent-ink);
  border:1px solid var(--accent);border-radius:var(--radius);padding:8px 14px;font:inherit;font-size:13.5px;
  font-weight:600;cursor:pointer;text-decoration:none;line-height:1.2;
  transition:transform var(--t-fast) var(--ease),box-shadow var(--t-med) var(--ease),
    background var(--t-med) var(--ease),border-color var(--t-med) var(--ease);}
.btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:var(--shadow-lg);}
.btn:active:not(:disabled){transform:none;}
.btn.sm{padding:4px 10px;font-size:12px;}
.btn.sec{background:transparent;color:var(--fg);border-color:var(--border-strong);}
.btn.sec:hover:not(:disabled){border-color:var(--accent-border);background:var(--raised);}
.btn.ghost{background:none;color:var(--muted);border-color:transparent;padding:8px 6px;}
.btn.ghost:hover:not(:disabled){color:var(--fg);background:var(--raised);box-shadow:none;transform:none;}
.btn.danger{color:var(--crit);border-color:var(--crit);}
.btn:disabled{opacity:.45;cursor:not-allowed;}
.btn:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,
button:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}

input,textarea,select{background:var(--bg);color:var(--fg);border:1px solid var(--border-strong);
  border-radius:var(--radius);padding:8px 10px;font:inherit;font-size:13.5px;width:100%;}
/* Selects: rounded like every other control, with a drawn chevron instead of
   the platform's square arrow box (which ignored border-radius on Windows). */
select{appearance:none;-webkit-appearance:none;border-radius:10px;padding-right:34px;cursor:pointer;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%238b97a7' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:right 12px center;background-size:12px;
  transition:border-color var(--t-fast) var(--ease),box-shadow var(--t-fast) var(--ease);}
select:hover{border-color:var(--accent-border);}
select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);outline:none;}
select[multiple]{background-image:none;padding-right:10px;}
input,textarea{border-radius:10px;}
label.field{display:flex;flex-direction:column;gap:5px;}
label.field span{font-size:12px;font-weight:600;color:var(--muted);}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}

table{width:100%;border-collapse:collapse;font-size:13.5px;}
.tblwrap{overflow-x:auto;}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;}
th{color:var(--muted);font-weight:600;font-size:12px;}
tr:last-child td{border-bottom:0;}
code{background:var(--raised);padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:.92em;}

.pill{display:inline-block;font-size:11.5px;font-weight:600;border-radius:999px;padding:2px 10px;
  white-space:nowrap;}
.pill.ok{background:var(--ok-soft);color:var(--ok);}
.pill.crit{background:var(--crit-soft);color:var(--crit);}
.pill.high{background:var(--high-soft);color:var(--high);}
.pill.med{background:var(--med-soft);color:var(--med);}
.pill.low{background:var(--low-soft);color:var(--low);}
.pill.info{background:var(--info-soft);color:var(--info);}
.destr{font-size:10px;font-weight:700;color:var(--crit);border:1px solid var(--crit);border-radius:4px;
  padding:1px 5px;letter-spacing:.03em;}
.bar{background:var(--raised);border-radius:999px;height:7px;width:100px;overflow:hidden;}
.fill{height:100%;border-radius:inherit;animation:grow 1s var(--ease) both;transform-origin:left;}

/* dashboard */
.summary-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:22px;}
.summary-row .cell{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);
  padding:16px 18px;box-shadow:var(--shadow);animation:rise var(--t-slow) var(--ease) backwards;}
.summary-row .cell:nth-child(2){animation-delay:40ms;}.summary-row .cell:nth-child(3){animation-delay:80ms;}
.summary-row .cell:nth-child(4){animation-delay:120ms;}.summary-row .cell:nth-child(5){animation-delay:160ms;}
.summary-row .cell:nth-child(6){animation-delay:200ms;}
.summary-row .num{font-family:var(--display);font-size:26px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-.01em;}
.summary-row .lbl{font-size:12.5px;color:var(--muted);margin-top:2px;}
.grid-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;}
.a-card{position:relative;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);
  padding:16px 17px;box-shadow:var(--shadow);animation:rise var(--t-slow) var(--ease) backwards;
  transition:border-color var(--t-med) var(--ease),box-shadow var(--t-med) var(--ease),transform var(--t-med) var(--ease);}
.a-card:hover{border-color:var(--accent-border);box-shadow:var(--shadow-lg);transform:translateY(-2px);}
.a-card .stretch{position:absolute;inset:0;border-radius:inherit;}
.a-card .top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px;}
.a-card .issue{font-family:var(--display);font-weight:700;font-size:15px;}
.a-card .id{color:var(--faint);font-size:11px;margin-top:2px;}

.tabbar{display:flex;gap:2px;border-bottom:1px solid var(--border);}
.tabbar button{appearance:none;background:none;border:0;font:inherit;font-size:12.5px;font-weight:600;
  color:var(--muted);padding:8px 12px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;}
.tabbar button.active{color:var(--fg);border-bottom-color:var(--accent);}
.tabpane{display:none;padding-top:12px;}
.tabpane.active{display:block;}

.glabel{font-size:12.5px;font-weight:600;color:var(--muted);margin:14px 0 6px;}
.glabel:first-child{margin-top:0;}
.actionrow{display:flex;gap:8px;flex-wrap:wrap;}

.spinner{width:13px;height:13px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;
  border-radius:50%;display:inline-block;animation:spin .7s linear infinite;vertical-align:-2px;}
@keyframes spin{to{transform:rotate(360deg);}}
@media (prefers-reduced-motion:reduce){.spinner{animation-duration:1.6s;}}
.flash.exec-flash{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}

/* the ⓘ affix + its shared bubble */
.i{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;
  border-radius:50%;border:1px solid var(--border-strong);color:var(--faint);
  font-size:9.5px;font-weight:700;font-style:normal;line-height:1;cursor:help;
  vertical-align:1px;margin-left:4px;text-transform:none;letter-spacing:0;flex:none;}
.i:hover,.i:focus{color:var(--accent);border-color:var(--accent);outline:none;}
.tipbox{position:fixed;display:none;z-index:60;max-width:320px;background:var(--tip-bg);
  color:var(--tip-fg);font-size:12.5px;line-height:1.45;font-weight:400;text-transform:none;
  letter-spacing:0;padding:8px 10px;border-radius:8px;box-shadow:var(--shadow-lg);
  animation:fadein var(--t-fast) var(--ease);
  pointer-events:none;white-space:pre-line;overflow-wrap:anywhere;}

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

/* step nav: four phase tabs. Numbered until done, ticked after; the open
   phase carries the accent. Sticky so the phases stay one click away. */
.stepnav{position:sticky;top:0;z-index:30;display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;
  background:var(--bg);margin:0 0 18px;padding:8px 0;}
.stepnav a{display:flex;align-items:center;gap:10px;white-space:nowrap;text-decoration:none;
  color:var(--fg);font-size:13.5px;padding:10px 12px;border-radius:12px;min-width:0;
  background:var(--surface);border:1px solid var(--border);
  transition:background var(--t-med) var(--ease),border-color var(--t-med) var(--ease);}
.stepnav a:hover{border-color:var(--accent-border);}
.stepnav a b{font-weight:600;overflow:hidden;text-overflow:ellipsis;}
.stepnav a.on{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-border);}
.stepnav a .dot{width:24px;height:24px;border-radius:50%;flex:none;display:inline-flex;
  align-items:center;justify-content:center;font-size:11.5px;font-weight:700;
  background:var(--raised);color:var(--muted);}
.stepnav a.done .dot,.stepnav a.on .dot{background:var(--accent);color:var(--accent-ink);}
.stepnav a.current .dot{box-shadow:0 0 0 3px var(--accent-soft);}
.stepnav a .n{margin-left:auto;color:var(--muted);font-size:12px;font-weight:600;
  font-variant-numeric:tabular-nums;}
@media (max-width:640px){.stepnav{grid-template-columns:repeat(2,minmax(0,1fr));}}

/* collapsible section */
.sect{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);
  box-shadow:var(--shadow);margin-bottom:14px;overflow:hidden;animation:rise var(--t-slow) var(--ease) backwards;}
.sect.attn{border-color:var(--accent-border);}
.s-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding:13px 16px;cursor:pointer;
  list-style:none;user-select:none;}
.s-head::-webkit-details-marker{display:none;}
.s-head:hover{background:var(--raised);}
.s-chev{width:0;height:0;border:5px solid transparent;border-left-color:var(--faint);
  margin-left:2px;transition:transform .15s;flex:none;}
.sect[open] .s-chev{transform:rotate(90deg) translateX(-1px);}
.s-num{font-size:11px;font-weight:700;color:var(--accent);background:var(--accent-soft);
  border-radius:4px;padding:2px 6px;font-variant-numeric:tabular-nums;flex:none;}
.s-title{font-family:var(--display);font-size:16px;font-weight:600;}
.s-sum{margin-left:auto;font-size:12.5px;color:var(--muted);text-align:right;}
.s-body{padding:0 16px 16px;border-top:1px solid var(--border);padding-top:14px;}
.s-act{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;}
@media (prefers-reduced-motion:reduce){.s-chev{transition:none;}}

/* tables */
table thead th{background:var(--sticky-bg);}
.tblwrap.scroll{max-height:60vh;overflow:auto;}
/* A table that IS the page (Findings, Audit Log) gets the card it would
   otherwise float without; one inside a section already sits in a card. */
.content>.tblwrap{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-lg);box-shadow:var(--shadow);animation:rise var(--t-slow) var(--ease) backwards;}
.content>.tblwrap thead th:first-child{border-top-left-radius:var(--radius-lg);}
.content>.tblwrap thead th:last-child{border-top-right-radius:var(--radius-lg);}
.tblwrap.scroll thead th{position:sticky;top:0;z-index:2;}
tbody tr:nth-child(even){background:var(--zebra);}
tbody tr{transition:background var(--t-fast) var(--ease);}
tbody tr:hover{background:var(--raised);}
td.empty{text-align:center;padding:22px 10px;}
table.compact th,table.compact td{padding:5px 8px;font-size:13px;}
/* Not scoped to `td`: the assessment card uses it too, and outside a table it
   was an unstyled class — which is how a long target URL ran past the card. */
.trunc{display:inline-block;max-width:280px;overflow:hidden;text-overflow:ellipsis;
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

/* Search + filter bar.
   The generic `.toolbar` is a flat row of labelled fields and an Apply button:
   every control has equal weight, the one you reach for most (search) is the
   same size as "Per Page", and nothing says what is currently filtered. This
   splits it into the two things it actually is — one query box on top, the
   facets and view options below — so the shape of the control matches the shape
   of the decision. */
.filters{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);box-shadow:var(--shadow);margin-bottom:14px;}
.f-top{display:flex;gap:10px;align-items:center;padding:12px 14px;}
.f-search{position:relative;flex:1;min-width:0;display:flex;align-items:center;}
.f-search>svg{position:absolute;left:10px;color:var(--faint);pointer-events:none;}
.f-search input{width:100%;padding-left:32px;padding-right:34px;}
.f-x{position:absolute;right:6px;display:inline-flex;color:var(--faint);line-height:0;
  padding:5px;border-radius:50%;text-decoration:none;}
.f-x:hover{background:var(--bg);color:var(--fg);}
.f-bot{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:9px 14px;
  border-top:1px solid var(--border);background:var(--bg);
  border-radius:0 0 var(--radius) var(--radius);}
.f-spacer{flex:1;min-width:0;}
.f-sel{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap;}
.f-sel select{width:auto;max-width:190px;padding:5px 30px 5px 10px;background-position:right 10px center;font-size:12.5px;
  background-color:var(--surface);}
.f-clear{font-size:12.5px;color:var(--muted);text-decoration:none;white-space:nowrap;}
.f-clear:hover{color:var(--crit);}

/* A segmented facet. Buttons rather than a <select> because the options are
   few, mutually exclusive, and each carries a count — a dropdown hides both
   the count and the fact that three of the four match nothing. */
.seg{display:inline-flex;gap:2px;padding:2px;max-width:100%;overflow-x:auto;
  background:var(--surface);border:1px solid var(--border);border-radius:999px;}
.seg a{display:inline-flex;align-items:center;gap:5px;white-space:nowrap;padding:5px 11px;
  border-radius:999px;font-size:12.5px;font-weight:600;color:var(--muted);text-decoration:none;}
.seg a:hover{color:var(--fg);background:var(--bg);}
.seg a[aria-current]{background:var(--accent-soft);color:var(--accent);}
.seg a b{font-size:11.5px;font-weight:700;font-variant-numeric:tabular-nums;color:var(--faint);}
.seg a[aria-current] b{color:var(--accent);}
.seg a.none{opacity:.5;}

@media (max-width:640px){
  .f-top,.f-bot{flex-wrap:wrap;}
  .f-spacer{display:none;}
  .seg{width:100%;}
}

/* inline editing row */
tr.editing{background:var(--accent-soft);}
tr.editing input,tr.editing select{padding:5px 7px;font-size:13px;}
tr.editing select{padding-right:28px;background-position:right 8px center;}
.addrow{background:var(--bg);}
.kchip{display:inline-block;background:var(--info-soft);color:var(--info);border-radius:4px;
  padding:1px 6px;font-size:11.5px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
  margin-right:3px;}
.flagdot{display:inline-block;width:8px;height:8px;border-radius:50%;}
.flagdot.on{background:var(--ok);}
.flagdot.off{background:var(--border-strong);}

/* assessment cards */
.a-card{display:flex;flex-direction:column;}
/* Above the card's stretched link, so they are clickable rather than opening it. */
.a-card .a-pick,.a-card .am{position:relative;z-index:2;}
.a-card .top{align-items:center;gap:8px;}
.a-card .a-head{flex:1;min-width:0;}
.a-card .issue{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.a-meta{display:flex;align-items:center;gap:7px;min-width:0;margin-top:3px;color:var(--faint);
  font-size:11.5px;white-space:nowrap;overflow:hidden;}
.a-meta .mono{font-size:11px;overflow:hidden;text-overflow:ellipsis;}
.a-dot{width:3px;height:3px;border-radius:50%;background:currentColor;opacity:.6;flex:none;}
/* The selection badge: a round box riding the card's top-left corner. Hidden
   until hover/focus, always shown once any card is selected. */
.a-card .a-pick{position:absolute;top:-9px;left:-9px;z-index:3;width:24px;height:24px;
  display:inline-flex;cursor:pointer;opacity:0;transform:scale(.6);
  transition:opacity var(--t-fast) var(--ease),transform var(--t-med) var(--ease);}
.a-sel{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer;}
.a-box{display:inline-flex;align-items:center;justify-content:center;width:100%;height:100%;
  border-radius:50%;background:var(--surface);border:1.5px solid var(--border-strong);color:transparent;
  box-shadow:0 1px 2px rgba(0,0,0,.08),0 4px 12px rgba(0,0,0,.08);pointer-events:none;
  transition:background var(--t-fast) var(--ease),border-color var(--t-fast) var(--ease),
  color var(--t-fast) var(--ease),box-shadow var(--t-fast) var(--ease);}
.a-box svg{stroke-width:3;transform:scale(.5);transition:transform var(--t-med) cubic-bezier(.3,1.6,.5,1);}
.a-card:hover .a-pick,.a-card:focus-within .a-pick,.selecting .a-card .a-pick{opacity:1;transform:none;}
.a-pick:hover .a-box{border-color:var(--accent);color:var(--accent-border);}
.a-sel:focus-visible + .a-box{box-shadow:0 0 0 3px var(--accent-soft),0 0 0 1px var(--accent);}
.a-sel:checked + .a-box{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);}
.a-sel:checked + .a-box svg,.a-pick:hover .a-box svg{transform:none;}
@media (hover:none){.a-card .a-pick{opacity:1;transform:none;}}
.selecting .a-card{cursor:pointer;}
.selecting .a-card:not(.selected){opacity:.82;}
.selecting .a-card:not(.selected):hover{opacity:1;}
.a-card.selected{border-color:var(--accent);
  background:linear-gradient(180deg,var(--accent-soft),var(--surface) 70%);
  box-shadow:0 0 0 1px var(--accent),0 0 0 5px var(--accent-soft),var(--shadow-lg);transform:none;}
.a-card.selected:hover{transform:none;}
/* The selection dock: floats at the bottom of the list column while anything
   is selected. Its anchor is a zero-height sticky line, so the dock takes no
   room in the page when it is away. */
.dock-anchor{position:sticky;bottom:22px;height:0;z-index:40;display:flex;justify-content:center;}
.dock{position:absolute;bottom:0;display:flex;align-items:center;gap:4px;padding:6px;margin:0;
  border-radius:16px;background:var(--fg);color:var(--bg);white-space:nowrap;
  box-shadow:0 10px 30px rgba(0,0,0,.25),0 2px 6px rgba(0,0,0,.15);
  opacity:0;visibility:hidden;transform:translateY(calc(100% + 30px)) scale(.96);
  transition:opacity var(--t-med) var(--ease),transform var(--t-slow) cubic-bezier(.2,1.2,.3,1),
  visibility 0s linear var(--t-slow);}
.dock.on{opacity:1;visibility:visible;transform:none;transition-delay:0s;}
.dock-n{display:inline-flex;align-items:center;gap:8px;padding:0 10px 0 4px;font-size:13px;font-weight:500;}
.dock-n b{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:24px;
  padding:0 7px;border-radius:999px;background:var(--accent);color:var(--accent-ink);
  font-size:12.5px;font-weight:700;font-variant-numeric:tabular-nums;}
.dock-n b.bump{animation:dock-bump 260ms var(--ease);}
@keyframes dock-bump{40%{transform:scale(1.25);}}
.dock-sep{width:1px;height:22px;background:currentColor;opacity:.18;margin:0 4px;}
.dock-x,.dock-b{display:inline-flex;align-items:center;gap:7px;height:34px;border:0;border-radius:10px;
  background:none;color:inherit;font:inherit;font-size:13px;font-weight:600;cursor:pointer;
  transition:background var(--t-fast) var(--ease),color var(--t-fast) var(--ease);}
.dock-x{width:34px;justify-content:center;opacity:.75;}
.dock-b{padding:0 12px;}
.dock-x:hover,.dock-b:hover{background:color-mix(in srgb,var(--bg) 14%,transparent);opacity:1;}
.dock-x:focus-visible,.dock-b:focus-visible{outline:2px solid var(--accent);outline-offset:1px;}
.dock-b[hidden]{display:none;}
.dock-b.danger{background:var(--crit);color:#fff;margin-left:2px;}
.dock-b.danger:hover{background:color-mix(in srgb,var(--crit) 86%,#000);}
@media (max-width:640px){.dock-b span{display:none;}.dock-b{padding:0 10px;}}
@media (prefers-reduced-motion:reduce){.dock,.a-card .a-pick,.a-box svg{transition:none;}}
.a-sev{display:flex;gap:2px;height:6px;margin-top:10px;}
.a-sev span{display:block;flex:0 0 auto;}
.a-sev span:first-child{border-radius:3px 0 0 3px;}
.a-sev span:last-child{border-radius:0 3px 3px 0;}
.a-sev span:only-child{border-radius:3px;}
.bulkbar{position:sticky;top:calc(var(--appbar-h) + 8px);z-index:35;display:flex;align-items:center;
  gap:10px;flex-wrap:wrap;padding:10px 14px;margin:0 0 12px;border-radius:12px;
  background:var(--accent-soft);border:1px solid var(--accent-border);color:var(--accent);
  animation:rise var(--t-med) var(--ease) backwards;}
.bulkbar[hidden]{display:none;}
.a-card .id{color:var(--faint);font-size:11px;margin-top:2px;}

/* the live run panel (views/assessment/progress.py) */
.runbar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--border);margin-top:10px;}
.runbar span{display:block;height:100%;transition:width var(--t-slow) var(--ease);}
.runcard{display:grid;grid-template-columns:auto minmax(0,1fr);gap:18px;align-items:center;}
.runinfo{min-width:0;}
.radar .sweep{transform-origin:60px 60px;}
.runcard.live .radar .sweep{animation:sweep 2.6s linear infinite;}
@keyframes sweep{to{transform:rotate(360deg);}}
@media (max-width:640px){.runcard{grid-template-columns:1fr;}.radar{display:none;}}
.runlegs{display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;}
.runleg{display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--muted);}
.runleg i{width:8px;height:8px;border-radius:2px;display:inline-block;}
.runleg b{color:var(--fg);font-variant-numeric:tabular-nums;}
.runfeed-head{font-size:12.5px;color:var(--muted);
  font-weight:600;padding:10px 14px;border-bottom:1px solid var(--border);background:var(--sticky-bg);}
.runrow{display:grid;grid-template-columns:96px 104px 1fr 56px 74px;gap:12px;align-items:center;
  padding:8px 14px;border-bottom:1px solid var(--border);font-size:12.5px;animation:rise var(--t-slow) var(--ease) backwards;}
.runrow:last-child{border-bottom:0;}
.runrow.fail{background:var(--crit-soft);}
.runrow .b{font-weight:600;}
.runrow .reason{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.runrow.muted{display:block;color:var(--muted);}
@media (max-width:760px){.runrow{grid-template-columns:1fr auto;}
  .runrow .reason,.runrow .mono.muted{display:none;}}

/* misc */
.legend{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:10px;}
.stale{border-color:var(--med);}
.kbd{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;
  border:1px solid var(--border-strong);border-bottom-width:2px;border-radius:4px;
  padding:0 4px;color:var(--muted);}
details.sect summary:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;}

/* assessment workspace + Copilot panel (views/assessment/copilot.py) */
.ws{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:20px;align-items:start;}
.ws-main{min-width:0;}
@media (max-width:1180px){.ws{grid-template-columns:minmax(0,1fr);}}
.copilot{position:sticky;top:12px;display:flex;flex-direction:column;gap:10px;
  background:var(--surface);border:1px solid var(--accent-border);border-radius:var(--radius-lg);
  padding:16px;box-shadow:var(--shadow);animation:rise var(--t-slow) var(--ease) backwards;
  max-height:calc(100vh - 24px);overflow:auto;}
.cp-head{display:flex;align-items:center;gap:8px;color:var(--accent);}
.cp-head h2{margin:0;font-size:16px;color:var(--fg);flex:1;}
.cp-meta{font-size:11.5px;color:var(--muted);font-family:var(--mono);}
.cp-card{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:12px;
  display:flex;flex-direction:column;gap:6px;font-size:13px;animation:rise var(--t-slow) var(--ease) backwards;}
.cp-card p{margin:0;color:var(--muted);}
.cp-card form{margin:4px 0 0;}
.cp-step{border-color:var(--accent-border);}
.cp-k{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:6px;}
.cp-ev{font-size:11.5px;color:var(--faint);overflow-wrap:anywhere;}
.cp-note{font-size:12px;color:var(--muted);margin:0;}
.cp-empty{margin:0;font-size:13px;}
.cp-answer{border-color:var(--accent-border);background:var(--accent-soft);}
.cp-answer p{color:var(--fg);}
.cp-ask{display:flex;gap:6px;margin-top:4px;}
.cp-ask input{flex:1;min-width:0;font-size:13px;}
.cp-refresh{margin:0;align-self:flex-start;}

/* confirm dialog (DIALOG_JS) */
.stp-dlg{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);
  color:var(--fg);padding:20px;width:min(440px,calc(100vw - 32px));box-shadow:var(--shadow-lg);
  animation:rise var(--t-med) var(--ease) backwards;}
.stp-dlg::backdrop{background:rgba(5,8,12,.55);backdrop-filter:blur(2px);}
.stp-dlg-msg{margin:0 0 14px;white-space:pre-line;line-height:1.5;}
.stp-dlg input{margin:0 0 14px;font-family:var(--mono);}
.stp-dlg-row{display:flex;justify-content:flex-end;gap:8px;}
.btn.danger-fill{background:var(--crit);border-color:var(--crit);color:#fff;}

/* theme toggle: show the face of the theme you would switch TO */
#theme-toggle .th-light{display:none;}
:root[data-theme="dark"] #theme-toggle .th-dark{display:none;}
:root[data-theme="dark"] #theme-toggle .th-light{display:inline-flex;}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]) #theme-toggle .th-dark{display:none;}
  :root:not([data-theme="light"]) #theme-toggle .th-light{display:inline-flex;}
}

/* motion. One vocabulary, three durations (tokens), one easing. Nothing that
   carries a verdict animates its text: only containers arrive and bars fill. */
/* `backwards`, never `both`: a fill that keeps `transform` after the animation
   turns the element into the containing block of every position:fixed child,
   which is how popovers opened inside a card landed hundreds of px away. */
@keyframes rise{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:none;}}
@keyframes fadein{from{opacity:0;}to{opacity:1;}}
@keyframes grow{from{transform:scaleX(0);}to{transform:scaleX(1);}}
@keyframes pulse{0%{box-shadow:0 0 0 0 var(--crit-soft);}70%{box-shadow:0 0 0 7px transparent;}
  100%{box-shadow:0 0 0 0 transparent;}}
@media (prefers-reduced-motion:reduce){
  *:not(.spinner),*::before,*::after{animation:none !important;transition:none !important;}
}
"""


# -- shared colour vocabulary ------------------------------------------------
#
# Severity, coverage state and approval status all reuse the same five-colour
# palette, so a reader has to learn one vocabulary instead of three.

SEV_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}
STATE_CLASS = {"COVERED": "ok", "PARTIAL": "med", "MISSING": "crit", "NOT_APPLICABLE": "info",
               "UNKNOWN": "info"}
APPROVAL_CLASS = {"APPROVED": "ok", "PENDING": "med", "REJECTED": "crit", "DISABLED": "info"}
STATUS_PILL = {
    "CREATED": ("Imported", "info"),
    "ANALYZED": ("Analyzed", "med"),
    "EXECUTED": ("Executed", "ok"),
}
VERDICT_CLASS = {"FAIL": "crit", "PASS": "ok", "INCONCLUSIVE": "med",
                 "BLOCKED": "info", "ERROR": "high"}
