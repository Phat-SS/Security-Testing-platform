"""The `⋯` action menu: every row's and card's secondary actions in one place.

Edit, Delete, Re-run and the like used to sit as a row of buttons on every line,
which made each row look like a form and put Delete one stray click from Edit.
One button now opens a short menu; destructive items sit last, in red, behind
the confirm dialog.

Items are plain markup that works without JavaScript inside the menu: a link is
a link, a POST is a real `<form>`, and a page-specific button keeps its own
class so the page's existing handler still finds it. The menu is positioned
`fixed` from the button's rectangle, because most rows live inside a scrolling
table wrapper that would clip an absolutely-positioned popover.

Each item may carry an icon and a one-line hint, and the popup may carry a
header (`title` / `subtitle`): once the menu is portalled to <body> it floats
free of its card, and the header is what still says which card it belongs to.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .base import attr, e
from .icons import icon as _icon

_DOTS = ('<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">'
         '<circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/>'
         '<circle cx="19" cy="12" r="1.8"/></svg>')
_NEW_TAB = ('<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<path d="M8 16L16 8M9 8h7v7"/></svg>')


@dataclass
class Item:
    label: str
    href: str = ""                       # a link
    action: str = ""                     # a POST form
    fields: dict = field(default_factory=dict)
    form_class: str = ""                 # e.g. an existing confirm handler's class
    form_data: dict = field(default_factory=dict)
    button_class: str = ""               # a JS button handled by the page
    button_data: dict = field(default_factory=dict)
    form_ref: str = ""                   # submits a form rendered elsewhere (no nesting)
    danger: bool = False
    new_tab: bool = False
    icon: str = ""                       # a name from ui.icons, shown before the label
    hint: str = ""                       # one muted line under the label


def _data(attrs: dict) -> str:
    return "".join(f' data-{k}="{attr(v)}"' for k, v in attrs.items())


def _inner(it: Item) -> str:
    """Icon slot, label (+ hint), new-tab mark. The icon slot is kept even when
    empty so labels line up in a menu that mixes items with and without one."""
    ic = _icon(it.icon, 16) if it.icon else ""
    hint = f'<span class="am-hint">{e(it.hint)}</span>' if it.hint else ""
    tail = f'<span class="am-tail">{_NEW_TAB}</span>' if it.new_tab else ""
    return (f'<span class="am-ic">{ic}</span>'
            f'<span class="am-lb"><span class="am-t">{e(it.label)}</span>{hint}</span>{tail}')


def action_menu(items: list[Item], label: str, title: str = "", subtitle: str = "") -> str:
    """`label` names what the actions are for, for the button's accessible name."""
    if not items:
        return ""
    rows = []
    for it in items:
        cls = "am-item danger" if it.danger else "am-item"
        inner = _inner(it)
        if it.href:
            target = ' target="_blank" rel="noopener"' if it.new_tab else ""
            rows.append(f'<a role="menuitem" class="{cls}" href="{attr(it.href)}"{target}>{inner}</a>')
        elif it.action:
            hidden = "".join(f'<input type="hidden" name="{attr(k)}" value="{attr(v)}">'
                             for k, v in it.fields.items())
            rows.append(
                f'<form method="post" action="{attr(it.action)}" class="am-form {attr(it.form_class)}"'
                f'{_data(it.form_data)}>{hidden}'
                f'<button role="menuitem" class="{cls}">{inner}</button></form>'
            )
        elif it.form_ref:
            # For a row inside another form (the plan's bulk-selection form): a
            # nested <form> is invalid HTML and would submit the outer one.
            rows.append(f'<button role="menuitem" class="{cls}" form="{attr(it.form_ref)}">'
                        f'{inner}</button>')
        else:
            rows.append(f'<button type="button" role="menuitem" class="{cls} {attr(it.button_class)}"'
                        f'{_data(it.button_data)}>{inner}</button>')
    # Destructive actions go last, after a rule, whatever order they came in.
    safe = [r for r, it in zip(rows, items) if not it.danger]
    risky = [r for r, it in zip(rows, items) if it.danger]
    body = "".join(safe) + ('<div class="am-sep" role="separator"></div>' if safe and risky else "") \
        + "".join(risky)
    head = ""
    if title:
        sub = f'<span class="am-sub">{e(subtitle)}</span>' if subtitle else ""
        head = f'<div class="am-head" aria-hidden="true"><span class="am-title">{e(title)}</span>{sub}</div>'
    return (
        f'<div class="am"><button type="button" class="am-btn" aria-haspopup="menu" '
        f'aria-expanded="false" aria-label="{attr(label)}" data-tip="{attr(label)}">{_DOTS}</button>'
        f'<div class="am-menu" role="menu" aria-label="{attr(label)}" hidden>{head}'
        f'<div class="am-list">{body}</div></div></div>'
    )


CSS = """
.am{position:relative;display:inline-flex;}
.am-btn{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;
  border-radius:9px;border:1px solid transparent;background:none;color:var(--muted);cursor:pointer;
  transition:background var(--t-fast) var(--ease),color var(--t-fast) var(--ease),
  border-color var(--t-fast) var(--ease),box-shadow var(--t-fast) var(--ease);}
.am-btn:hover{background:var(--raised);color:var(--fg);border-color:var(--border);}
.am-btn[aria-expanded="true"]{background:var(--surface);color:var(--accent);
  border-color:var(--accent-border);box-shadow:0 0 0 3px var(--accent-soft);}
.am-menu{position:fixed;z-index:80;min-width:236px;max-width:300px;padding:0;
  background:color-mix(in srgb,var(--surface) 97%,transparent);
  -webkit-backdrop-filter:saturate(1.4) blur(16px);backdrop-filter:saturate(1.4) blur(16px);
  border:1px solid var(--border-strong);border-radius:14px;
  box-shadow:0 2px 6px rgba(0,0,0,.06),var(--shadow-lg);
  display:flex;flex-direction:column;overflow:hidden;transform-origin:top right;
  animation:am-in 170ms var(--ease) both;}
.am-menu[data-side="up"]{transform-origin:bottom right;animation-name:am-in-up;}
.am-menu[hidden]{display:none;}
@keyframes am-in{from{opacity:0;transform:translateY(-6px) scale(.96);}to{opacity:1;transform:none;}}
@keyframes am-in-up{from{opacity:0;transform:translateY(6px) scale(.96);}to{opacity:1;transform:none;}}
@media (prefers-reduced-motion:reduce){.am-menu{animation:none;}}
.am-head{display:flex;flex-direction:column;gap:2px;padding:11px 14px 10px;
  border-bottom:1px solid var(--border);
  background:linear-gradient(180deg,var(--raised),color-mix(in srgb,var(--raised) 40%,transparent));}
.am-title{font-family:var(--display);font-weight:700;font-size:13.5px;color:var(--fg);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.am-sub{font-family:var(--mono);font-size:11px;color:var(--faint);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.am-list{display:flex;flex-direction:column;gap:1px;padding:6px;}
.am-form{margin:0;display:block;}
.am-item{display:grid;grid-template-columns:28px minmax(0,1fr) auto;align-items:center;column-gap:9px;
  width:100%;min-height:38px;text-align:left;padding:5px 10px 5px 5px;border-radius:9px;border:0;
  background:none;color:var(--fg);font:inherit;font-size:13px;font-weight:500;text-decoration:none;
  cursor:pointer;white-space:nowrap;
  transition:background var(--t-fast) var(--ease),color var(--t-fast) var(--ease);}
.am-ic{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;
  border-radius:8px;color:var(--muted);
  transition:background var(--t-fast) var(--ease),color var(--t-fast) var(--ease);}
.am-lb{display:flex;flex-direction:column;min-width:0;line-height:1.3;}
.am-t{overflow:hidden;text-overflow:ellipsis;}
.am-hint{font-size:11.5px;font-weight:400;color:var(--faint);overflow:hidden;text-overflow:ellipsis;}
.am-tail{display:inline-flex;color:var(--faint);}
.am-item:hover,.am-item:focus-visible{background:var(--raised);outline:none;}
.am-item:hover .am-ic,.am-item:focus-visible .am-ic{color:var(--accent);background:var(--accent-soft);}
.am-item:hover .am-tail{color:var(--muted);}
.am-item:focus-visible{box-shadow:inset 0 0 0 1.5px var(--accent-border);}
.am-item.danger,.am-item.danger .am-ic{color:var(--crit);}
.am-item.danger:hover,.am-item.danger:focus-visible{background:var(--crit-soft);}
.am-item.danger:hover .am-ic,.am-item.danger:focus-visible .am-ic{background:transparent;color:var(--crit);}
.am-item.danger:focus-visible{box-shadow:inset 0 0 0 1.5px var(--crit);}
.am-sep{height:1px;background:var(--border);margin:5px 6px;}
"""

JS = """
(function () {
  var open = null;
  function close(focusBack) {
    if (!open) return;
    open.menu.hidden = true;
    // Back where it came from, so forms inside keep their place in the page.
    open.home.appendChild(open.menu);
    open.btn.setAttribute('aria-expanded', 'false');
    if (focusBack) open.btn.focus();
    open = null;
  }
  function place(btn, menu) {
    var r = btn.getBoundingClientRect();
    menu.style.left = '0px'; menu.style.top = '0px';
    var w = menu.offsetWidth, h = menu.offsetHeight;
    var left = Math.min(Math.max(8, r.right - w), window.innerWidth - w - 8);
    var top = r.bottom + 6;
    var up = top + h > window.innerHeight - 8;
    if (up) top = Math.max(8, r.top - h - 6);
    menu.style.left = left + 'px'; menu.style.top = top + 'px';
    // Grow out of the button, whichever side of it the menu landed on.
    menu.dataset.side = up ? 'up' : 'down';
  }
  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest('.am-btn');
    if (btn) {
      ev.preventDefault(); ev.stopPropagation();
      var menu = (open && open.btn === btn) ? open.menu : btn.parentNode.querySelector('.am-menu');
      var same = open && open.btn === btn;
      close(false);
      if (same) return;
      // Portalled to <body>: an ancestor with a transform or overflow:hidden
      // (cards, sections, scrolling table wrappers) would otherwise offset or
      // clip a position:fixed popover.
      var home = btn.parentNode;
      document.body.appendChild(menu);
      menu.hidden = false;
      btn.setAttribute('aria-expanded', 'true');
      place(btn, menu);
      open = { btn: btn, menu: menu, home: home };
      var first = menu.querySelector('.am-item');
      if (first) first.focus({ preventScroll: true });
      return;
    }
    if (open && !open.menu.contains(ev.target)) close(false);
    // A JS item (e.g. an inline Edit) closes the menu after its own handler.
    if (open && ev.target.closest('button.am-item[type=button], a.am-item')) setTimeout(function () { close(false); }, 0);
  });
  // Capture phase, and Escape stops there: a page's own Escape handler (the
  // plan's "clear selection") must not also fire while a menu is open.
  window.addEventListener('keydown', function (ev) {
    if (!open) return;
    // Keys aimed elsewhere (e.g. the confirm dialog a menu item just opened)
    // are not the menu's to handle.
    if (!open.menu.contains(ev.target) && ev.target !== open.btn) return;
    var items = Array.prototype.slice.call(open.menu.querySelectorAll('.am-item'));
    var i = items.indexOf(document.activeElement);
    if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); close(true); }
    else if (ev.key === 'ArrowDown') { ev.preventDefault(); items[(i + 1) % items.length].focus({ preventScroll: true }); }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); items[(i - 1 + items.length) % items.length].focus({ preventScroll: true }); }
    else if (ev.key === 'Home') { ev.preventDefault(); items[0].focus({ preventScroll: true }); }
    else if (ev.key === 'End') { ev.preventDefault(); items[items.length - 1].focus({ preventScroll: true }); }
    else if (ev.key === 'Tab') { close(false); }
  }, true);
  // Follow the button when the page or a table wrapper scrolls; close only
  // once the button itself has left the viewport.
  window.addEventListener('scroll', function (ev) {
    if (!open) return;
    // A row scrolled inside its table wrapper: close rather than float free.
    if (ev.target !== document && ev.target !== document.documentElement && !open.menu.contains(ev.target)) {
      close(false); return;
    }
    var r = open.btn.getBoundingClientRect();
    if (r.bottom < 0 || r.top > window.innerHeight) { close(false); return; }
    place(open.btn, open.menu);
  }, true);
  window.addEventListener('resize', function () { close(false); });
  // A form item that names a confirmation asks for it in the app dialog.
  document.addEventListener('submit', function (ev) {
    var f = ev.target;
    if (open && open.menu.contains(f)) close(false);
    if (!f.classList || !f.classList.contains('am-form') || !f.dataset.confirm) return;
    window.stpConfirmSubmit(f, ev, f.dataset.confirm, { danger: f.dataset.danger === '1' });
  }, true);
})();
"""
