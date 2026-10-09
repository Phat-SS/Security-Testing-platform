"""A themed select: the trigger AND the open list, in both themes.

CSS can round a `<select>`'s closed box, but its open list is drawn by the
operating system — square, unthemed, ignoring dark mode, with no hover or check
state. That popup was what made every dropdown look raw.

So each single-choice `<select>` is enhanced on load: the native element stays
in the form (it is what submits, what `required` validates, what no-JS users
get, and what every existing `change` handler listens to), and a button plus a
listbox are drawn over it. Choosing an option sets the native value and fires
`input` and `change` on it, so auto-submit filters and page scripts behave
exactly as before.

Opt out with `data-native` (or `multiple` / `size>1`, which stay native).
An option may carry `data-hint` for a secondary label (an identifier shown in
mono beside its Title Case name). Lists longer than eight options get a search
box. Keyboard: ↑ ↓ Home End to move, Enter to choose, Esc/Tab to close, and
typing jumps to the first matching option.
"""

from __future__ import annotations

CSS = """
.sx{position:relative;display:inline-flex;max-width:100%;vertical-align:middle;}
/* `label.field span` styles the field's caption; the component's own spans
   sit inside the same label and must not inherit that. */
label.field .sx,label.field .sx span{font-size:inherit;font-weight:inherit;color:inherit;
  text-transform:none;letter-spacing:normal;}
label.field .sx,.sx.sx-block{display:flex;width:100%;}
.sx-native{position:absolute!important;inset:0;width:100%!important;height:100%!important;
  opacity:0;pointer-events:none;margin:0!important;}
.sx-btn{all:unset;box-sizing:border-box;display:flex;align-items:center;gap:10px;width:100%;
  min-height:38px;padding:0 12px 0 13px;border-radius:12px;border:1px solid var(--border-strong);
  background:var(--bg);color:var(--fg);font:inherit;font-size:13.5px;cursor:pointer;
  transition:border-color var(--t-fast) var(--ease),background var(--t-fast) var(--ease),
    box-shadow var(--t-fast) var(--ease);}
.sx-btn:hover{border-color:var(--accent-border);background:var(--raised);}
.sx-btn:focus-visible,.sx-btn[aria-expanded="true"]{border-color:var(--accent);
  box-shadow:0 0 0 4px var(--accent-soft);outline:none;}
.sx-btn:disabled{cursor:not-allowed;opacity:.6;border-style:dashed;background:transparent;}
.sx-val{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:left;}
.sx-chev{flex:none;color:var(--muted);transition:transform var(--t-med) var(--ease),color var(--t-fast);}
.sx-btn[aria-expanded="true"] .sx-chev{transform:rotate(180deg);color:var(--accent);}
.sx.sx-sm .sx-btn{min-height:32px;font-size:12.5px;border-radius:10px;padding:0 10px 0 11px;}

.sx-list{position:fixed;z-index:90;min-width:180px;max-width:min(460px,calc(100vw - 16px));
  max-height:min(340px,calc(100vh - 24px));display:flex;flex-direction:column;padding:6px;
  background:var(--surface);border:1px solid var(--border-strong);border-radius:14px;
  box-shadow:var(--shadow-lg);animation:sxpop var(--t-med) var(--ease) both;transform-origin:top;}
.sx-list.up{transform-origin:bottom;}
.sx-search{display:flex;align-items:center;gap:8px;height:36px;padding:0 10px;margin-bottom:4px;
  border-radius:10px;background:var(--raised);color:var(--muted);flex:none;}
.sx-search input{all:unset;flex:1;min-width:0;font-size:13px;color:var(--fg);}
.sx-opts{overflow:auto;display:flex;flex-direction:column;gap:2px;}
.sx-group{padding:8px 10px 2px;font-size:11.5px;font-weight:600;color:var(--muted);}
.sx-opt{display:flex;align-items:center;gap:10px;min-height:36px;padding:0 10px;border-radius:10px;
  cursor:pointer;color:var(--fg);font-size:13.5px;}
.sx-opt .sx-check{width:16px;flex:none;display:inline-flex;color:var(--accent);visibility:hidden;}
.sx-opt .sx-text{flex:1;min-width:0;}
.sx-opt .sx-hint{font-family:var(--mono);font-size:11.5px;color:var(--muted);}
.sx-opt.active{background:var(--raised);}
.sx-opt[aria-selected="true"]{background:var(--accent-soft);color:var(--accent);font-weight:600;}
.sx-opt[aria-selected="true"] .sx-check{visibility:visible;}
.sx-opt[aria-disabled="true"]{opacity:.45;cursor:not-allowed;}
.sx-empty{padding:10px;font-size:12.5px;color:var(--muted);}
@keyframes sxpop{from{opacity:0;transform:translateY(-4px) scale(.98);}to{opacity:1;transform:none;}}
"""

JS = r"""
(function () {
  var CHEV = '<svg class="sx-chev" width="14" height="14" viewBox="0 0 24 24" fill="none" ' +
    'stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" ' +
    'aria-hidden="true"><path d="M7 10l5 5 5-5"/></svg>';
  var CHECK = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
  var SEARCH = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/></svg>';
  var current = null, uid = 0;
  var root = document.documentElement;

  function nameOf(sel) {
    if (sel.getAttribute('aria-label')) return sel.getAttribute('aria-label');
    if (sel.id) {
      var forLab = document.querySelector('label[for="' + sel.id.replace(/"/g, '') + '"]');
      if (forLab) return forLab.textContent.trim();
    }
    var lab = sel.closest('label');
    var span = lab && lab.querySelector(':scope > span:not(.sx)');
    return span ? span.textContent.trim() : (sel.name || '');
  }

  function enhance(sel) {
    if (sel.dataset.sx || sel.multiple || sel.size > 1 || sel.hasAttribute('data-native')) return;
    sel.dataset.sx = '1';
    var width = sel.offsetWidth;
    var wrap = document.createElement('span');
    wrap.className = 'sx';
    if (sel.closest('.f-sel, tr.editing, .toolbar')) wrap.classList.add('sx-sm');
    if (sel.style.width && sel.style.width !== 'auto') wrap.style.width = sel.style.width;
    else if (!sel.closest('label.field') && width) wrap.style.minWidth = width + 'px';
    if (sel.style.maxWidth) wrap.style.maxWidth = sel.style.maxWidth;
    sel.parentNode.insertBefore(wrap, sel);
    wrap.appendChild(sel);
    sel.classList.add('sx-native');
    sel.tabIndex = -1;
    sel.setAttribute('aria-hidden', 'true');
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'sx-btn';
    btn.setAttribute('role', 'combobox');
    btn.setAttribute('aria-haspopup', 'listbox');
    btn.setAttribute('aria-expanded', 'false');
    btn.setAttribute('aria-label', nameOf(sel));
    btn.innerHTML = '<span class="sx-val"></span>' + CHEV;
    wrap.appendChild(btn);
    function sync() {
      var o = sel.options[sel.selectedIndex];
      btn.querySelector('.sx-val').textContent = o ? o.textContent : '';
      btn.disabled = sel.disabled;
    }
    sync();
    sel._sxSync = sync;
    sel.addEventListener('change', sync);
    // A label click focuses the hidden native control; hand it to the button.
    sel.addEventListener('focus', function () { btn.focus(); });
    btn.addEventListener('click', function (ev) { ev.preventDefault(); toggle(sel, btn); });
    btn.addEventListener('keydown', function (ev) {
      if (current && current.btn === btn) return;  // open: the list's handler owns the keys
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].indexOf(ev.key) >= 0) {
        ev.preventDefault(); open(sel, btn);
      }
    });
  }

  function place() {
    if (!current) return;
    var r = current.btn.getBoundingClientRect(), list = current.list;
    list.style.minWidth = Math.max(180, r.width) + 'px';
    var h = list.offsetHeight, below = window.innerHeight - r.bottom, up = below < h + 12 && r.top > below;
    list.classList.toggle('up', up);
    var left = Math.min(Math.max(8, r.left), window.innerWidth - list.offsetWidth - 8);
    list.style.left = left + 'px';
    list.style.top = (up ? Math.max(8, r.top - h - 6) : r.bottom + 6) + 'px';
  }

  function close(focusBack) {
    if (!current) return;
    var c = current;
    current = null;
    c.list.remove();
    c.btn.setAttribute('aria-expanded', 'false');
    c.btn.removeAttribute('aria-activedescendant');
    if (focusBack) c.btn.focus();
  }

  function toggle(sel, btn) {
    if (current && current.btn === btn) { close(true); return; }
    open(sel, btn);
  }

  function open(sel, btn) {
    if (sel.disabled) return;
    close(false);
    var list = document.createElement('div');
    list.className = 'sx-list';
    var id = 'sx-' + (++uid);
    var search = null;
    if (sel.options.length > 8) {
      var box = document.createElement('label');
      box.className = 'sx-search';
      box.innerHTML = SEARCH;
      search = document.createElement('input');
      search.placeholder = root.getAttribute('data-lbl-search') || 'Search';
      search.setAttribute('aria-label', search.placeholder);
      box.appendChild(search);
      list.appendChild(box);
    }
    var opts = document.createElement('div');
    opts.className = 'sx-opts';
    opts.setAttribute('role', 'listbox');
    opts.id = id;
    opts.setAttribute('aria-label', nameOf(sel));
    list.appendChild(opts);
    var items = [];
    Array.prototype.forEach.call(sel.children, function (node) {
      var group = node.tagName === 'OPTGROUP' ? node : null;
      if (group) {
        var g = document.createElement('div');
        g.className = 'sx-group';
        g.textContent = group.label;
        g.setAttribute('role', 'presentation');
        opts.appendChild(g);
      }
      Array.prototype.forEach.call(group ? group.children : [node], function (o) {
        if (o.tagName !== 'OPTION') return;
        var el = document.createElement('div');
        el.className = 'sx-opt';
        el.id = id + '-' + o.index;
        el.setAttribute('role', 'option');
        el.setAttribute('aria-selected', o.selected ? 'true' : 'false');
        if (o.disabled || (group && group.disabled)) el.setAttribute('aria-disabled', 'true');
        el.innerHTML = '<span class="sx-check">' + CHECK + '</span><span class="sx-text"></span>';
        el.querySelector('.sx-text').textContent = o.textContent;
        if (o.dataset.hint) {
          var h = document.createElement('span');
          h.className = 'sx-hint';
          h.textContent = o.dataset.hint;
          el.appendChild(h);
        }
        el.addEventListener('mousedown', function (ev) { ev.preventDefault(); });
        el.addEventListener('click', function () { choose(o.index); });
        el.addEventListener('mousemove', function () { activate(items.indexOf(el)); });
        el._opt = o;
        opts.appendChild(el);
        items.push(el);
      });
    });
    var empty = document.createElement('div');
    empty.className = 'sx-empty';
    empty.hidden = true;
    empty.textContent = root.getAttribute('data-lbl-nomatch') || 'No matches';
    opts.appendChild(empty);
    document.body.appendChild(list);
    btn.setAttribute('aria-expanded', 'true');
    btn.setAttribute('aria-controls', id);
    current = { sel: sel, btn: btn, list: list, items: items, active: -1, typed: '', typedAt: 0,
                search: search };
    if (search) {
      search.setAttribute('role', 'combobox');
      search.setAttribute('aria-controls', id);
      search.setAttribute('aria-expanded', 'true');
      search.setAttribute('aria-autocomplete', 'list');
    }
    place();
    var start = items.findIndex(function (el) { return el.getAttribute('aria-selected') === 'true'; });
    activate(start < 0 ? next(-1, 1) : start);
    (search || btn).focus({ preventScroll: true });
    if (search) search.addEventListener('input', function () {
      var q = search.value.trim().toLowerCase(), shown = 0;
      items.forEach(function (el) {
        var hit = !q || el.textContent.toLowerCase().indexOf(q) >= 0;
        el.hidden = !hit;
        if (hit) shown++;
      });
      empty.hidden = shown > 0;
      activate(next(-1, 1));
    });
    list.addEventListener('keydown', onKey);
  }

  function visible(i) {
    var el = current.items[i];
    return el && !el.hidden && el.getAttribute('aria-disabled') !== 'true';
  }
  function next(from, step) {
    var n = current.items.length;
    for (var k = 1; k <= n; k++) {
      var i = from + step * k;
      if (i < 0 || i >= n) break;
      if (visible(i)) return i;
    }
    return from;
  }
  function activate(i) {
    if (!current) return;
    current.items.forEach(function (el, j) { el.classList.toggle('active', j === i); });
    current.active = i;
    var el = current.items[i];
    [current.btn, current.search].forEach(function (host) {
      if (!host) return;
      if (el && !el.hidden) host.setAttribute('aria-activedescendant', el.id);
      else host.removeAttribute('aria-activedescendant');
    });
    if (el && !el.hidden) el.scrollIntoView({ block: 'nearest' });
  }
  function choose(index) {
    var c = current;
    if (!c) return;
    var o = c.sel.options[index];
    if (!o || o.disabled) return;
    var changed = c.sel.selectedIndex !== index;
    c.sel.selectedIndex = index;
    close(true);
    if (changed) {
      c.sel.dispatchEvent(new Event('input', { bubbles: true }));
      c.sel.dispatchEvent(new Event('change', { bubbles: true }));
    }
    if (c.sel._sxSync) c.sel._sxSync();
  }
  function onKey(ev) {
    if (!current) return;
    var k = ev.key;
    if (k === 'ArrowDown') { ev.preventDefault(); activate(next(current.active, 1)); }
    else if (k === 'ArrowUp') { ev.preventDefault(); activate(next(current.active, -1)); }
    else if (k === 'Home' && ev.target.tagName !== 'INPUT') { ev.preventDefault(); activate(next(-1, 1)); }
    else if (k === 'End' && ev.target.tagName !== 'INPUT') {
      ev.preventDefault(); activate(next(current.items.length, -1));
    }
    else if (k === 'Enter' || (k === ' ' && ev.target.tagName !== 'INPUT')) {
      ev.preventDefault();
      var el = current.items[current.active];
      if (el) choose(el._opt.index);
    } else if (k === 'Escape') { ev.preventDefault(); close(true); }
    else if (k === 'Tab') { close(false); }
    else if (k.length === 1 && !ev.ctrlKey && !ev.metaKey && ev.target.tagName !== 'INPUT') {
      var now = Date.now();
      current.typed = (now - current.typedAt > 600 ? '' : current.typed) + k.toLowerCase();
      current.typedAt = now;
      var hit = current.items.findIndex(function (el, j) {
        return visible(j) && el.textContent.trim().toLowerCase().indexOf(current.typed) === 0;
      });
      if (hit >= 0) activate(hit);
    }
  }

  // The button keeps focus while the list is open without a search box, so
  // its keys are routed to the list.
  window.addEventListener('keydown', function (ev) {
    if (!current) return;
    if (ev.key === 'Escape') {  // handled here, and not also by the page's Escape
      ev.preventDefault(); ev.stopPropagation(); close(true); return;
    }
    if (document.activeElement === current.btn) {
      onKey(ev);
      // Stop here: after choose() closes the list, the button's own keydown
      // listener would see "closed" and open it again on the same Enter.
      if (ev.key !== 'Tab') ev.stopPropagation();
    }
  }, true);
  document.addEventListener('mousedown', function (ev) {
    if (current && !current.list.contains(ev.target) && !current.btn.contains(ev.target)) close(false);
  });
  var lastWidth = window.innerWidth;
  window.addEventListener('resize', function () {
    if (window.innerWidth !== lastWidth) { lastWidth = window.innerWidth; close(false); }
    else place();
  });
  window.addEventListener('scroll', function (ev) {
    if (!current || current.list.contains(ev.target)) return;
    var r = current.btn.getBoundingClientRect();
    if (r.bottom < 0 || r.top > window.innerHeight) close(false); else place();
  }, true);

  function scan(node) {
    (node.querySelectorAll ? node : document).querySelectorAll('select').forEach(enhance);
  }
  scan(document);
  // Selects that arrive later (the live run panel, swapped-in fragments).
  new MutationObserver(function (records) {
    records.forEach(function (r) {
      r.addedNodes.forEach(function (n) {
        if (n.nodeType !== 1) return;
        if (n.tagName === 'SELECT') enhance(n); else scan(n);
      });
    });
  }).observe(document.body, { childList: true, subtree: true });
  window.stpEnhanceSelects = scan;
})();
"""
