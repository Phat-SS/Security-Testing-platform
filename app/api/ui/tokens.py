"""The design tokens — the one place a colour, radius or shadow is defined.

Until this module existed the palette was declared twice: `views._CSS` carried
a light `:root` plus an *unguarded* `@media (prefers-color-scheme: dark)`, and
`ui.CSS` carried a second, guarded copy of the same dark values plus explicit
`[data-theme]` blocks. Both were concatenated into every page, and the toggle
only worked because the second copy happened to come last. Two sources for one
value is a bug that has not happened yet.

The order below is the whole contract, and it is the reason the toggle wins in
both directions:

  1. bare `:root` defines the COMPLETE light palette — no colour is ever
     defined only inside a media query or a `[data-theme]` block;
  2. the dark media query is guarded with `:not([data-theme="light"])`, so a
     tester on a dark OS who explicitly asked for light actually gets it;
  3. `[data-theme="dark"]` / `[data-theme="light"]` restate each side, so an
     explicit choice beats the OS either way.
"""

from __future__ import annotations

# Values are literal hex rather than computed: these are read off the running
# product, and a generated palette drifts from what the reviewer signed off on.
_DARK = """
  --bg:#0b1113;--surface:#121a1c;--fg:#e6efed;--muted:#8ea3a1;--faint:#5e7472;
  --border:#223032;--border-strong:#2c3d3e;
  --accent:#34c2bd;--accent-ink:#06201f;--accent-soft:#163333;--accent-border:#1f4b48;
  --crit:#e05a68;--high:#e08a4a;--med:#d4af37;--low:#4caf7d;--info:#8b98a3;
  --crit-soft:#2a1418;--high-soft:#2a1f11;--med-soft:#2a250f;--low-soft:#122a1c;--info-soft:#1a2022;
  --shadow:0 1px 2px rgba(0,0,0,.3);
  --tip-bg:#e8f1ef;--tip-fg:#0d1517;
  --zebra:#151e20;
  --sticky-bg:#182224;
  --sidebar:#121a1c;
"""

_LIGHT = """
  --bg:#f6f7f6;--surface:#ffffff;--fg:#12181b;--muted:#5b6b6d;--faint:#8a9698;
  --border:#dde3e2;--border-strong:#c7d0cf;
  --accent:#0d6e6e;--accent-ink:#ffffff;--accent-soft:#e3f2f1;--accent-border:#bfe0de;
  --crit:#b4232a;--high:#c8500f;--med:#96700a;--low:#2f7a4f;--info:#5c6b74;
  --crit-soft:#fbe6e8;--high-soft:#fbead9;--med-soft:#f7edd0;--low-soft:#e1f2e7;--info-soft:#eaecee;
  --shadow:0 1px 2px rgba(20,30,30,.05),0 1px 1px rgba(20,30,30,.04);
  --tip-bg:#1b2426;--tip-fg:#f2f7f6;
  --zebra:#fbfcfc;
  --sticky-bg:#f2f5f4;
  --sidebar:#ffffff;
"""

# Not themed: the same in both palettes, so they sit outside the three blocks.
_SCALE = """
  --radius:6px;--radius-lg:10px;--space:8px;
  --sidebar-w:244px;--sidebar-w-min:64px;--appbar-h:52px;
  --font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;
"""

CSS = f""":root{{{_SCALE}{_LIGHT}}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{{_DARK}}}}}
:root[data-theme="dark"]{{{_DARK}}}
:root[data-theme="light"]{{{_LIGHT}}}
"""
