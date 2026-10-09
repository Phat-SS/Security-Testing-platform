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

# Values are literal hex rather than computed: these are the Sentinel brand
# palette as drawn on the design canvas, and a generated palette drifts from
# what the reviewer signed off on.
#
# Severity and verdict deliberately do not share a hue: `--ok` (a pass, a
# covered category, an approved test) is the brand mint, and `--low` is blue,
# so "low severity" can never be mistaken for "passed". Every pair that must be
# told apart also differs in lightness, not hue alone.
_DARK = """
  --bg:#0a0e13;--surface:#11171f;--raised:#161e28;--fg:#e8edf3;--muted:#8b97a7;--faint:#76839a;
  --border:#222c38;--border-strong:#2c3846;
  --accent:#2ee6b6;--accent-ink:#04221a;--accent-soft:#15201e;--accent-border:#1f4b40;
  --crit:#ff5468;--high:#ff9447;--med:#f2c14e;--low:#6ca8ff;--info:#8b97a7;--ok:#2ee6b6;
  --crit-soft:#2a1418;--high-soft:#2a1d12;--med-soft:#2a250f;--low-soft:#142034;--info-soft:#1a2028;
  --ok-soft:#15201e;
  --shadow:0 1px 2px rgba(0,0,0,.35);--shadow-lg:0 12px 40px rgba(0,0,0,.45);
  --tip-bg:#e8edf3;--tip-fg:#0a0e13;
  --zebra:#0f151c;
  --sticky-bg:#141b24;
  --sidebar:#0d1218;
  --sev-critical:#ff8a9b;--sev-high:#dc5468;--sev-medium:#ad4251;--sev-low:#7a3540;
  --out-fail:#e23a52;--out-review:#5b8ee8;--out-pass:#14a37f;--out-other:#3a4555;
"""

_LIGHT = """
  --bg:#f5f7fa;--surface:#ffffff;--raised:#f0f3f7;--fg:#0e1520;--muted:#566173;--faint:#647083;
  --border:#e1e6ed;--border-strong:#cdd5df;
  --accent:#007a61;--accent-ink:#ffffff;--accent-soft:#e3f6f0;--accent-border:#b5e3d6;
  --crit:#c8102e;--high:#a84a08;--med:#8a6400;--low:#1d5fd1;--info:#566173;--ok:#007a61;
  --crit-soft:#fde7ea;--high-soft:#fdebdd;--med-soft:#fbf1d6;--low-soft:#e3edfd;--info-soft:#e9edf2;
  --ok-soft:#e3f6f0;
  --shadow:0 1px 2px rgba(14,21,32,.05),0 1px 1px rgba(14,21,32,.04);
  --shadow-lg:0 12px 40px rgba(14,21,32,.10);
  --tip-bg:#0e1520;--tip-fg:#f5f7fa;
  --zebra:#fafbfc;
  --sticky-bg:#f5f7fa;
  --sidebar:#ffffff;
  --sev-critical:#86101f;--sev-high:#b8313f;--sev-medium:#d9636a;--sev-low:#eb9a9a;
  --out-fail:#a1102f;--out-review:#2a6bd4;--out-pass:#007a61;--out-other:#c3cad4;
"""

# Chart colours (--sev-*, --out-*) were run through the dataviz palette
# validator against each theme's surface: severity is an ordinal single-hue
# ramp, outcomes a three-hue categorical set plus a neutral remainder.

# Not themed: the same in both palettes, so they sit outside the three blocks.
# The faces are named first and fall back to the platform's own UI faces: the
# app ships no static files and makes no third-party request (a security tool
# phoning a font CDN on every page view leaks who is testing what), so the
# brand faces are used when the tester has them installed and degrade cleanly
# when they do not.
_SCALE = """
  --radius:8px;--radius-lg:14px;--space:8px;
  --sidebar-w:248px;--sidebar-w-min:64px;--appbar-h:56px;
  --font:14px/1.55 "IBM Plex Sans","Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
  --display:"Space Grotesk","Segoe UI Variable Display","Segoe UI",system-ui,-apple-system,sans-serif;
  --mono:"JetBrains Mono","Cascadia Code",ui-monospace,SFMono-Regular,Consolas,monospace;
  --ease:cubic-bezier(.2,.8,.2,1);--t-fast:120ms;--t-med:200ms;--t-slow:320ms;
"""

CSS = f""":root{{{_SCALE}{_LIGHT}}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{{_DARK}}}}}
:root[data-theme="dark"]{{{_DARK}}}
:root[data-theme="light"]{{{_LIGHT}}}
"""
