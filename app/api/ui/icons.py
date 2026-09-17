"""Inline SVG icons.

Inline rather than a sprite sheet or an icon font: this app ships no static
files at all (every page is one self-contained response), and `currentColor`
is what lets a nav item recolour on hover and in the dark palette without a
second asset.

One grid (24), one stroke weight (1.8), one cap style — an icon set whose
members disagree on those reads as three different products.
"""

from __future__ import annotations

_PATHS = {
    "shield": '<path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6z"/><path d="M9.5 12l1.8 1.8 3.6-3.6"/>',
    "list": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9h10M7 13h6"/>',
    "alert": '<path d="M12 4l8 14H4z"/><path d="M12 10v3.5M12 16h.01"/>',
    "clock": '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l2.5 2"/>',
    "check": '<path d="M4 12.5l5 5L20 6.5"/>',
    "globe": ('<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2.5 2.6 2.5 12.8 0 16'
              'M12 4c-2.5 2.6-2.5 12.8 0 16"/>'),
    "identity": ('<circle cx="9" cy="9" r="3.2"/><path d="M3.5 19c.8-3 2.9-4.5 5.5-4.5s4.7 1.5 5.5 4.5"/>'
                 '<path d="M16 7h5M16 11h5"/>'),
    "link": ('<path d="M10 14l-3.5 3.5a3.5 3.5 0 01-5-5L5 9"/>'
             '<path d="M14 10l3.5-3.5a3.5 3.5 0 015 5L19 15"/><path d="M9.5 14.5l5-5"/>'),
    "sliders": '<path d="M5 7h14M5 12h14M5 17h14"/>',
    "power": '<path d="M12 4v8"/><path d="M7.5 7a7 7 0 109 0"/>',
    "chevron-updown": '<path d="M8 9l4-4 4 4"/><path d="M16 15l-4 4-4-4"/>',
    "panel": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9.5 4v16"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="M15.8 15.8L20 20"/>',
    "x": '<path d="M6 6l12 12M18 6L6 18"/>',
    "external": '<path d="M14 4h6v6"/><path d="M20 4l-9 9"/><path d="M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5"/>',
}


def icon(name: str, size: int = 16, cls: str = "") -> str:
    """One icon as inline SVG, inheriting the surrounding text colour.

    `aria-hidden` because every caller here pairs the glyph with a real text
    label — announcing both would read the item twice.
    """
    body = _PATHS[name]
    klass = f' class="{cls}"' if cls else ""
    return (
        f'<svg{klass} width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        f'stroke-linejoin="round" aria-hidden="true">{body}</svg>'
    )


def names() -> list[str]:
    return sorted(_PATHS)
