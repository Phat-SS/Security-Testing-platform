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
    "moon": '<path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"/>',
    "sun": ('<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2'
            'M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4"/>'),
    "file": '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h4"/>',
    "settings": ('<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3'
                 'M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1"/>'),
    "sparkle": '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/>',
    "trash": ('<path d="M4 7h16"/><path d="M9.5 7V4.5h5V7"/>'
              '<path d="M6.5 7l.8 12.5a1.5 1.5 0 001.5 1.5h6.4a1.5 1.5 0 001.5-1.5L17.5 7"/>'
              '<path d="M10 11v6M14 11v6"/>'),
    "copy": ('<rect x="8" y="8" width="12" height="12" rx="2"/>'
             '<path d="M16 8V5.5A1.5 1.5 0 0014.5 4h-9A1.5 1.5 0 004 5.5v9A1.5 1.5 0 005.5 16H8"/>'),
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "arrow-right": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "download": '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
    "refresh": '<path d="M20 11a8 8 0 10-2.3 5.7"/><path d="M20 4v7h-7"/>',
    "lock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
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


def logo(size: int = 28) -> str:
    """The Sentinel mark: a radar sweep that has locked onto one finding.

    Not part of the `icon()` set because it is not a line icon — it is filled,
    two-coloured, and owns its own frame.
    """
    return (
        f'<svg class="logo" width="{size}" height="{size}" viewBox="0 0 40 40" aria-hidden="true">'
        '<rect x="1" y="1" width="38" height="38" rx="10" fill="var(--surface)" '
        'stroke="var(--accent)" stroke-opacity=".4"/>'
        '<circle cx="20" cy="20" r="12" fill="none" stroke="var(--accent)" stroke-width="1.4" opacity=".45"/>'
        '<circle cx="20" cy="20" r="6" fill="none" stroke="var(--accent)" stroke-width="1.6"/>'
        '<path d="M20 20 L20 7 A13 13 0 0 1 31.3 13.5 Z" fill="var(--accent)" opacity=".3"/>'
        '<circle cx="20" cy="20" r="2" fill="var(--accent)"/>'
        '<circle cx="28" cy="12.5" r="1.8" fill="var(--crit)"/></svg>'
    )


def names() -> list[str]:
    return sorted(_PATHS)
