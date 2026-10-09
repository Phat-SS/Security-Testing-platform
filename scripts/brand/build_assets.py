"""Build the Sentinel brand assets into docs/assets/.

    python scripts/brand/build_assets.py            # SVGs
    python scripts/brand/build_assets.py --png      # + social-preview.png (needs Edge or Chrome)

Every asset comes from this one file so the README banner, the logos and the
app's own mark (app/api/ui/icons.py `logo()`) stay the same drawing. Colours
are the app's dark/light tokens (app/api/ui/tokens.py).

The SVGs are written for GitHub's README renderer: an <img> SVG there may
animate (SMIL and CSS both run) but may not load fonts or run script, so text
uses system font stacks and nothing is external.
"""

from __future__ import annotations

import argparse
import math
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "assets"

THEMES = {
    "dark": {
        "bg": "#0a0e13", "bg2": "#0d141b", "surface": "#11171f", "border": "#222c38",
        "fg": "#e8edf3", "muted": "#8b97a7", "faint": "#5d6a7c",
        "accent": "#2ee6b6", "accent_ink": "#04221a", "crit": "#ff5468",
        "high": "#ff9447", "low": "#6ca8ff", "grid": "#ffffff", "grid_op": ".035",
    },
    "light": {
        "bg": "#f5f7fa", "bg2": "#eaf3f0", "surface": "#ffffff", "border": "#d6dde6",
        "fg": "#0e1520", "muted": "#566173", "faint": "#8a95a5",
        "accent": "#007a61", "accent_ink": "#ffffff", "crit": "#c8102e",
        "high": "#a84a08", "low": "#1d5fd1", "grid": "#0e1520", "grid_op": ".05",
    },
}

DISPLAY = "'Space Grotesk','Segoe UI Variable Display','Segoe UI',Inter,'Helvetica Neue',Arial,sans-serif"
SANS = "'IBM Plex Sans','Segoe UI',Inter,'Helvetica Neue',Arial,sans-serif"
MONO = "'JetBrains Mono','Cascadia Code',Consolas,'SFMono-Regular',Menlo,monospace"

SWEEP_S = 6  # one radar revolution, seconds


def _pt(cx: float, cy: float, r: float, deg: float) -> tuple[float, float]:
    """Point at `deg` clockwise from 12 o'clock."""
    a = math.radians(deg - 90)
    return round(cx + r * math.cos(a), 2), round(cy + r * math.sin(a), 2)


def _wedge(cx: float, cy: float, r: float, span: float) -> str:
    """The sweep's trailing wedge: from (0 - span) up to 0 degrees."""
    x0, y0 = _pt(cx, cy, r, -span)
    x1, y1 = _pt(cx, cy, r, 0)
    return f"M{cx} {cy} L{x0} {y0} A{r} {r} 0 0 1 {x1} {y1} Z"


def radar(t: dict, cx: float, cy: float, r: float, animated: bool, uid: str,
          blips=None, label: bool = True) -> str:
    """Rings, crosshair, ticks, a rotating sweep, and blips that light up as
    the sweep crosses them. The critical blip pings and names itself."""
    blips = blips or [(38, .62, "low"), (118, .78, "high"), (205, .45, "accent"),
                      (292, .7, "accent"), (140, .72, "crit")]
    s = [f'<g id="{uid}-radar">']
    s.append(f'<circle cx="{cx}" cy="{cy}" r="{r * 1.25}" fill="url(#{uid}-glow)"/>')
    s.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{t["surface"]}" fill-opacity=".55" '
             f'stroke="{t["accent"]}" stroke-opacity=".35" stroke-width="1.5"/>')
    for k in (0.33, 0.66):
        s.append(f'<circle cx="{cx}" cy="{cy}" r="{r * k:.1f}" fill="none" stroke="{t["accent"]}" '
                 f'stroke-opacity=".22" stroke-width="1" stroke-dasharray="2 5"/>')
    s.append(f'<path d="M{cx - r} {cy}H{cx + r}M{cx} {cy - r}V{cy + r}" stroke="{t["accent"]}" '
             f'stroke-opacity=".14" stroke-width="1"/>')
    for deg in range(0, 360, 10):
        long = deg % 30 == 0
        x0, y0 = _pt(cx, cy, r - (9 if long else 5), deg)
        x1, y1 = _pt(cx, cy, r, deg)
        s.append(f'<line x1="{x0}" y1="{y0}" x2="{x1}" y2="{y1}" stroke="{t["accent"]}" '
                 f'stroke-opacity="{".5" if long else ".25"}" stroke-width="1"/>')

    # The sweep: a gradient wedge plus a bright leading edge, rotated as one.
    ex, ey = _pt(cx, cy, r, 0)
    sweep = (f'<path d="{_wedge(cx, cy, r, 70)}" fill="url(#{uid}-sweep)"/>'
             f'<line x1="{cx}" y1="{cy}" x2="{ex}" y2="{ey}" stroke="{t["accent"]}" '
             f'stroke-width="2" stroke-linecap="round"/>')
    if animated:
        s.append(f'<g>{sweep}<animateTransform attributeName="transform" type="rotate" '
                 f'from="0 {cx} {cy}" to="360 {cx} {cy}" dur="{SWEEP_S}s" repeatCount="indefinite"/></g>')
    else:
        s.append(f'<g transform="rotate(78 {cx} {cy})">{sweep}</g>')

    for deg, dist, tone in blips:
        bx, by = _pt(cx, cy, r * dist, deg)
        color = t[tone]
        crit = tone == "crit"
        size = 5 if crit else 3.6
        begin = f"{deg / 360 * SWEEP_S:.2f}s"
        if animated:
            fade = (f'<animate attributeName="opacity" values="1;.18;.18" keyTimes="0;.7;1" '
                    f'dur="{SWEEP_S}s" begin="{begin}" repeatCount="indefinite"/>')
            s.append(f'<circle cx="{bx}" cy="{by}" r="{size}" fill="{color}" opacity=".18">{fade}</circle>')
            if crit:
                s.append(
                    f'<circle cx="{bx}" cy="{by}" r="{size}" fill="none" stroke="{color}" stroke-width="1.6" opacity="0">'
                    f'<animate attributeName="r" values="{size};{size * 5}" dur="{SWEEP_S / 2}s" begin="{begin}" repeatCount="indefinite"/>'
                    f'<animate attributeName="opacity" values=".9;0" dur="{SWEEP_S / 2}s" begin="{begin}" repeatCount="indefinite"/></circle>'
                )
        else:
            s.append(f'<circle cx="{bx}" cy="{by}" r="{size}" fill="{color}"/>')
            if crit:
                s.append(f'<circle cx="{bx}" cy="{by}" r="{size * 2.6}" fill="none" stroke="{color}" '
                         f'stroke-width="1.4" opacity=".45"/>')
        if crit and label:
            lx, ly = bx + 16, by + 26
            tag = (f'<g><line x1="{bx + 4}" y1="{by + 4}" x2="{lx}" y2="{ly - 1}" stroke="{color}" stroke-width="1"/>'
                   f'<rect x="{lx}" y="{ly - 7}" width="104" height="22" rx="6" fill="{t["surface"]}" '
                   f'stroke="{color}" stroke-opacity=".7"/>'
                   f'<text x="{lx + 9}" y="{ly + 8}" font-family="{MONO}" font-size="11" font-weight="700" '
                   f'fill="{color}">API1 · BOLA</text>')
            if animated:
                tag += (f'<animate attributeName="opacity" values="1;1;0;0" keyTimes="0;.55;.7;1" '
                        f'dur="{SWEEP_S}s" begin="{begin}" repeatCount="indefinite"/></g>')
                s.append(tag.replace("<g>", '<g opacity="0">', 1))
            else:
                s.append(tag + "</g>")
    s.append(f'<circle cx="{cx}" cy="{cy}" r="4" fill="{t["accent"]}"/>')
    s.append("</g>")
    return "".join(s)


def defs(t: dict, uid: str) -> str:
    return (
        "<defs>"
        f'<radialGradient id="{uid}-glow"><stop offset="0" stop-color="{t["accent"]}" stop-opacity=".22"/>'
        f'<stop offset="1" stop-color="{t["accent"]}" stop-opacity="0"/></radialGradient>'
        # Bright at the leading edge (the wedge's clockwise end), fading behind.
        f'<linearGradient id="{uid}-sweep" x1="1" y1="0" x2="0" y2=".6">'
        f'<stop offset="0" stop-color="{t["accent"]}" stop-opacity=".5"/>'
        f'<stop offset="1" stop-color="{t["accent"]}" stop-opacity="0"/></linearGradient>'
        f'<linearGradient id="{uid}-bg" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0" stop-color="{t["bg"]}"/><stop offset="1" stop-color="{t["bg2"]}"/></linearGradient>'
        f'<pattern id="{uid}-grid" width="32" height="32" patternUnits="userSpaceOnUse">'
        f'<path d="M32 0H0V32" fill="none" stroke="{t["grid"]}" stroke-opacity="{t["grid_op"]}"/></pattern>'
        f'<linearGradient id="{uid}-scan" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{t["accent"]}" stop-opacity="0"/>'
        f'<stop offset=".5" stop-color="{t["accent"]}" stop-opacity=".07"/>'
        f'<stop offset="1" stop-color="{t["accent"]}" stop-opacity="0"/></linearGradient>'
        "</defs>"
    )


def _check(x: float, y: float, color: str) -> str:
    return (f'<path d="M{x} {y}l3.2 3.2 6.3-6.6" fill="none" stroke="{color}" '
            f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')


def banner(theme: str, animated: bool = True, w: int = 1280, h: int = 400) -> str:
    t = THEMES[theme]
    uid = f"sb{theme[0]}{'a' if animated else 's'}"
    cx, cy, r = 250, h / 2, 140
    tx = 470
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
         f'role="img" aria-labelledby="{uid}-t {uid}-d">'
         f'<title id="{uid}-t">Sentinel</title>'
         f'<desc id="{uid}-d">AI-assisted API security testing platform: the AI proposes, a trusted runner disposes.</desc>',
         defs(t, uid),
         f'<rect width="{w}" height="{h}" rx="18" fill="url(#{uid}-bg)"/>',
         f'<rect width="{w}" height="{h}" rx="18" fill="url(#{uid}-grid)"/>']
    if animated:
        s.append(f'<rect x="0" y="-160" width="{w}" height="160" fill="url(#{uid}-scan)">'
                 f'<animate attributeName="y" values="-160;{h}" dur="7s" repeatCount="indefinite"/></rect>')
    s.append(f'<rect x=".5" y=".5" width="{w - 1}" height="{h - 1}" rx="17.5" fill="none" '
             f'stroke="{t["border"]}"/>')
    s.append(radar(t, cx, cy, r, animated, uid))

    # Copy, right of the radar.
    s.append(f'<text x="{tx}" y="86" font-family="{MONO}" font-size="13" font-weight="700" '
             f'letter-spacing="2.6" fill="{t["accent"]}">AI-ASSISTED · OWASP API TOP 10 (2023)</text>')
    s.append(f'<text x="{tx - 4}" y="164" font-family="{DISPLAY}" font-size="84" font-weight="700" '
             f'letter-spacing="-2" fill="{t["fg"]}">Sentinel</text>')
    s.append(f'<text x="{tx}" y="204" font-family="{SANS}" font-size="21" fill="{t["muted"]}">'
             f'API security testing where the AI proposes —'
             f'<tspan x="{tx}" dy="28">and a trusted runner disposes.</tspan></text>')

    # Terminal line with a typed command and the run's result.
    by, bw = 262, 690
    s.append(f'<rect x="{tx}" y="{by}" width="{bw}" height="66" rx="12" fill="{t["surface"]}" '
             f'stroke="{t["border"]}"/>')
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        s.append(f'<circle cx="{tx + 18 + i * 13}" cy="{by + 16}" r="3.6" fill="{c}" opacity=".85"/>')
    cmd = "sentinel assess CRM-1234 --execute"
    res = "12 approved · 3 findings · evidence chain verified"
    cmd_w = 9.0 * (len(cmd) + 2)
    s.append(f'<clipPath id="{uid}-type"><rect x="{tx + 16}" y="{by + 26}" height="20" '
             f'width="{0 if animated else cmd_w}">'
             + (f'<animate attributeName="width" values="0;{cmd_w};{cmd_w};{cmd_w}" '
                f'keyTimes="0;.28;.94;1" dur="9s" repeatCount="indefinite" calcMode="spline" '
                f'keySplines=".4 0 .6 1;0 0 1 1;0 0 1 1"/>' if animated else "")
             + "</rect></clipPath>")
    s.append(f'<text x="{tx + 18}" y="{by + 40}" font-family="{MONO}" font-size="15" fill="{t["fg"]}" '
             f'clip-path="url(#{uid}-type)"><tspan fill="{t["accent"]}" font-weight="700">$ </tspan>{cmd}</text>')
    if animated:
        s.append(f'<rect x="{tx + 18}" y="{by + 28}" width="8" height="16" rx="1" fill="{t["accent"]}">'
                 f'<animate attributeName="x" values="{tx + 18};{tx + 18 + cmd_w};{tx + 18 + cmd_w};{tx + 18}" '
                 f'keyTimes="0;.28;.94;1" dur="9s" repeatCount="indefinite" calcMode="spline" '
                 f'keySplines=".4 0 .6 1;0 0 1 1;0 0 1 1"/>'
                 f'<animate attributeName="opacity" values="1;0;1" dur="1s" repeatCount="indefinite"/></rect>')
    rx = tx + 18 + cmd_w + 16
    res_g = (f'<g>{_check(rx, by + 35, t["accent"])}'
             f'<text x="{rx + 16}" y="{by + 40}" font-family="{MONO}" font-size="13" '
             f'fill="{t["muted"]}">{res}</text>')
    if rx + 16 + len(res) * 7.9 > tx + bw:   # too long for one line: drop to a second row
        res_g = (f'<g>{_check(tx + 18, by + 55, t["accent"])}'
                 f'<text x="{tx + 34}" y="{by + 60}" font-family="{MONO}" font-size="12.5" '
                 f'fill="{t["muted"]}">{res}</text>')
    if animated:
        s.append(res_g.replace("<g>", '<g opacity="0">', 1)
                 + '<animate attributeName="opacity" values="0;0;1;1;0" keyTimes="0;.3;.36;.92;1" '
                   'dur="9s" repeatCount="indefinite"/></g>')
    else:
        s.append(res_g + "</g>")

    # The three controls, as chips.
    x = tx
    for label in ("Scope-validated", "Human-approved", "Evidence-chained", "Never executes PoC code"):
        cw = 30 + len(label) * 7.6
        s.append(f'<g><rect x="{x}" y="{by + 80}" width="{cw}" height="26" rx="13" fill="{t["accent"]}" '
                 f'fill-opacity=".1" stroke="{t["accent"]}" stroke-opacity=".35"/>'
                 f'{_check(x + 10, by + 93, t["accent"])}'
                 f'<text x="{x + 24}" y="{by + 97.5}" font-family="{SANS}" font-size="12.5" font-weight="600" '
                 f'fill="{t["fg"]}">{label}</text></g>')
        x += cw + 8
    s.append("</svg>")
    return "".join(s)


def mark(theme: str, animated: bool, size: int = 128, frame: bool = True) -> str:
    """The app's logo, drawn at 40x40 like icons.logo(), optionally animated."""
    t = THEMES[theme]
    sweep = '<path d="M20 20 L20 7 A13 13 0 0 1 31.3 13.5 Z" fill="{a}" opacity=".32"/>'.format(a=t["accent"])
    if animated:
        sweep = (f'<g>{sweep}<line x1="20" y1="20" x2="31.3" y2="13.5" stroke="{t["accent"]}" '
                 f'stroke-width=".9" stroke-linecap="round" opacity=".9"/>'
                 f'<animateTransform attributeName="transform" type="rotate" from="0 20 20" to="360 20 20" '
                 f'dur="4s" repeatCount="indefinite"/></g>')
    dot = f'<circle cx="28" cy="12.5" r="1.8" fill="{t["crit"]}">'
    if animated:
        # Lit as the sweep's leading edge passes ~60° (0.67s into a 4s turn).
        dot += ('<animate attributeName="opacity" values="1;.25;.25" keyTimes="0;.6;1" dur="4s" '
                'begin=".67s" repeatCount="indefinite"/>')
    dot += "</circle>"
    ping = ""
    if animated:
        ping = (f'<circle cx="28" cy="12.5" r="1.8" fill="none" stroke="{t["crit"]}" stroke-width=".6" opacity="0">'
                f'<animate attributeName="r" values="1.8;6" dur="2s" begin=".67s" repeatCount="indefinite"/>'
                f'<animate attributeName="opacity" values=".9;0" dur="2s" begin=".67s" repeatCount="indefinite"/></circle>')
    box = (f'<rect x="1" y="1" width="38" height="38" rx="10" fill="{t["surface"] if theme == "light" else t["bg2"]}" '
           f'stroke="{t["accent"]}" stroke-opacity=".45"/>' if frame else "")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 40 40" '
        f'role="img" aria-label="Sentinel"><title>Sentinel</title>{box}'
        f'<circle cx="20" cy="20" r="12" fill="none" stroke="{t["accent"]}" stroke-width="1.4" opacity=".45"/>'
        f'<circle cx="20" cy="20" r="6" fill="none" stroke="{t["accent"]}" stroke-width="1.6"/>'
        f'{sweep}<circle cx="20" cy="20" r="2" fill="{t["accent"]}"/>{dot}{ping}</svg>'
    )


def wordmark(theme: str, animated: bool = False) -> str:
    """Mark + name, for headers and docs. 360x96."""
    t = THEMES[theme]
    inner = mark(theme, animated, 72)
    inner = inner.replace('width="72" height="72"', 'x="12" y="12" width="72" height="72"', 1)
    inner = inner.replace(' xmlns="http://www.w3.org/2000/svg"', "", 1)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="360" height="96" viewBox="0 0 360 96" '
        f'role="img" aria-label="Sentinel"><title>Sentinel</title>{inner}'
        f'<text x="100" y="60" font-family="{DISPLAY}" font-size="44" font-weight="700" '
        f'letter-spacing="-1" fill="{t["fg"]}">Sentinel</text>'
        f'<text x="102" y="80" font-family="{MONO}" font-size="10.5" font-weight="700" letter-spacing="2" '
        f'fill="{t["accent"]}">API SECURITY TESTING</text></svg>'
    )


def social(theme: str = "dark") -> str:
    """1280x640 for GitHub's social preview: the static banner, centred, with room."""
    t = THEMES[theme]
    inner = banner(theme, animated=False)
    inner = inner.replace('width="1280" height="400" viewBox', 'x="0" y="120" width="1280" height="400" viewBox', 1)
    inner = inner.replace(' xmlns="http://www.w3.org/2000/svg"', "", 1)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640">'
            f'<rect width="1280" height="640" fill="{t["bg"]}"/>{inner}'
            f'<text x="640" y="580" text-anchor="middle" font-family="{MONO}" font-size="15" '
            f'fill="{t["faint"]}">Jira → OWASP-aligned plan → human approval → scope-checked run → signed report</text></svg>')


def render_png(svg: Path, png: Path, w: int, h: int) -> bool:
    browser = None
    for name in ("msedge", "chrome", "google-chrome", "chromium"):
        browser = shutil.which(name)
        if browser:
            break
    for p in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Google\Chrome\Application\chrome.exe"):
        if not browser and Path(p).exists():
            browser = p
    if not browser:
        print("no Edge/Chrome found; skipping PNG", file=sys.stderr)
        return False
    html = svg.with_suffix(".render.html")
    html.write_text(f'<html><body style="margin:0">{svg.read_text(encoding="utf-8")}</body></html>',
                    encoding="utf-8")
    # A throwaway profile: with the user's own browser already open, a headless
    # launch on the default profile is handed to that instance and exits 0
    # without ever taking the screenshot.
    # On Windows the launcher can return before its child has written the
    # file, so wait for it rather than trusting the exit code.
    png.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        try:
            subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                            f"--user-data-dir={profile}", f"--window-size={w},{h}",
                            f"--screenshot={png.resolve()}", html.resolve().as_uri()],
                           check=True, timeout=90, capture_output=True)
            deadline = time.time() + 45
            while not png.exists() and time.time() < deadline:
                time.sleep(0.5)
            time.sleep(1)  # let the writer finish
        finally:
            html.unlink(missing_ok=True)
    return png.exists()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--png", action="store_true", help="also render social-preview.png")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    files = {
        "banner-dark.svg": banner("dark"),
        "banner-light.svg": banner("light"),
        "logo-animated-dark.svg": mark("dark", True),
        "logo-animated-light.svg": mark("light", True),
        "logo-dark.svg": mark("dark", False),
        "logo-light.svg": mark("light", False),
        "wordmark-dark.svg": wordmark("dark"),
        "wordmark-light.svg": wordmark("light"),
        "favicon.svg": mark("dark", False, 32),
        "social-preview.svg": social("dark"),
    }
    for name, svg in files.items():
        (OUT / name).write_text(svg + "\n", encoding="utf-8")
        print(f"wrote docs/assets/{name}")
    if args.png and render_png(OUT / "social-preview.svg", OUT / "social-preview.png", 1280, 640):
        print("wrote docs/assets/social-preview.png")


if __name__ == "__main__":
    main()
