"""Hand-built SVG figures for the benchmark report.

SVG rather than a plotting library so the figures embed directly in Markdown and
GitHub, carry no runtime, and stay legible in light and dark (every colour is
explicit; text uses currentColor where the host theme can reach it). One figure
per function; each returns an SVG string.
"""

from __future__ import annotations

PALETTE = {
    "ua_regex": "#9ca3af",
    "rate_limit": "#f59e0b",
    "path_blocklist": "#a78bfa",
    "crowdsec": "#38bdf8",
    "mg_scan": "#34d399",
    "mg_blend": "#ef4444",
    "mg_heuristic": "#fb7185",
}
LABELS = {
    "ua_regex": "UA regex",
    "rate_limit": "rate limit",
    "path_blocklist": "path blocklist",
    "crowdsec": "CrowdSec",
    "mg_scan": "microguard scan",
    "mg_blend": "microguard (blend)",
    "mg_heuristic": "microguard (rules)",
}


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def ladder_chart(levels: list[str], series: dict[str, list[float | None]],
                 fpr: dict[str, str] | None = None, title: str = "") -> str:
    """Recall (y) vs evasion level (x), one line per detector.

    `series[name]` is a recall in [0,1] or None (level not measured) per level.
    `fpr[name]` is a short human-FPR string shown in the legend.
    """
    w, h = 720, 420
    ml, mr, mt, mb = 56, 210, 40, 46
    pw, ph = w - ml - mr, h - mt - mb
    n = len(levels)
    def x(i: int) -> float:
        return ml + (pw * i / (n - 1) if n > 1 else pw / 2)
    def y(v: float) -> float:
        return mt + ph * (1 - v)

    parts = [
        (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
         f'font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13">'),
        f'<rect width="{w}" height="{h}" fill="none"/>',
    ]
    if title:
        parts.append(f'<text x="{ml}" y="22" font-size="15" font-weight="600" '
                     f'fill="currentColor">{_esc(title)}</text>')
    # gridlines + y labels
    for gv in (0, 0.25, 0.5, 0.75, 1.0):
        gy = y(gv)
        parts.append(f'<line x1="{ml}" y1="{gy:.1f}" x2="{ml + pw}" y2="{gy:.1f}" '
                     f'stroke="currentColor" stroke-opacity="0.12"/>')
        parts.append(f'<text x="{ml - 8}" y="{gy + 4:.1f}" text-anchor="end" '
                     f'fill="currentColor" fill-opacity="0.7">{int(gv * 100)}%</text>')
    parts.append(f'<text x="{ml - 40}" y="{mt + ph / 2}" fill="currentColor" '
                 f'fill-opacity="0.7" transform="rotate(-90 {ml - 40} {mt + ph / 2})" '
                 f'text-anchor="middle">recall (bots caught)</text>')
    # x labels
    for i, lvl in enumerate(levels):
        parts.append(f'<text x="{x(i):.1f}" y="{mt + ph + 22}" text-anchor="middle" '
                     f'fill="currentColor" fill-opacity="0.8">{_esc(lvl)}</text>')

    order = [k for k in PALETTE if k in series]
    for name in order:
        color = PALETTE[name]
        pts = [(x(i), y(v)) for i, v in enumerate(series[name]) if v is not None]
        if not pts:
            continue
        d = "M" + " L".join(f"{px:.1f},{py:.1f}" for px, py in pts)
        parts.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2.5" '
                     f'stroke-linejoin="round"/>')
        for px, py in pts:
            parts.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3.4" fill="{color}"/>')
    # legend
    ly = mt + 4
    for name in order:
        label = LABELS.get(name, name)
        note = f"  ({fpr[name]})" if fpr and name in fpr else ""
        parts.append(f'<rect x="{ml + pw + 16}" y="{ly - 9}" width="14" height="4" '
                     f'rx="2" fill="{PALETTE[name]}"/>')
        parts.append(f'<text x="{ml + pw + 36}" y="{ly - 4}" fill="currentColor">'
                     f'{_esc(label)}<tspan fill-opacity="0.55">{_esc(note)}</tspan></text>')
        ly += 24
    parts.append("</svg>")
    return "\n".join(parts)


def grouped_bars(title: str, groups: list[str], series: dict[str, list[float]],
                 colors: dict[str, str], unit: str = "") -> str:
    """Simple grouped bar chart (used for latency and inference)."""
    w, h = 640, 340
    ml, mr, mt, mb = 60, 150, 40, 50
    pw, ph = w - ml - mr, h - mt - mb
    names = list(series)
    peak = max((v for vals in series.values() for v in vals), default=1.0) or 1.0
    gcount = len(groups)
    gw = pw / gcount
    bw = gw / (len(names) + 1)
    parts = [
        (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
         f'font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13">'),
        (f'<text x="{ml}" y="22" font-size="15" font-weight="600" fill="currentColor">'
         f'{_esc(title)}</text>'),
    ]
    for gv in (0, 0.5, 1.0):
        gy = mt + ph * (1 - gv)
        parts.append(f'<line x1="{ml}" y1="{gy:.1f}" x2="{ml + pw}" y2="{gy:.1f}" '
                     f'stroke="currentColor" stroke-opacity="0.12"/>')
        parts.append(f'<text x="{ml - 8}" y="{gy + 4:.1f}" text-anchor="end" '
                     f'fill="currentColor" fill-opacity="0.7">{peak * gv:.1f}</text>')
    for gi, group in enumerate(groups):
        gx = ml + gw * gi
        for ni, name in enumerate(names):
            v = series[name][gi]
            bh = ph * (v / peak)
            bx = gx + bw * (ni + 0.5)
            parts.append(f'<rect x="{bx:.1f}" y="{mt + ph - bh:.1f}" width="{bw * 0.9:.1f}" '
                         f'height="{bh:.1f}" fill="{colors[name]}" rx="2"/>')
        parts.append(f'<text x="{gx + gw / 2:.1f}" y="{mt + ph + 20}" text-anchor="middle" '
                     f'fill="currentColor" fill-opacity="0.8">{_esc(group)}</text>')
    ly = mt + 4
    for name in names:
        parts.append(f'<rect x="{ml + pw + 16}" y="{ly - 9}" width="12" height="12" '
                     f'rx="2" fill="{colors[name]}"/>')
        parts.append(f'<text x="{ml + pw + 34}" y="{ly + 1}" fill="currentColor">'
                     f'{_esc(name)}</text>')
        ly += 22
    if unit:
        parts.append(f'<text x="{ml}" y="{h - 6}" fill="currentColor" fill-opacity="0.55">'
                     f'{_esc(unit)}</text>')
    parts.append("</svg>")
    return "\n".join(parts)
