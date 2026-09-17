"""A single shareable card: the evasion-ladder chart plus three headline numbers.

Reads the ladder results, lays out an HTML card, and rasterizes it to PNG with
the headless Chromium already used by the ladder. Writes into linkedin-assets/
(git-ignored). Headline numbers are computed from the results, never typed in.

    python -m benchmarks.linkedin
"""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.figures import ladder_chart

ROOT = Path(__file__).resolve().parents[1]
SCORED = ROOT / "benchmarks" / "results" / "ladder" / "scored.json"
OUT = ROOT / "linkedin-assets"
LADDER_ORDER = ["L0", "L1", "L2", "L3", "L4", "L5", "L5-farm"]


def _recall(cells, config, level, det):
    r = cells.get(f"{config}/{level}", {}).get(det, {}).get("recall")
    return r["value"] if r and r.get("n") else None


def headline_numbers(scored: dict) -> list[tuple[str, str]]:
    cells = scored["cells"]
    config = "default" if "default" in scored["seeds"] else next(iter(scored["seeds"]))
    numbers: list[tuple[str, str]] = []

    # 1. blend vs UA regex once the UA is spoofed (L1).
    blend_l1 = _recall(cells, config, "L1", "mg_blend")
    ua_l1 = _recall(cells, config, "L1", "ua_regex")
    if blend_l1 is not None and ua_l1 is not None:
        numbers.append((
            f"{blend_l1 * 100:.0f}% vs {ua_l1 * 100:.0f}%",
            "bots caught once they fake a browser UA — microguard vs a UA blocklist"))

    # 2. human false-positive rate at the shipping threshold.
    hfpr = cells.get(f"{config}/humans", {}).get("mg_blend", {}).get("fpr")
    if hfpr:
        numbers.append((f"{hfpr['k']} / {hfpr['n']}",
                        "real humans wrongly flagged at the default block threshold"))

    # 3. where even a real browser stops helping the bot (worst level for blend).
    worst = min(
        ((lvl, _recall(cells, config, lvl, "mg_blend")) for lvl in LADDER_ORDER
         if _recall(cells, config, lvl, "mg_blend") is not None),
        key=lambda p: p[1], default=(None, None))
    if worst[0] is not None:
        numbers.append((
            f"{worst[1] * 100:.0f}%",
            (f"recall at {worst[0]} — the low-and-slow distributed browser farm, "
             "microguard's hardest case")))
    return numbers[:3]


def build_card(scored: dict) -> str:
    cells = scored["cells"]
    config = "default" if "default" in scored["seeds"] else next(iter(scored["seeds"]))
    levels = [lvl for lvl in LADDER_ORDER if f"{config}/{lvl}" in cells]
    series = {}
    fpr = {}
    for det in ("ua_regex", "rate_limit", "crowdsec", "mg_blend"):
        row = [_recall(cells, config, lvl, det) for lvl in levels]
        if any(v is not None for v in row):
            series[det] = row
            h = cells.get(f"{config}/humans", {}).get(det, {}).get("fpr")
            fpr[det] = f"{h['k']}/{h['n']} humans" if h else ""
    chart = ladder_chart(levels, series, fpr, title="")

    tiles = "".join(
        f'<div class="tile"><div class="big">{val}</div><div class="cap">{cap}</div></div>'
        for val, cap in headline_numbers(scored)
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
      * {{ box-sizing: border-box; margin: 0; }}
      body {{ width: 1200px; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
              background: #0b1120; color: #e5e7eb; padding: 48px 56px; }}
      h1 {{ font-size: 40px; letter-spacing: -0.02em; }}
      .sub {{ color: #94a3b8; font-size: 20px; margin-top: 8px; }}
      .tiles {{ display: flex; gap: 20px; margin: 32px 0; }}
      .tile {{ flex: 1; background: #111827; border: 1px solid #1f2937; border-radius: 14px;
               padding: 22px 24px; }}
      .big {{ font-size: 38px; font-weight: 700; color: #f87171; }}
      .cap {{ color: #9ca3af; font-size: 15px; margin-top: 8px; line-height: 1.35; }}
      .chart {{ background: #111827; border: 1px solid #1f2937; border-radius: 14px;
                padding: 20px; color: #e5e7eb; }}
      .foot {{ color: #64748b; font-size: 14px; margin-top: 20px; }}
    </style></head><body>
      <h1>Microguard vs. bots that fake being human</h1>
      <div class="sub">Detection built on a 2&nbsp;KB micrograd model, measured against
        the alternatives an operator would actually deploy — on the same bots at rising
        levels of evasion. Rules fixed before any run.</div>
      <div class="tiles">{tiles}</div>
      <div class="chart">{chart}</div>
      <div class="foot">Recall vs. evasion level (L0 = announces itself, L5-farm = a real
        headless browser pacing like a human across many IPs). Baselines: a User-Agent
        blocklist, a rate limit, CrowdSec.</div>
    </body></html>"""


def render(html: str, out_png: Path) -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 900},
                                device_scale_factor=2)
        page.set_content(html, wait_until="networkidle")
        box = page.locator("body").bounding_box()
        page.screenshot(path=str(out_png), clip=box)
        browser.close()
    return True


def main() -> None:
    if not SCORED.exists():
        print(f"no ladder results yet at {SCORED}; run the ladder and score it first")
        return
    scored = json.loads(SCORED.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    html = build_card(scored)
    (OUT / "benchmark-card.html").write_text(html, encoding="utf-8")
    png = OUT / "benchmark-card.png"
    if render(html, png):
        print(f"wrote {png}")
    else:
        print(f"wrote {OUT / 'benchmark-card.html'} (Playwright absent; open and screenshot)")
    for val, cap in headline_numbers(scored):
        print(f"  {val:14} {cap}")


if __name__ == "__main__":
    main()
