"""The real-browser actors: L4, L5, L5-farm, and the browser humans.

A headless Chromium that actually renders the page and runs the fingerprint
script, so the fingerprint signal is measured against a real browser rather
than a hand-written POST. Actors run concurrently under a semaphore; each has
its own browser context, so their sessions never cross — except the farm, whose
whole point is one profile reused across ten IPs.

Playwright is imported lazily: an httpx-only smoke run, and the unit tests, must
not need a browser installed.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass

from benchmarks.ladder.actors import (
    BASE,
    CHROME_UA,
    ActorSpec,
    Pacer,
    Request,
    human_plan,
    scraper_plan,
)
from benchmarks.ladder.site import PRODUCTS, product_path

# One profile per index, so a unique-profile actor looks like a distinct
# machine and the farm (all sharing index 0) looks like one.
PROFILES = [
    {"viewport": {"width": w, "height": h}, "locale": loc, "timezone_id": tz,
     "device_scale_factor": dsf}
    for w, h, loc, tz, dsf in [
        (1280, 800, "en-US", "America/New_York", 1),
        (1440, 900, "en-GB", "Europe/London", 2),
        (1536, 864, "de-DE", "Europe/Berlin", 1),
        (1366, 768, "fr-FR", "Europe/Paris", 1),
        (1920, 1080, "en-US", "America/Los_Angeles", 1),
        (1600, 900, "es-ES", "Europe/Madrid", 2),
        (1280, 720, "it-IT", "Europe/Rome", 1),
        (2560, 1440, "en-AU", "Australia/Sydney", 2),
    ]
]


@dataclass
class BrowserResult:
    ip: str
    pages_loaded: int
    fingerprinted: bool


def _bot_plan(spec: ActorSpec, rng: random.Random) -> list[Request]:
    if spec.job == "scraper" and spec.level == "L5-farm":
        # Farm members browse lightly; the signal is the shared fingerprint,
        # not the volume. 8 page views each (PREREGISTRATION.md).
        pages = [product_path(rng.randint(1, PRODUCTS)) for _ in range(7)]
        return [Request("GET", "/catalog/"), *(Request("GET", p) for p in pages)]
    if spec.job == "scraper":
        return scraper_plan()
    if spec.job == "credential":
        from benchmarks.ladder.actors import credential_plan
        return credential_plan()
    if spec.job == "poller":
        from benchmarks.ladder.actors import poller_plan
        return poller_plan()
    if spec.job == "vulnscan":
        from benchmarks.ladder.actors import vulnscan_plan
        return vulnscan_plan()
    raise ValueError(spec.job)


async def _drive(context, spec: ActorSpec, plan: list[Request], pacer: Pacer | None) -> BrowserResult:
    page = await context.new_page()
    loaded = 0
    fp_seen = {"hit": False}

    async def on_request(req):
        if req.url.endswith("/microguard/fp") and req.method == "POST":
            fp_seen["hit"] = True

    page.on("request", on_request)
    for req in plan:
        url = BASE + req.path
        try:
            if req.method == "GET":
                await page.goto(url, wait_until="networkidle", timeout=15000)
                loaded += 1
            else:
                # A real form post from within the page, so it carries the
                # browser's headers and the session cookie the GET set.
                await page.evaluate(
                    """([u, b]) => fetch(u, {method:'POST', headers:{'Content-Type':
                       'application/x-www-form-urlencoded'}, body:b})""",
                    [url, "username=admin&password=x"],
                )
        except Exception:  # noqa: BLE001,S110 - a slow nav is one lost request, not a failed run
            pass
        if pacer is not None and req.page:
            await asyncio.sleep(pacer.gap())
    # The fingerprint POST is fire-and-forget from the page; give it a beat.
    await asyncio.sleep(0.5)
    await page.close()
    return BrowserResult(spec.ip, loaded, fp_seen["hit"])


async def _run_async(
    specs: list[ActorSpec], seed: int, concurrency: int, headed: bool
) -> list[BrowserResult]:
    from playwright.async_api import async_playwright

    results: list[BrowserResult] = []
    sem = asyncio.Semaphore(concurrency)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not headed)

        async def one(spec: ActorSpec, idx: int) -> None:
            rng = random.Random((seed, spec.ip).__hash__())
            profile = PROFILES[spec.profile % len(PROFILES)] if spec.profile else PROFILES[idx % len(PROFILES)]
            paced = spec.level in ("L5", "L5-farm") or spec.job == "human_browser"
            pacer = Pacer(hash((seed, spec.ip)) & 0xFFFF) if paced else None
            plan = human_plan(rng) if spec.cls == "human" else _bot_plan(spec, rng)
            async with sem:
                context = await browser.new_context(
                    user_agent=CHROME_UA,
                    extra_http_headers={"X-Forwarded-For": spec.ip},
                    **profile,
                )
                try:
                    results.append(await _drive(context, spec, plan, pacer))
                finally:
                    await context.close()

        await asyncio.gather(*(one(s, i) for i, s in enumerate(specs)))
        await browser.close()
    return results


def run_browser_actors(
    specs: list[ActorSpec], seed: int, concurrency: int = 8, headed: bool = False
) -> list[BrowserResult]:
    """Drive every browser actor, concurrently. Returns per-actor outcomes."""
    if not specs:
        return []
    return asyncio.run(_run_async(specs, seed, concurrency, headed))
