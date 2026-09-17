"""The traffic that climbs the evasion ladder.

Each actor gets one IP and one class before it sends anything, so ground truth
is exact (PREREGISTRATION.md, Suite A). Bots run the same request budget at
every level; what changes up the ladder is only how well they impersonate a
browser: user agent, headers, pacing, and whether a real browser is driving.

Two transports, because the levels demand both:
- httpx for L0-L3 and scripted humans: exact control of UA, headers, and gaps.
- Playwright for L4-L5 and browser humans: a real Chromium that runs the
  fingerprint script, so the fingerprint signal is tested against a real
  browser and not a forged POST.

Nothing is aimed anywhere but 127.0.0.1.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from benchmarks.ladder.site import PRODUCTS, product_path

BASE = "http://127.0.0.1:8080"
BOT_NET, HUMAN_NET = "10.66", "10.99"
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
GAPS_FILE = Path(__file__).with_name("human_gaps.json")
GAP_CLIP = (1.0, 30.0)

LEVELS = ("L0", "L1", "L2", "L3", "L4", "L5", "L5-farm")
BROWSER_LEVELS = frozenset({"L4", "L5", "L5-farm"})
HUMAN_PACED = frozenset({"L3", "L5", "L5-farm"})


# --------------------------------------------------------------------------
# pacing
# --------------------------------------------------------------------------


class Pacer:
    """Draws page-to-page gaps for the human-paced levels.

    Real Zanbil human page-view gaps (benchmarks/ladder/human_gaps.json),
    clipped to GAP_CLIP so a single run does not stretch to hours. Bots and
    humans at a paced level draw from the same distribution, so timing alone
    cannot separate them.
    """

    def __init__(self, seed: int):
        payload = json.loads(GAPS_FILE.read_text(encoding="utf-8"))
        self._q = payload["quantiles_permille"]
        self._rng = random.Random(seed)

    def gap(self) -> float:
        lo, hi = GAP_CLIP
        return min(hi, max(lo, self._q[self._rng.randrange(len(self._q))]))


# --------------------------------------------------------------------------
# what to request
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    # A page view is where a real browser would run the fingerprint script and
    # send a Referer on the next hop; assets and API calls are neither.
    page: bool = True
    body: dict | None = None


def scraper_plan() -> list[Request]:
    reqs = [Request("GET", "/catalog/")]
    reqs += [Request("GET", product_path(i)) for i in range(1, 25)]
    return reqs  # 25


def credential_plan() -> list[Request]:
    reqs = [Request("GET", "/login.html")]
    reqs += [
        Request("POST", "/login", page=False, body={"username": "admin", "password": f"try{i}"})
        for i in range(15)
    ]
    return reqs  # 16


def poller_plan() -> list[Request]:
    return [Request("GET", product_path(7)) for _ in range(15)]  # 15


# 10 probe paths a static shop never runs, then 10 injection payloads on the
# one endpoint that takes input. The offline scan and path blocklist should see
# these; the point is whether behaviour flags them once the UA is a browser.
PROBE_PATHS = (
    "/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/phpmyadmin/",
    "/xmlrpc.php", "/.aws/credentials", "/vendor/phpunit/phpunit/phpunit.php",
    "/cgi-bin/test.cgi", "/boaform/admin/formLogin",
)
INJECTIONS = (
    "1' OR '1'='1", "1 UNION SELECT null,null--", "'; DROP TABLE users--",
    "../../../../etc/passwd", "<script>alert(1)</script>", "${jndi:ldap://x/a}",
    "1) waitfor delay '0:0:5'--", "%00", "; sleep(5)", "|| cat /etc/passwd",
)


def vulnscan_plan() -> list[Request]:
    reqs = [Request("GET", p, page=False) for p in PROBE_PATHS]
    reqs += [Request("GET", f"/search?q={payload}", page=False) for payload in INJECTIONS]
    return reqs  # 20


BOT_PLANS: dict[str, Callable[[], list[Request]]] = {
    "scraper": scraper_plan,
    "credential": credential_plan,
    "poller": poller_plan,
    "vulnscan": vulnscan_plan,
}
# Which levels each job runs at. Poller is a constant-rate job; pacing it into
# human gaps would make it a different job, so it stops at the fast levels.
# Vulnscan L0-L2 is the real tools (run_tools), so its scripted plan starts at L3.
JOB_LEVELS: dict[str, tuple[str, ...]] = {
    "scraper": LEVELS,
    "credential": ("L0", "L1", "L2", "L3", "L4", "L5"),
    "poller": ("L0", "L1", "L2", "L4"),
    "vulnscan": ("L3", "L4", "L5"),
}
TOOL_DEFAULT_UA = {
    "scraper": "python-requests/2.31.0",
    "credential": "python-requests/2.31.0",
    "poller": "Go-http-client/1.1",
    "vulnscan": "python-requests/2.31.0",
}


# --------------------------------------------------------------------------
# scripted transport (httpx): L0-L3 bots and scripted humans
# --------------------------------------------------------------------------


def _headers(ip: str, ua: str, referer: str | None, browser_headers: bool) -> dict[str, str]:
    headers = {"X-Forwarded-For": ip, "User-Agent": ua}
    if browser_headers:
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        headers["Accept-Language"] = "en-US,en;q=0.9"
        headers["Accept-Encoding"] = "gzip, deflate"
    if referer:
        headers["Referer"] = BASE + referer
    return headers


def run_scripted(
    client: httpx.Client,
    ip: str,
    plan: Iterable[Request],
    *,
    ua: str,
    browser_headers: bool,
    referer_chain: bool,
    pacer: Pacer | None,
    poll_interval: float | None,
) -> None:
    """Drive one scripted actor's plan through nginx.

    `referer_chain` sets each page's Referer to the previous page, the way a
    browser does; without it every request arrives refererless.
    """
    prev: str | None = None
    for req in plan:
        referer = prev if referer_chain else None
        headers = _headers(ip, ua, referer, browser_headers)
        try:
            client.request(req.method, req.path, headers=headers, data=req.body, timeout=10)
        except httpx.HTTPError:
            pass
        if req.page:
            prev = req.path
        if poll_interval is not None:
            time.sleep(poll_interval)
        elif pacer is not None and req.page:
            time.sleep(pacer.gap())


def human_plan(rng: random.Random) -> list[Request]:
    """A believable shopping visit: land, browse a few products, sometimes act."""
    reqs = [Request("GET", "/")]
    reqs.append(Request("GET", "/catalog/"))
    for _ in range(rng.randint(2, 5)):
        reqs.append(Request("GET", product_path(rng.randint(1, PRODUCTS))))
    if rng.random() < 0.3:
        reqs.append(Request("GET", f"/search?q=product+{rng.randint(1, 99)}", page=False))
    if rng.random() < 0.15:
        reqs.append(Request("GET", "/login.html"))
        reqs.append(Request("POST", "/login", page=False,
                            body={"username": f"user{rng.randint(1, 999)}", "password": "hunter2"}))
    return reqs


# --------------------------------------------------------------------------
# actor plan-out: who exists in one run
# --------------------------------------------------------------------------


@dataclass
class ActorSpec:
    ip: str
    cls: str  # "bot" | "human"
    job: str  # bot job, or "human_scripted" / "human_browser"
    level: str
    profile: int = 0  # farm actors sharing a browser profile share this
    fingerprint_hash: str | None = None


@dataclass
class RunPlan:
    seed: int
    config: str
    scripted_bots: list[ActorSpec] = field(default_factory=list)
    browser_bots: list[ActorSpec] = field(default_factory=list)
    tool_bots: list[ActorSpec] = field(default_factory=list)
    scripted_humans: list[ActorSpec] = field(default_factory=list)
    browser_humans: list[ActorSpec] = field(default_factory=list)

    def all(self) -> list[ActorSpec]:
        return (self.scripted_bots + self.browser_bots + self.tool_bots
                + self.scripted_humans + self.browser_humans)

    def truth(self) -> dict[str, dict]:
        return {
            a.ip: {"class": a.cls, "job": a.job, "level": a.level, "profile": a.profile}
            for a in self.all()
        }


TOOL_JOBS = ("ffuf", "sqlmap", "nuclei")  # the real vulnscan tools, one IP each, at L0-L2


def plan_run(seed: int, config: str) -> RunPlan:
    """Assign every actor its IP and class for one (seed, config) run.

    IP third octet encodes the level index, the fourth a slot, so an IP is
    self-describing in the access log; the returned truth carries it anyway.
    """
    plan = RunPlan(seed, config)
    for lvl_idx, level in enumerate(LEVELS):
        for job in ("scraper", "credential", "poller", "vulnscan"):
            if level not in JOB_LEVELS[job]:
                continue
            n = 10 if (job == "scraper" and level == "L5-farm") else 2
            for slot in range(n):
                ip = f"{BOT_NET}.{lvl_idx}.{_slot(job, slot)}"
                spec = ActorSpec(ip, "bot", job, level, profile=(1 if level == "L5-farm" else 0))
                (plan.browser_bots if level in BROWSER_LEVELS else plan.scripted_bots).append(spec)
        # Real vulnscan tools live at L0-L2, one IP each, outside the plan model.
        if level in ("L0", "L1", "L2"):
            for t_idx, tool in enumerate(TOOL_JOBS):
                ip = f"{BOT_NET}.{lvl_idx}.{200 + t_idx}"
                plan.tool_bots.append(ActorSpec(ip, "bot", f"tool:{tool}", level))

    for i in range(20):
        plan.scripted_humans.append(ActorSpec(f"{HUMAN_NET}.1.{i + 1}", "human", "human_scripted", "human"))
    for i in range(15):
        plan.browser_humans.append(ActorSpec(f"{HUMAN_NET}.2.{i + 1}", "human", "human_browser", "human"))
    return plan


_JOB_BASE = {"scraper": 0, "credential": 20, "poller": 40, "vulnscan": 60}


def _slot(job: str, slot: int) -> int:
    return _JOB_BASE[job] + slot + 1
