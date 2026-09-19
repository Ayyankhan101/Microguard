"""Run the evasion ladder: real production path, exact ground truth.

One invocation runs one (seed, config) cell end to end:

  1. build the shop, start `microguard serve` (observe-only) behind nginx, and
     for the `promoted` config also start `microguard signals`;
  2. drive every actor -- scripted (httpx, threaded), the real tools, and the
     real-browser actors (Playwright, concurrent);
  3. stop everything and save access.log, the decision archive, and the exact
     truth map under benchmarks/results/ladder/<config>/<seed>/.

    python -m benchmarks.ladder.run --seed 1 --config default
    python -m benchmarks.ladder.run --seed 1 --config default --small   # smoke

`--small` keeps only L0-L2 scripted actors and a few humans, no browser, for a
fast wiring check. Nothing ever leaves 127.0.0.1.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import redis

from benchmarks.ladder import actors
from benchmarks.ladder.actors import ActorSpec, Pacer, RunPlan, human_plan, plan_run
from benchmarks.ladder.site import build as build_site
from benchmarks.ladder.tools import run_tool

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "benchmarks" / "results" / "ladder"
REDIS_URL = os.environ.get("LADDER_REDIS_URL", "redis://localhost:6379/15")
SERVE_PORT = 8400
NGINX_PORT = 8080


class Services:
    """nginx + `microguard serve` (+ `signals` when promoted), on loopback."""

    def __init__(self, workdir: Path, archive: Path, promoted: bool):
        self.workdir = workdir
        self.archive = archive
        self.promoted = promoted
        self.procs: list[subprocess.Popen] = []

    def __enter__(self):
        build_site(self.workdir / "site")
        conf = (ROOT / "benchmarks" / "ladder" / "nginx.conf").read_text(encoding="utf-8")
        (self.workdir / "nginx.conf").write_text(
            conf.replace("__PREFIX__", str(self.workdir)), encoding="utf-8"
        )
        redis.Redis.from_url(REDIS_URL).flushdb()

        self._spawn([
            "microguard", "serve", "--host", "127.0.0.1", "--port", str(SERVE_PORT),
            "--redis-url", REDIS_URL, "--block-threshold", "1.0",
            "--collect-to", str(self.archive), "--deployment-id", "ladder",
        ], "serve.log")
        self._wait_serve()
        if self.promoted:
            self._promote_fingerprint()
            self._spawn([
                "microguard", "signals", "--redis-url", REDIS_URL, "--interval", "300",
            ], "signals.log")
        self._spawn(
            ["nginx", "-p", f"{self.workdir}/", "-c", f"{self.workdir}/nginx.conf"],
            "nginx.log", nginx=True,
        )
        self._wait_nginx()
        return self

    def _spawn(self, cmd: list[str], logname: str, nginx: bool = False) -> None:
        log = (self.workdir / logname).open("w", encoding="utf-8")
        self.procs.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
        if nginx:
            self._nginx_cmd = cmd

    def _wait_serve(self) -> None:
        for _ in range(50):
            if self.procs[0].poll() is not None:  # died on a bound port
                log = (self.workdir / "serve.log").read_text(encoding="utf-8", errors="replace")
                raise RuntimeError(
                    f"serve exited during startup (port {SERVE_PORT} already in "
                    f"use?). Last serve.log:\n{log[-400:]}"
                )
            try:
                httpx.get(f"http://127.0.0.1:{SERVE_PORT}/check",
                          headers={"X-Real-IP": "9.9.9.9", "X-Original-URI": "/"}, timeout=1)
                return
            except httpx.HTTPError:
                time.sleep(0.2)
        raise RuntimeError("check server did not come up; see serve.log")

    def _wait_nginx(self) -> None:
        for _ in range(50):
            # A stale server already on :8080 would answer 200 and silently
            # eat the run's traffic (its access.log lands elsewhere), so a bind
            # failure must be fatal rather than something we serve past.
            if self.procs[-1].poll() is not None:
                log = (self.workdir / "error.log").read_text(encoding="utf-8", errors="replace")
                raise RuntimeError(
                    f"nginx exited during startup (port {NGINX_PORT} already in "
                    f"use?). Last error.log:\n{log[-400:]}"
                )
            try:
                r = httpx.get(f"http://127.0.0.1:{NGINX_PORT}/",
                              headers={"X-Forwarded-For": "203.0.113.1"}, timeout=1)
                if r.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError("nginx did not serve; see nginx.log / error.log")

    def _promote_fingerprint(self) -> None:
        from microguard.live.runtime_config import CONFIG_KEY, PROMOTED_SIGNALS_FIELD
        redis.Redis.from_url(REDIS_URL).hset(
            CONFIG_KEY, PROMOTED_SIGNALS_FIELD, json.dumps(["fingerprint"])
        )

    def __exit__(self, *exc) -> None:
        with suppress_all():
            subprocess.run([*self._nginx_cmd, "-s", "stop"], timeout=10, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for proc in self.procs:
            with suppress_all():
                proc.send_signal(signal.SIGTERM)
        for proc in self.procs:
            with suppress_all():
                proc.wait(timeout=10)


class suppress_all:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


# --------------------------------------------------------------------------
# driving the actors
# --------------------------------------------------------------------------


def _drive_scripted(plan: RunPlan, small: bool) -> None:
    """Every scripted bot and human, each in its own thread and client."""
    jobs: list[tuple[ActorSpec, list, dict]] = []
    for spec in plan.scripted_bots:
        opts = _level_opts(spec.level, spec.job, plan.seed)
        jobs.append((spec, actors.BOT_PLANS[spec.job](), opts))
    for spec in plan.scripted_humans:
        rng = random.Random(hash((plan.seed, spec.ip)))
        opts = {"ua": actors.CHROME_UA, "browser_headers": True, "referer_chain": True,
                "pacer": Pacer(hash((plan.seed, spec.ip)) & 0xFFFF), "poll_interval": None}
        jobs.append((spec, human_plan(rng), opts))

    def work(item):
        spec, plan_reqs, opts = item
        with httpx.Client(base_url=actors.BASE) as client:
            actors.run_scripted(client, spec.ip, plan_reqs, **opts)

    with ThreadPoolExecutor(max_workers=8 if small else 16) as pool:
        list(pool.map(work, jobs))


def _level_opts(level: str, job: str, seed: int) -> dict:
    """UA, headers, referer, and pacing for a scripted bot at one level."""
    tool_ua = actors.TOOL_DEFAULT_UA[job]
    poll = 2.0 if job == "poller" else None
    if level == "L0":
        return {"ua": tool_ua, "browser_headers": False, "referer_chain": False,
                "pacer": None, "poll_interval": poll}
    if level == "L1":
        return {"ua": actors.CHROME_UA, "browser_headers": False, "referer_chain": False,
                "pacer": None, "poll_interval": poll}
    if level == "L2":
        return {"ua": actors.CHROME_UA, "browser_headers": True, "referer_chain": True,
                "pacer": None, "poll_interval": poll}
    if level == "L3":
        return {"ua": actors.CHROME_UA, "browser_headers": True, "referer_chain": True,
                "pacer": Pacer(seed * 131 + hash(job) % 97), "poll_interval": None}
    raise ValueError(f"{level} is not a scripted level")


def _run_tools(plan: RunPlan, log) -> None:
    """All tool actors at once; each has its own IP, so they never collide."""
    def work(spec: ActorSpec) -> str:
        return run_tool(spec.job.split(":", 1)[1], spec.ip, spec.level)

    with ThreadPoolExecutor(max_workers=max(1, len(plan.tool_bots))) as pool:
        for line in pool.map(work, plan.tool_bots):
            log(line)


def _run_browser(plan: RunPlan, concurrency: int, log) -> list:
    specs = plan.browser_bots + plan.browser_humans
    if not specs:
        return []
    from benchmarks.ladder.browser import run_browser_actors
    log(f"browser: {len(specs)} actors")
    return run_browser_actors(specs, plan.seed, concurrency=concurrency)


# --------------------------------------------------------------------------
# one cell
# --------------------------------------------------------------------------


def run_cell(seed: int, config: str, small: bool, concurrency: int, no_browser: bool) -> Path:
    plan = plan_run(seed, config)
    if small:
        plan.scripted_bots = [s for s in plan.scripted_bots if s.level in ("L0", "L1", "L2")]
        plan.tool_bots = []
        plan.browser_bots = []
        plan.scripted_humans = plan.scripted_humans[:6]
        plan.browser_humans = []

    out = RESULTS / config / f"seed{seed}"
    out.mkdir(parents=True, exist_ok=True)
    workdir = out / "work"
    workdir.mkdir(exist_ok=True)
    archive = out / "collected.jsonl"
    archive.unlink(missing_ok=True)

    def log(msg: str) -> None:
        print(f"[seed{seed} {config}] {msg}", flush=True)

    with Services(workdir, archive, promoted=(config == "promoted")):
        if config == "promoted":
            time.sleep(2)  # let one refresher pass resolve the first actors
        log("scripted actors")
        _drive_scripted(plan, small)
        if plan.tool_bots:
            log("real tools (vulnscan L0-L2)")
            _run_tools(plan, log)
        browser_results = [] if no_browser else _run_browser(plan, concurrency, log)
        time.sleep(2)  # flush the last decisions to the archive
        # nginx writes access.log inside workdir; copy the final one out.
        (out / "access.log").write_bytes((workdir / "access.log").read_bytes())

    truth = plan.truth()
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    (out / "run_meta.json").write_text(json.dumps({
        "seed": seed, "config": config, "small": small, "no_browser": no_browser,
        "actors": len(truth), "bots": sum(v["class"] == "bot" for v in truth.values()),
        "humans": sum(v["class"] == "human" for v in truth.values()),
        "browser_fingerprinted": sum(r.fingerprinted for r in browser_results),
        "browser_actors": len(browser_results),
    }, indent=2), encoding="utf-8")
    log(f"done -> {out}")
    return out


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--config", choices=["default", "promoted"], default="default")
    parser.add_argument("--small", action="store_true", help="fast wiring check")
    parser.add_argument("--no-browser", action="store_true", help="skip Playwright actors")
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args(argv)
    try:
        redis.Redis.from_url(REDIS_URL).ping()
    except redis.RedisError:
        sys.exit(f"Redis not reachable at {REDIS_URL}; start one (the lab uses db 15).")
    run_cell(args.seed, args.config, args.small, args.concurrency, args.no_browser)


if __name__ == "__main__":
    main()
