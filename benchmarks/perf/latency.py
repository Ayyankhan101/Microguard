"""Suite C: is the check path fast and small enough to run in front of a site?

Measures the real `microguard serve` /check endpoint under load, the memory a
populated Redis costs, offline scan throughput, and per-prediction time
(micrograd vs sklearn). No pass/fail; the one reference point is the deploy
how-to's target of p99 under 20 ms for /check.

    python -m benchmarks.perf.latency

Records the hardware it ran on, because that is the only thing that makes the
numbers comparable to anything.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import subprocess
import time
from pathlib import Path

import httpx
import redis

from benchmarks.metrics import quantile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "benchmarks" / "results" / "perf.json"
REDIS_URL = os.environ.get("LADDER_REDIS_URL", "redis://localhost:6379/15")
SERVE_PORT = 8465
PROBE_IPS = [f"198.51.{a}.{b}" for a in range(20) for b in range(1, 251)]  # 5000 distinct


def _hardware() -> dict:
    info = {"platform": platform.platform(), "python": platform.python_version(),
            "processor": platform.processor() or platform.machine()}
    try:
        info["cpu"] = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
            text=True, timeout=5, check=False).stdout.strip()
        info["mem_gb"] = round(int(subprocess.run(
            ["sysctl", "-n", "hw.memsize"], capture_output=True, text=True,
            timeout=5, check=False).stdout.strip()) / 1e9, 1)
    except Exception:  # noqa: BLE001,S110 - hardware fields are best-effort
        pass
    return info


class Serve:
    def __init__(self, workdir: Path):
        self.workdir = workdir

    def __enter__(self):
        redis.Redis.from_url(REDIS_URL).flushdb()
        self.log = (self.workdir / "serve.log").open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            ["microguard", "serve", "--host", "127.0.0.1", "--port", str(SERVE_PORT),
             "--redis-url", REDIS_URL, "--block-threshold", "1.0"],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        for _ in range(50):
            try:
                httpx.get(f"http://127.0.0.1:{SERVE_PORT}/check",
                          headers={"X-Real-IP": "9.9.9.9", "X-Original-URI": "/"}, timeout=1)
                return self
            except httpx.HTTPError:
                time.sleep(0.2)
        raise RuntimeError("serve did not come up")

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.log.close()


async def _load(concurrency: int, total: int) -> list[float]:
    """Fire `total` /check requests at `concurrency`, one rotating IP each."""
    url = f"http://127.0.0.1:{SERVE_PORT}/check"
    latencies: list[float] = []
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=10) as client:
        async def one(i: int) -> None:
            ip = PROBE_IPS[i % len(PROBE_IPS)]
            headers = {"X-Real-IP": ip, "X-Original-URI": "/catalog/p1.html",
                       "User-Agent": "Mozilla/5.0", "X-Original-Method": "GET"}
            async with sem:
                t = time.perf_counter()
                try:
                    await client.get(url, headers=headers)
                    latencies.append((time.perf_counter() - t) * 1000)
                except httpx.HTTPError:
                    pass
        await asyncio.gather(*(one(i) for i in range(total)))
    return latencies


def latency_suite(workdir: Path) -> dict:
    result: dict = {"check_latency_ms": {}}
    with Serve(workdir):
        for concurrency in (1, 10, 50):
            # Warm up, then measure.
            asyncio.run(_load(concurrency, 500))
            t0 = time.perf_counter()
            lat = asyncio.run(_load(concurrency, 5000))
            wall = time.perf_counter() - t0
            result["check_latency_ms"][f"c{concurrency}"] = {
                "n": len(lat),
                "p50": round(quantile(lat, 0.5), 3),
                "p95": round(quantile(lat, 0.95), 3),
                "p99": round(quantile(lat, 0.99), 3),
                "req_per_s": round(len(lat) / wall, 1),
            }
        result["redis_memory"] = _redis_memory()
    return result


def _redis_memory() -> dict:
    """used_memory after N distinct actors have a live session."""
    client = redis.Redis.from_url(REDIS_URL)
    before = int(client.info("memory")["used_memory"])
    url = f"http://127.0.0.1:{SERVE_PORT}/check"
    n = 10000
    with httpx.Client(timeout=10) as c:
        for i in range(n):
            ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            c.get(url, headers={"X-Real-IP": ip, "X-Original-URI": "/", "User-Agent": "Mozilla/5.0"})
    after = int(client.info("memory")["used_memory"])
    return {"actors": n, "used_memory_before": before, "used_memory_after": after,
            "bytes_per_actor": round((after - before) / n, 1)}


def _inference() -> dict:
    import random

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    from microguard.model import BotDetector

    rng = random.Random(0)
    vectors = [[rng.random() for _ in range(19)] for _ in range(2000)]
    det = BotDetector(str(ROOT / "data" / "model.json"))

    t = time.perf_counter()
    for v in vectors:
        det.predict(v)
    micro = (time.perf_counter() - t) / len(vectors) * 1e6  # us

    labels = [rng.random() < 0.5 for _ in vectors]
    out = {"micrograd_us_per_predict": round(micro, 2)}
    for name, clf in (("logreg", LogisticRegression(max_iter=1000)),
                      ("rf", RandomForestClassifier(n_estimators=200, random_state=0))):
        clf.fit(vectors, labels)
        t = time.perf_counter()
        for v in vectors:
            clf.predict_proba([v])
        out[f"{name}_us_per_predict"] = round((time.perf_counter() - t) / len(vectors) * 1e6, 2)
    return out


def scan_throughput(zanbil_day: Path, limit: int = 1_000_000) -> dict | None:
    """Lines/s for `microguard scan` on a Zanbil slice."""
    if not zanbil_day.exists():
        return None
    import contextlib
    import io

    from microguard.cli import scan_logfile
    slice_path = OUT.parent / "scan_slice.log"
    with zanbil_day.open(encoding="utf-8") as src, slice_path.open("w", encoding="utf-8") as dst:
        for i, line in enumerate(src):
            if i >= limit:
                break
            dst.write(line)
    lines = min(limit, sum(1 for _ in slice_path.open(encoding="utf-8")))
    t = time.perf_counter()
    with contextlib.redirect_stderr(io.StringIO()):
        res = scan_logfile(str(slice_path), fmt="nginx")
    elapsed = time.perf_counter() - t
    slice_path.unlink(missing_ok=True)
    return {"lines": lines, "seconds": round(elapsed, 2),
            "lines_per_s": round(lines / elapsed), "sessions": res["total_sessions"]}


def main() -> None:
    workdir = OUT.parent / "perf_work"
    workdir.mkdir(parents=True, exist_ok=True)
    result = {"hardware": _hardware()}
    result.update(latency_suite(workdir))
    result["inference"] = _inference()
    zanbil = ROOT / "benchmarks" / "data" / "zanbil" / "days" / "2019-01-23.log"
    scan = scan_throughput(zanbil)
    if scan is not None:
        result["scan_throughput"] = scan
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
