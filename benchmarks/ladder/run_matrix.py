"""Run every ladder cell the report needs, in one process.

`default` config first (the core result), then `promoted`, five seeds each.
Skips a cell whose run_meta.json already exists, so an interrupted matrix
resumes where it stopped. One cell at a time — the check server and nginx bind
fixed ports.

    python -m benchmarks.ladder.run_matrix                # all of it
    python -m benchmarks.ladder.run_matrix --configs default --seeds 1 2 3 4 5
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import redis

from benchmarks.ladder.run import REDIS_URL, RESULTS, run_cell


def _done(config: str, seed: int) -> bool:
    meta = RESULTS / config / f"seed{seed}" / "run_meta.json"
    if not meta.exists():
        return False
    payload = json.loads(meta.read_text(encoding="utf-8"))
    return not payload.get("small") and not payload.get("no_browser")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configs", nargs="+", default=["default", "promoted"])
    parser.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3, 4, 5])
    parser.add_argument("--concurrency", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        redis.Redis.from_url(REDIS_URL).ping()
    except redis.RedisError:
        sys.exit(f"Redis not reachable at {REDIS_URL}")

    started = time.time()
    for config in args.configs:
        for seed in args.seeds:
            if _done(config, seed):
                print(f"[matrix] skip {config}/seed{seed} (already complete)", flush=True)
                continue
            t = time.time()
            print(f"[matrix] === {config}/seed{seed} ===", flush=True)
            run_cell(seed, config, small=False, concurrency=args.concurrency, no_browser=False)
            print(f"[matrix] {config}/seed{seed} took {time.time() - t:.0f}s", flush=True)
    print(f"[matrix] all cells done in {(time.time() - started) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
