"""Build the committed Zanbil fixture that tests/test_dataset_integrity.py runs
the leakage guards against.

Why a fixture derived from real traffic rather than synthetic lines: the guards
assert that no feature column separates the classes and that none is constant
within one class. Invented traffic fails that by construction -- every made-up
human gets a browser user agent and every made-up bot a crawler one, so
`ua_category` separates perfectly and the guard fires on the fixture rather than
on a real defect. Sampling real actors keeps the overlap the guards depend on:
in the full dataset `ua_category` spans 0..2 in BOTH classes, because
`probe_bot` and `unverified_crawler` routinely present browser user agents.

What is preserved: paths, timestamps, user agents, status codes, byte counts and
referers, so feature extraction sees real shapes.

What is removed: every client IP is rewritten to a documentation range
(RFC 5737) with a stable per-day mapping, so an actor still groups into the same
sessions and no real visitor address is committed.

Run from a checkout that has the real Zanbil data present:

    python -m benchmarks.public.zanbil split
    python -m benchmarks.public.zanbil label
    python scripts/build_zanbil_test_fixture.py

The raw Zanbil logs are gitignored (`benchmarks/data/`), which is why this
cannot run in CI and why its output is committed instead.
"""

from __future__ import annotations

import json
import os
import random
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DAYS = os.path.join(ROOT, 'benchmarks', 'data', 'zanbil', 'days')
SRC_LABELS = os.path.join(ROOT, 'benchmarks', 'data', 'zanbil', 'labels')
OUT = os.path.join(ROOT, 'tests', 'fixtures', 'zanbil')

# Three days, not one: `provenance` is f'zanbil_{label}_{day}', and the
# human-class guard requires more than one human provenance value.
DAYS = ['2019-01-22', '2019-01-23', '2019-01-24']

HUMAN_LABELS = {'human_proxy'}
BOT_LABELS = {'verified_crawler', 'unverified_crawler', 'probe_bot'}

ACTORS_PER_CLASS_PER_DAY = 22
MAX_LINES_PER_ACTOR = 40   # enough for several sessions at the 30-minute timeout
# Breadth over depth: the guards care whether a column VARIES within a class,
# so many actors with short histories beat a few with long ones. At 9 actors
# per class no sampled human happened to browse between 02:00 and 06:00, which
# made night_ratio constant across the human class and tripped the guard on
# the fixture rather than on a defect.
SEED = 20260919

# RFC 5737 documentation ranges, one per class so a failure is easy to read.
HUMAN_NET = '198.51.100.'
BOT_NET = '203.0.113.'


def _pick(labels: dict, wanted: set[str], rng: random.Random, n: int) -> list[str]:
    """Actors carrying one of `wanted`, sampled deterministically.

    Sorted before sampling so the choice does not depend on dict iteration
    order, and sampled rather than taking the head so the fixture is not all
    heavy actors.
    """
    candidates = sorted(ip for ip, info in labels.items() if info['label'] in wanted)
    return rng.sample(candidates, min(n, len(candidates)))


def build() -> None:
    rng = random.Random(SEED)
    os.makedirs(os.path.join(OUT, 'days'), exist_ok=True)
    os.makedirs(os.path.join(OUT, 'labels'), exist_ok=True)

    for day in DAYS:
        with open(os.path.join(SRC_LABELS, f'{day}.json'), encoding='utf-8') as fh:
            labels = json.load(fh)

        humans = _pick(labels, HUMAN_LABELS, rng, ACTORS_PER_CLASS_PER_DAY)
        bots = _pick(labels, BOT_LABELS, rng, ACTORS_PER_CLASS_PER_DAY)

        rewrite = {}
        for i, ip in enumerate(humans):
            rewrite[ip] = f'{HUMAN_NET}{i + 1}'
        for i, ip in enumerate(bots):
            rewrite[ip] = f'{BOT_NET}{i + 1}'

        kept: dict[str, list[str]] = defaultdict(list)
        with open(os.path.join(SRC_DAYS, f'{day}.log'), encoding='utf-8') as fh:
            for line in fh:
                ip, _, rest = line.partition(' ')
                if ip in rewrite and len(kept[ip]) < MAX_LINES_PER_ACTOR:
                    kept[ip].append(f'{rewrite[ip]} {rest}')

        out_lines = [ln for ip in rewrite for ln in kept.get(ip, [])]
        with open(os.path.join(OUT, 'days', f'{day}.log'), 'w', encoding='utf-8') as fh:
            fh.writelines(out_lines)

        out_labels = {
            rewrite[ip]: {**labels[ip], 'requests': len(kept.get(ip, []))}
            for ip in rewrite
        }
        with open(os.path.join(OUT, 'labels', f'{day}.json'), 'w', encoding='utf-8') as fh:
            json.dump(out_labels, fh, indent=2, sort_keys=True)

        n_h = sum(1 for ip in humans if kept.get(ip))
        n_b = sum(1 for ip in bots if kept.get(ip))
        print(f'{day}: {len(out_lines):5} lines, {n_h} human actors, {n_b} bot actors')


if __name__ == '__main__':
    build()
