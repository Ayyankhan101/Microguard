"""Build a realistic training set from REAL human and REAL bot traffic.

The shipped model's human class comes from one file (`harvard_training_data.json`),
so columns constant within it identify the *source*, not the *class* — the leak
`docs/explanation-training-data.md` describes. The fix it names is "real human
sessions extracted by the same `extract_features` as the bot class". That data
exists: the Zanbil e-commerce log (a real production nginx log) contains real
human shoppers AND real bots (crawlers, scanners) from the **same site**, and
this repo already holds real forensic attacks (organization-x).

This builder combines them:

- **human**  — Zanbil `human_proxy` actors (browser UA + checkout + assets).
- **bot**    — Zanbil crawlers/probes (same site, so the model cannot separate
               the classes by data source) PLUS organization-x forensic attacks
               (for attack-shape coverage).

Every row carries its provenance and the Zanbil **day** it came from, so the
trainer can hold out whole days for an honest generalization number rather than
random-splitting correlated sessions.

Inputs (run `python -m benchmarks.public.zanbil split label` first):
    benchmarks/data/zanbil/days/<YYYY-MM-DD>.log     — per-day access logs
    benchmarks/data/zanbil/labels/<YYYY-MM-DD>.json  — actor labels
    data/zenodo_data/organization-x/                 — real attacks (in repo)

Honesty: the human labels are a behavioural PROXY, not verified ground truth,
and Zanbil is one Iranian e-commerce site in 2019 — realistic for e-commerce
browsing, not internet-universal. See the module's write-up in docs/results/.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from collections import defaultdict

from ..features import extract_features, group_into_sessions
from ..parser import parse_nginx_line
from .build_real_dataset import (
    group_into_actor_sessions,
    load_all_organization_x_entries,
)
from .groundtruth import label_sessions_by_groundtruth, load_rules

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(_HERE))
DATA_DIR = os.path.join(ROOT, 'data')
ZANBIL_DIR = os.path.join(ROOT, 'benchmarks', 'data', 'zanbil')
ZANBIL_DAYS = os.path.join(ZANBIL_DIR, 'days')
ZANBIL_LABELS = os.path.join(ZANBIL_DIR, 'labels')
ORGX_RULES_PATH = os.path.join(
    DATA_DIR, 'zenodo_data', 'organization-x', 'ground-truth', 'organization-x.yaml'
)

HUMAN_LABELS = {'human_proxy'}
BOT_LABELS = {'verified_crawler', 'unverified_crawler', 'probe_bot'}
MIN_REQUESTS = 3          # a session needs a few requests to have a shape
MAX_SESSIONS_PER_ACTOR = 5  # keep one heavy shopper/crawler from dominating


def _actor_hash(*parts: str) -> str:
    """A stable, non-reversible id for one actor, so the committed dataset
    carries no raw visitor IPs. Same actor -> same id, which is all the
    group-level train/test split needs."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def _zanbil_days() -> list[str]:
    if not os.path.isdir(ZANBIL_LABELS):
        raise SystemExit(
            f"no Zanbil labels at {ZANBIL_LABELS}. Run:\n"
            "  python -m benchmarks.public.zanbil split\n"
            "  python -m benchmarks.public.zanbil label"
        )
    return sorted(
        f[:-5] for f in os.listdir(ZANBIL_LABELS)
        if f.endswith('.json') and f != 'summary.json'
    )


def _zanbil_rows(days: list[str], rng: random.Random) -> list[dict]:
    """One row per Zanbil session of a labeled actor, on the given days."""
    rows: list[dict] = []
    for day in days:
        with open(os.path.join(ZANBIL_LABELS, f'{day}.json'), encoding='utf-8') as fh:
            labels = json.load(fh)
        keep = {ip: info['label'] for ip, info in labels.items()
                if info['label'] in HUMAN_LABELS or info['label'] in BOT_LABELS}
        if not keep:
            continue
        # Filter to labeled actors while parsing, so one day fits in memory.
        by_ip: dict[str, list] = defaultdict(list)
        with open(os.path.join(ZANBIL_DAYS, f'{day}.log'), encoding='utf-8') as fh:
            for line in fh:
                entry = parse_nginx_line(line.rstrip('\n'))
                if entry is not None and entry.ip in keep:
                    by_ip[entry.ip].append(entry)
        for ip, entries in by_ip.items():
            label = keep[ip]
            is_bot = label in BOT_LABELS
            sessions = group_into_sessions(entries, timeout_minutes=30)
            sessions = [s for s in sessions if s.request_count >= MIN_REQUESTS]
            if len(sessions) > MAX_SESSIONS_PER_ACTOR:
                sessions = rng.sample(sessions, MAX_SESSIONS_PER_ACTOR)
            for session in sessions:
                rows.append({
                    'features': extract_features(session),
                    'label': 1.0 if is_bot else 0.0,
                    'group_id': f'zanbil_{day}_{_actor_hash(day, ip)}',
                    # Day is part of the provenance: each Zanbil day is a
                    # distinct real collection window, so the human class is
                    # not a single homogeneous source (a genuine fix, not a
                    # label — the constant-column and separability guards above
                    # already pass on this data).
                    'provenance': f'zanbil_{label}_{day}',
                    'day': day,
                })
    return rows


def _orgx_bot_rows() -> list[dict]:
    """organization-x forensic attacks, keyed by (ip, user_agent) like the
    existing builder. Bot-side only — its IPs are anonymized to ~2 values."""
    from ..labeler import label_session
    rules = load_rules(ORGX_RULES_PATH)
    sessions = group_into_actor_sessions(load_all_organization_x_entries())
    rows: list[dict] = []
    for session, gt_label, category in label_sessions_by_groundtruth(sessions, rules):
        if session.request_count < MIN_REQUESTS:
            continue
        if gt_label == 'bot':
            prov = f'orgx_ground_truth:{category}'
        elif label_session(session)[0] == 'bot':
            prov = 'orgx_heuristic'
        else:
            continue  # not trusted as a human example
        rows.append({
            'features': extract_features(session),
            'label': 1.0,
            'group_id': f'orgx_{_actor_hash(session.ip, session.user_agent)}',
            'provenance': prov,
            'day': 'orgx',
        })
    return rows


def build_dataset(seed: int = 42, include_orgx: bool = True) -> dict:
    rng = random.Random(seed)
    days = _zanbil_days()
    rows = _zanbil_rows(days, rng)
    if include_orgx:
        rows += _orgx_bot_rows()
    rng.shuffle(rows)

    source_counts: dict[str, int] = defaultdict(int)
    day_counts: dict[str, dict[str, int]] = defaultdict(lambda: {'human': 0, 'bot': 0})
    for r in rows:
        source_counts[r['provenance'].split(':')[0]] += 1
        day_counts[r['day']]['bot' if r['label'] > 0.5 else 'human'] += 1

    n_bot = sum(1 for r in rows if r['label'] > 0.5)
    return {
        'features': [r['features'] for r in rows],
        'labels': [r['label'] for r in rows],
        'group_ids': [r['group_id'] for r in rows],
        'provenance': [r['provenance'] for r in rows],
        'days': [r['day'] for r in rows],
        'n_samples': len(rows),
        'n_features': len(rows[0]['features']) if rows else 0,
        'n_human': len(rows) - n_bot,
        'n_bot': n_bot,
        'source_counts': dict(source_counts),
        'day_counts': {d: c for d, c in sorted(day_counts.items())},
        'zanbil_days': days,
    }


def main() -> None:
    dataset = build_dataset()
    out = os.path.join(DATA_DIR, 'realistic_training_data.json')
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump(dataset, fh, indent=2)
    print(f"saved {out}")
    print(f"  samples: {dataset['n_samples']} "
          f"(human {dataset['n_human']}, bot {dataset['n_bot']})")
    print(f"  sources: {dataset['source_counts']}")
    by_day = {d: f"{c['human']}h/{c['bot']}b" for d, c in dataset['day_counts'].items()}
    print(f"  by day: {by_day}")


if __name__ == '__main__':
    main()
