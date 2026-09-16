#!/usr/bin/env python3
"""Prototype for issue #19: retrain the model on the LIVE feature distribution.

The shipped model normalizes with ranges from complete-session training data,
but the live scorer scores each request as a session builds, so live vectors
collapse into a band where the model is constant. This trains the same tiny MLP
on feature vectors taken straight from a lab archive (the real live per-request
distribution), with normalization computed from that same distribution, and
writes model.json + normalization.json to an output dir.

Train on one lab run, then score a FRESH run with --model <out>/model.json.
This never touches data/model.json.
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from microguard.collect import load_collected
from microguard.model import BotDetector

MAX_ROWS_PER_ACTOR = 20  # keep a heavy scanner (thousands of rows) from dominating


def main():
    archive = sys.argv[1]
    truth_path = sys.argv[2]
    out_dir = Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(truth_path) as fh:
        truth = json.load(fh)

    by_actor: dict[str, list[list[float]]] = defaultdict(list)
    for row in load_collected(archive):
        ip = row.get("ip")
        if ip in truth:
            by_actor[ip].append(row["features"])

    rng = random.Random(0)
    feats: list[list[float]] = []
    labels: list[float] = []
    for ip, vecs in by_actor.items():
        chosen = vecs if len(vecs) <= MAX_ROWS_PER_ACTOR else rng.sample(vecs, MAX_ROWS_PER_ACTOR)
        label = 1.0 if truth[ip] == "bot" else 0.0
        feats.extend(chosen)
        labels.extend([label] * len(chosen))

    n = len(feats)
    n_bot = int(sum(labels))
    print(f"training rows: {n} ({n_bot} bot, {n - n_bot} human) from {len(by_actor)} actors")

    # Normalization from the live distribution, the whole point of the fix.
    cols = list(zip(*feats))
    mins = [min(c) for c in cols]
    maxs = [max(c) for c in cols]
    norm = [
        [(v - mn) / (mx - mn) if mx > mn else 0.5 for v, mn, mx in zip(row, mins, maxs)]
        for row in feats
    ]

    det = BotDetector()
    det.norm_mins, det.norm_maxs = mins, maxs
    det.train(norm, labels, epochs=200, batch_size=32, learning_rate=0.05, verbose=False)
    det.save(str(out_dir / "model.json"))
    with open(out_dir / "normalization.json", "w", encoding="utf-8") as fh:
        json.dump({"mins": mins, "maxs": maxs}, fh, indent=2)
    print(f"wrote {out_dir}/model.json and normalization.json")


if __name__ == "__main__":
    main()
