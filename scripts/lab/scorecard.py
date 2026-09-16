#!/usr/bin/env python3
"""Score the lab run against exact ground truth (the IP->class map we assigned).

`microguard evaluate` labels traffic the way the real tool would in the field,
from honeypot and invite evidence. This is the complementary view: because the
lab assigned every actor its class, we can score EVERY actor, including bots
that never tripped a trap, and separate the three verdict sources the archive
now carries:

  model    — the micrograd MLP alone (max model_score over the actor's requests)
  heuristic— the rule labeler alone (did any request get heuristic_label == bot)
  blend    — what actually ships: compute_combined_score, i.e. the row `score`

For model and blend we sweep the block threshold; the heuristic is a fixed label.
Prints precision / recall / F1 for the bot class, plus the human false-positive
rate — the number that decides whether blocking is safe to turn on.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

from microguard.collect import load_collected
from microguard.scoring import BLOCK_THRESHOLD_DEFAULT

THRESHOLDS = (0.5, 0.6, 0.7, 0.8, BLOCK_THRESHOLD_DEFAULT, 0.9, 0.95)


def _metrics(tp, fp, fn, tn):
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return prec, rec, f1, fpr


def main():
    archive = sys.argv[1] if len(sys.argv) > 1 else "scripts/lab/.run/collected.jsonl"
    truth_path = sys.argv[2] if len(sys.argv) > 2 else "scripts/lab/.run/ground_truth.json"
    with open(truth_path) as fh:
        truth = json.load(fh)

    # Reduce the archive to one row-set per actor IP.
    max_model: dict[str, float] = defaultdict(lambda: -1.0)
    max_blend: dict[str, float] = defaultdict(lambda: -1.0)
    heur_bot: dict[str, bool] = defaultdict(bool)
    seen: set[str] = set()
    for row in load_collected(archive):
        ip = row.get("ip")
        if ip not in truth:
            continue  # loopback / stray; only score actors we labeled
        seen.add(ip)
        if isinstance(row.get("model_score"), (int, float)):
            max_model[ip] = max(max_model[ip], row["model_score"])
        if isinstance(row.get("score"), (int, float)):
            max_blend[ip] = max(max_blend[ip], row["score"])
        if row.get("heuristic_label") == "bot":
            heur_bot[ip] = True

    actors = sorted(seen)
    bots = [ip for ip in actors if truth[ip] == "bot"]
    humans = [ip for ip in actors if truth[ip] == "human"]
    missing = [ip for ip in truth if ip not in seen]

    print("# Lab scorecard (exact ground truth)\n")
    print(f"Actors scored: {len(actors)}  ({len(bots)} bot, {len(humans)} human)")
    if missing:
        print(f"Assigned but never scored (no session recorded): {len(missing)}")
    print()

    def confusion(predicate):
        tp = sum(predicate(ip) for ip in bots)
        fn = len(bots) - tp
        fp = sum(predicate(ip) for ip in humans)
        tn = len(humans) - fp
        return tp, fp, fn, tn

    print("## Detector comparison\n")
    print("| detector | precision | recall (bots caught) | F1 | human FP rate |")
    print("|---|---|---|---|---|")

    tp, fp, fn, tn = confusion(lambda ip: heur_bot[ip])
    p, r, f1, fpr = _metrics(tp, fp, fn, tn)
    print(f"| heuristic label | {p:.0%} | {r:.0%} ({tp}/{len(bots)}) | {f1:.2f} | {fpr:.0%} ({fp}/{len(humans)}) |")

    for label, table in (("model", max_model), ("blend", max_blend)):
        for t in THRESHOLDS:
            tp, fp, fn, tn = confusion(lambda ip, t=t, tb=table: tb[ip] > t)
            p, r, f1, fpr = _metrics(tp, fp, fn, tn)
            d = " (default)" if t == BLOCK_THRESHOLD_DEFAULT else ""
            print(f"| {label} > {t:.2f}{d} | {p:.0%} | {r:.0%} ({tp}/{len(bots)}) | {f1:.2f} | {fpr:.0%} ({fp}/{len(humans)}) |")

    # The operational question: lowest threshold that flags zero real humans.
    print("\n## Safe-to-block reading\n")
    for label, table in (("blend", max_blend), ("model", max_model)):
        safe = [t for t in THRESHOLDS if not any(table[ip] > t for ip in humans)]
        if safe:
            t = min(safe)
            caught = sum(table[ip] > t for ip in bots)
            print(f"- {label}: lowest threshold with 0 humans flagged is {t:.2f}, "
                  f"catching {caught}/{len(bots)} bots ({caught/len(bots):.0%}).")
        else:
            print(f"- {label}: every threshold flags at least one real human.")


if __name__ == "__main__":
    main()
