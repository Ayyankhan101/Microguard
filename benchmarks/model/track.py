"""Suite D: does the micrograd model catch bots the rules miss, cleanly?

The shipped model is a near-constant on the live path (issue #19). This suite
retrains the same tiny MLP on the live per-request feature distribution, and
lines it up against sklearn baselines and against the rules it is supposed to
add to. Train and test never share a run, and L3-L5 are never in training, so a
number here is generalization, not memorization (PREREGISTRATION.md, Suite D).

    python -m benchmarks.model.track

Leakage note: this reads only the ladder archives (exact ground truth). The
Zanbil/Harvard timing data that trained the shipped human class is never used
here, so retraining cannot be graded on data it also learned from.
"""

from __future__ import annotations

import json
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from benchmarks.metrics import Rate, average_precision, bootstrap_interval, roc_auc
from benchmarks.provenance import stamp
from microguard.features import FEATURE_NAMES
from microguard.model import BotDetector

ROOT = Path(__file__).resolve().parents[2]
LADDER = ROOT / "benchmarks" / "results" / "ladder"
OUT = ROOT / "benchmarks" / "results" / "model_track.json"

TRAIN_SEEDS = (1, 2)
TRAIN_LEVELS = frozenset({"L0", "L1", "L2"})
MAX_ROWS_PER_ACTOR = 20
UA_FEATURES = ("ua_category", "has_accept_language", "header_consistency_score")


@dataclass
class Row:
    ip: str
    features: list[float]
    label: float  # 1.0 bot, 0.0 human
    level: str


def _read_runs(config: str, seeds):
    for seed in seeds:
        seed_dir = LADDER / config / f"seed{seed}"
        gt = seed_dir / "ground_truth.json"
        arch = seed_dir / "collected.jsonl"
        if not gt.exists() or not arch.exists():
            continue
        truth = json.loads(gt.read_text(encoding="utf-8"))
        by_ip: dict[str, list[list[float]]] = defaultdict(list)
        for line in arch.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if isinstance(row.get("features"), list) and row["ip"] in truth:
                by_ip[row["ip"]].append([float(f) for f in row["features"]])
        yield truth, by_ip


def gather_rows(config: str, seeds, levels=None, per_actor=MAX_ROWS_PER_ACTOR) -> list[Row]:
    rng = random.Random(0)
    rows: list[Row] = []
    for truth, by_ip in _read_runs(config, seeds):
        for ip, vecs in by_ip.items():
            info = truth[ip]
            if levels is not None and info["class"] == "bot" and info["level"] not in levels:
                continue
            if levels is not None and info["class"] == "human":
                pass  # humans always kept
            chosen = vecs if len(vecs) <= per_actor else rng.sample(vecs, per_actor)
            label = 1.0 if info["class"] == "bot" else 0.0
            rows.extend(Row(ip, v, label, info.get("level", "human")) for v in chosen)
    return rows


# --------------------------------------------------------------------------
# models: each exposes predict(list[float]) -> float
# --------------------------------------------------------------------------




def _apply(mins, maxs, feats):
    return [(v - mn) / (mx - mn) if mx > mn else 0.5 for v, mn, mx in zip(feats, mins, maxs)]


def train_micrograd(rows: list[Row], drop: tuple[str, ...] = ()) -> callable:
    keep = [i for i, name in enumerate(FEATURE_NAMES) if name not in drop]
    feats = [[r.features[i] for i in keep] for r in rows]
    labels = [r.label for r in rows]
    mins = [min(c) for c in zip(*feats)]
    maxs = [max(c) for c in zip(*feats)]
    norm = [_apply(mins, maxs, f) for f in feats]

    det = BotDetector()
    # The architecture is fixed at 19 inputs; feed the dropped columns as a
    # constant 0.5 (the neutral normalized value) rather than reshaping it.
    def expand(vec_keep):
        full = [0.5] * len(FEATURE_NAMES)
        for j, i in enumerate(keep):
            full[i] = vec_keep[j]
        return full

    det.norm_mins = [0.0] * len(FEATURE_NAMES)
    det.norm_maxs = [1.0] * len(FEATURE_NAMES)  # inputs are already normalized

    def reset():
        det.__init__()
        det.norm_mins = [0.0] * len(FEATURE_NAMES)
        det.norm_maxs = [1.0] * len(FEATURE_NAMES)

    det.train_until_it_learns(
        [expand(f) for f in norm], labels, reset=reset,
        epochs=200, batch_size=32, learning_rate=0.05, verbose=False,
    )

    def predict(raw: list[float]) -> float:
        kept = _apply(mins, maxs, [raw[i] for i in keep])
        return det.predict(expand(kept))

    return predict


def train_sklearn(rows: list[Row], kind: str, drop: tuple[str, ...] = ()) -> callable:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    keep = [i for i, name in enumerate(FEATURE_NAMES) if name not in drop]
    feats = [[r.features[i] for i in keep] for r in rows]
    labels = [r.label for r in rows]
    mins = [min(c) for c in zip(*feats)]
    maxs = [max(c) for c in zip(*feats)]
    x = [_apply(mins, maxs, f) for f in feats]
    if kind == "logreg":
        clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    else:
        clf = RandomForestClassifier(n_estimators=200, random_state=0)
    clf.fit(x, labels)
    idx = list(clf.classes_).index(1.0)

    def predict(raw: list[float]) -> float:
        return float(clf.predict_proba([_apply(mins, maxs, [raw[i] for i in keep])])[0][idx])

    return predict


# --------------------------------------------------------------------------
# evaluation
# --------------------------------------------------------------------------


@dataclass
class ActorEval:
    ip: str
    label: float
    level: str
    score: float


def _actor_scores(predict, test_rows: list[Row]) -> list[ActorEval]:
    by_ip: dict[str, list[float]] = defaultdict(list)
    meta: dict[str, Row] = {}
    for r in test_rows:
        by_ip[r.ip].append(predict(r.features))
        meta[r.ip] = r
    return [ActorEval(ip, meta[ip].label, meta[ip].level, max(scores))
            for ip, scores in by_ip.items()]


def _leakage_guard(rows: list[Row]) -> list[dict]:
    """Any single feature that separates the train classes perfectly."""
    offenders = []
    labels = [r.label for r in rows]
    for i, name in enumerate(FEATURE_NAMES):
        col = [r.features[i] for r in rows]
        bot = [v for v, lbl in zip(col, labels) if lbl > 0.5]
        human = [v for v, lbl in zip(col, labels) if lbl <= 0.5]
        if not bot or not human:
            continue
        if min(bot) > max(human) or min(human) > max(bot):
            offenders.append({"feature": name, "bot_range": [min(bot), max(bot)],
                              "human_range": [min(human), max(human)]})
    return offenders


def _archived_heuristic(config: str, seeds, want_ip: str) -> bool:
    for seed in seeds:
        arch = LADDER / config / f"seed{seed}" / "collected.jsonl"
        if not arch.exists():
            continue
        for line in arch.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("ip") == want_ip and row.get("heuristic_label") == "bot":
                return True
    return False


def _metrics_block(evals: list[ActorEval]) -> dict:
    scores = [e.score for e in evals]
    labels = [e.label > 0.5 for e in evals]
    ap = average_precision(scores, labels)
    auc = roc_auc(scores, labels)
    recall_at_half = Rate(
        sum(e.score > 0.5 for e in evals if e.label > 0.5),
        sum(1 for e in evals if e.label > 0.5),
    )
    fpr_at_half = Rate(
        sum(e.score > 0.5 for e in evals if e.label <= 0.5),
        sum(1 for e in evals if e.label <= 0.5),
    )
    return {
        "auc": auc,
        "auc_ci": bootstrap_interval(roc_auc, scores, labels, n_boot=1000),
        "ap": ap,
        "ap_ci": bootstrap_interval(average_precision, scores, labels, n_boot=1000),
        "recall_at_0.5": recall_at_half.as_dict(),
        "fpr_at_0.5": fpr_at_half.as_dict(),
    }


def run() -> dict:
    train_rows = gather_rows("default", TRAIN_SEEDS, levels=TRAIN_LEVELS)
    test_seeds = tuple(s for s in _available_seeds("default") if s not in TRAIN_SEEDS)
    test_rows = gather_rows("default", test_seeds)
    if not train_rows or not test_rows:
        return {"error": "need default seeds 1-2 (train) and >=1 more (test)",
                "train_rows": len(train_rows), "test_rows": len(test_rows)}

    heur_flags = {e.ip: _archived_heuristic("default", test_seeds, e.ip)
                  for e in _actor_scores(lambda f: 0.0, test_rows)}

    models = {
        "micrograd_retrained": train_micrograd(train_rows),
        "sklearn_logreg": train_sklearn(train_rows, "logreg"),
        "sklearn_rf": train_sklearn(train_rows, "rf"),
        "micrograd_no_ua": train_micrograd(train_rows, drop=UA_FEATURES),
    }
    result: dict = {
        "train": {"seeds": list(TRAIN_SEEDS), "levels": sorted(TRAIN_LEVELS),
                  "rows": len(train_rows), "bots": int(sum(r.label for r in train_rows))},
        "test": {"seeds": list(test_seeds), "rows": len(test_rows)},
        "leakage": _leakage_guard(train_rows),
        "models": {},
    }
    for name, predict in models.items():
        evals = _actor_scores(predict, test_rows)
        block = _metrics_block(evals)
        # Marginal catches: bots this model flags at 0.5 that the rules missed,
        # and humans it newly flags. Per PREREGISTRATION rule 4.
        marginal = [e for e in evals if e.label > 0.5 and e.score > 0.5 and not heur_flags.get(e.ip)]
        added_fp = [e for e in evals if e.label <= 0.5 and e.score > 0.5 and not heur_flags.get(e.ip)]
        block["marginal_catches"] = len(marginal)
        block["marginal_by_level"] = _count_levels(marginal)
        block["added_human_fp"] = len(added_fp)
        block["earns_place"] = (len(marginal) >= len(test_seeds)) and (len(added_fp) == 0)
        result["models"][name] = block

    # The shipped model, for contrast: its actor scores on the same test set.
    shipped = BotDetector(str(ROOT / "data" / "model.json"))
    result["models"]["shipped_baseline"] = _metrics_block(
        _actor_scores(shipped.predict, test_rows)
    )
    return result


def _count_levels(evals: list[ActorEval]) -> dict:
    out: dict[str, int] = defaultdict(int)
    for e in evals:
        out[e.level] += 1
    return dict(out)


def _available_seeds(config: str) -> list[int]:
    seeds = []
    for seed_dir in (LADDER / config).glob("seed*"):
        meta = seed_dir / "run_meta.json"
        if meta.exists() and not json.loads(meta.read_text(encoding="utf-8")).get("small"):
            seeds.append(int(seed_dir.name[4:]))
    return sorted(seeds)


def main() -> None:
    result = run()
    result["provenance"] = stamp()
    OUT.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    if "error" in result:
        print(result["error"])
        return
    for name, block in result["models"].items():
        auc = block.get("auc")
        mc = block.get("marginal_catches", "-")
        print(f"{name:22} auc={auc if auc is None else round(auc, 3)} "
              f"marginal_catches={mc} added_fp={block.get('added_human_fp', '-')}")
    print(f"leakage offenders: {[o['feature'] for o in result['leakage']]}")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
