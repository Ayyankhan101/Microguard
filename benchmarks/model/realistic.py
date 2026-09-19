"""Train the micrograd model on REAL human+bot traffic, evaluate held out.

Trains on Zanbil days 22-24 (real human shoppers + real crawlers) plus the
organization-x forensic attacks, and evaluates on Zanbil days 25-26 — real
humans and real bots the model never saw. Reports the retrained micrograd model,
sklearn reference models, and the shipped model side by side, so the question
"does training on real data beat what ships?" gets a real answer, not an
assertion.

    python -m microguard.training.build_realistic_dataset   # first
    python -m benchmarks.model.realistic

Honesty: the human labels are a behavioural proxy (browser UA + checkout +
assets), and the data is one Iranian e-commerce site in 2019 — realistic for
e-commerce browsing, not internet-universal. See docs/results/.
"""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.metrics import Rate, average_precision, bootstrap_interval, roc_auc
from benchmarks.provenance import stamp
from microguard.model import BotDetector

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "realistic_training_data.json"
OUT = ROOT / "benchmarks" / "results" / "realistic_model.json"
TRAIN_DAYS = {"2019-01-22", "2019-01-23", "2019-01-24", "orgx"}
TEST_DAYS = {"2019-01-25", "2019-01-26"}


def _split(data: dict):
    train, test = [], []
    for feat, label, day in zip(data["features"], data["labels"], data["days"]):
        row = ([float(x) for x in feat], float(label))
        (train if day in TRAIN_DAYS else test if day in TEST_DAYS else train).append(row)
    return train, test


def _minmax(rows):
    cols = list(zip(*(f for f, _ in rows)))
    return [min(c) for c in cols], [max(c) for c in cols]


def _apply(mins, maxs, f):
    return [(v - mn) / (mx - mn) if mx > mn else 0.5 for v, mn, mx in zip(f, mins, maxs)]


def _train_micrograd(train, mins, maxs, drop_idx=()):
    feats = [_apply(mins, maxs, f) for f, _ in train]
    for f in feats:
        for i in drop_idx:
            f[i] = 0.5
    labels = [lbl for _, lbl in train]
    det = BotDetector()
    det.norm_mins = [0.0] * len(mins)
    det.norm_maxs = [1.0] * len(mins)  # already normalized

    def reset():
        det.__init__()
        det.norm_mins = [0.0] * len(mins)
        det.norm_maxs = [1.0] * len(mins)

    det.train_until_it_learns(feats, labels, reset=reset, epochs=200,
                              batch_size=32, learning_rate=0.05, verbose=False)

    def predict(raw):
        f = _apply(mins, maxs, raw)
        for i in drop_idx:
            f[i] = 0.5
        return det.predict(f)
    return predict


def _train_sklearn(train, mins, maxs, kind):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    x = [_apply(mins, maxs, f) for f, _ in train]
    y = [lbl for _, lbl in train]
    clf = (LogisticRegression(max_iter=1000, class_weight="balanced") if kind == "logreg"
           else RandomForestClassifier(n_estimators=200, random_state=0))
    clf.fit(x, y)
    idx = list(clf.classes_).index(1.0)
    return lambda raw: float(clf.predict_proba([_apply(mins, maxs, raw)])[0][idx])


def _evaluate(predict, test) -> dict:
    scores = [predict(f) for f, _ in test]
    labels = [lbl > 0.5 for _, lbl in test]
    # recall at the lowest human-FP: the highest threshold with 0 humans flagged,
    # and the bot recall there. Sweep the observed scores.
    best = {"threshold": 1.0, "recall": Rate(0, sum(labels))}
    for t in sorted(set(scores)):
        fp = sum(1 for s, lbl in zip(scores, labels) if not lbl and s > t)
        if fp == 0:
            tp = sum(1 for s, lbl in zip(scores, labels) if lbl and s > t)
            r = Rate(tp, sum(labels))
            if r.value and (best["recall"].value is None or r.value > best["recall"].value):
                best = {"threshold": t, "recall": r}
    return {
        "auc": roc_auc(scores, labels),
        "auc_ci": bootstrap_interval(roc_auc, scores, labels, n_boot=1000),
        "ap": average_precision(scores, labels),
        "recall_at_0_human_fp": best["recall"].as_dict(),
        "recall_at_0_fp_threshold": round(best["threshold"], 3),
        "n_test_human": sum(1 for lbl in labels if not lbl),
        "n_test_bot": sum(labels),
    }


UA_FEATURES = ("ua_category", "has_accept_language", "header_consistency_score")


def run() -> dict:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    from microguard.features import FEATURE_NAMES
    train, test = _split(data)
    mins, maxs = _minmax(train)
    drop = tuple(FEATURE_NAMES.index(n) for n in UA_FEATURES)

    models = {
        "micrograd_realistic": _train_micrograd(train, mins, maxs),
        "micrograd_realistic_no_ua": _train_micrograd(train, mins, maxs, drop_idx=drop),
        "sklearn_logreg": _train_sklearn(train, mins, maxs, "logreg"),
        "sklearn_rf": _train_sklearn(train, mins, maxs, "rf"),
    }
    result = {
        "train": {"days": sorted(TRAIN_DAYS), "rows": len(train),
                  "bots": int(sum(lbl for _, lbl in train))},
        "test": {"days": sorted(TEST_DAYS), "rows": len(test),
                 "bots": int(sum(lbl for _, lbl in test))},
        "models": {name: _evaluate(pred, test) for name, pred in models.items()},
    }
    shipped = BotDetector(str(ROOT / "data" / "model.json"))
    result["models"]["shipped_baseline"] = _evaluate(shipped.predict, test)
    return result


def main() -> None:
    result = run()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    result["provenance"] = stamp()
    OUT.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(f"train {result['train']['rows']} rows, test {result['test']['rows']} "
          f"({result['test']['rows'] - result['test']['bots']} human, "
          f"{result['test']['bots']} bot) on held-out days\n")
    for name, b in result["models"].items():
        auc = b["auc"]
        print(f"  {name:26} AUC={auc if auc is None else round(auc, 3)}  "
              f"AP={b['ap'] if b['ap'] is None else round(b['ap'], 3)}  "
              f"recall@0-human-FP={_fmt(b['recall_at_0_human_fp'])}")
    print(f"\nwrote {OUT}")


def _fmt(rate: dict) -> str:
    return f"{rate['value'] * 100:.0f}% ({rate['k']}/{rate['n']})" if rate.get("n") else "n/a"


if __name__ == "__main__":
    main()
