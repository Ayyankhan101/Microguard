"""Score every ladder run against exact ground truth (PREREGISTRATION.md, Suite A).

Reads the archives and access logs under benchmarks/results/ladder/, applies
each detector, and pools counts across seeds per (config, level). Writes one
JSON the report renders; prints nothing a decision rests on that the JSON does
not also carry.

    python -m benchmarks.ladder.score
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path

from benchmarks.detectors import (
    Actor,
    Verdict,
    load_actors,
    mg_blend,
    mg_heuristic,
    mg_model,
    offline_scan,
    path_blocklist,
    rate_limit,
    scan_verdicts,
    ua_regex,
)
from benchmarks.metrics import DetectionDelay, Rate, clearly_above, roc_auc
from benchmarks.public.crowdsec import crowdsec_flagged_ips

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "benchmarks" / "results" / "ladder"
OUT = RESULTS / "scored.json"

# Detectors that read only the access log / archive (cheap, per actor).
LIVE_DETECTORS = {
    "ua_regex": ua_regex,
    "rate_limit": rate_limit(),
    "path_blocklist": path_blocklist,
    "mg_heuristic": mg_heuristic,
    "mg_blend": mg_blend(),
    "mg_model": mg_model(),
}


def _cell_key(config: str, level: str) -> str:
    return f"{config}/{level}"


def _load_cell(seed_dir: Path) -> tuple[dict[str, Actor], dict[str, dict]]:
    truth = json.loads((seed_dir / "ground_truth.json").read_text(encoding="utf-8"))
    actors = load_actors(
        [str(seed_dir / "access.log")],
        str(seed_dir / "collected.jsonl"),
        ips=set(truth),
    )
    return actors, truth


def _model_constancy(actors: dict[str, Actor]) -> dict:
    """The shipped model's live spread. PREREGISTRATION anchor 3, corrected.

    The anchor named 0.731; that is the offline/holdout constant. The live
    per-request path collapses to a different near-constant (train/serve skew,
    issue #19), so the operative check is near-constancy, not the literal.
    """
    scores = [d.model_score for a in actors.values() for d in a.decisions]
    if not scores:
        return {"n": 0}
    return {
        "n": len(scores),
        "median": statistics.median(scores),
        "iqr": (statistics.quantiles(scores, n=4)[2] - statistics.quantiles(scores, n=4)[0])
        if len(scores) > 1 else 0.0,
        "min": min(scores),
        "max": max(scores),
    }


def score() -> dict:
    # Gather actors per cell across seeds, plus per-seed recall for one detector.
    cells: dict[str, dict] = {}
    seeds_seen: dict[str, set[int]] = defaultdict(set)
    per_seed_recall: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    model_spread: dict[str, list] = defaultdict(list)

    for config_dir in sorted(RESULTS.glob("*/")):
        config = config_dir.name
        if config in {"tmp"}:
            continue
        for seed_dir in sorted(config_dir.glob("seed*")):
            meta = seed_dir / "run_meta.json"
            if not meta.exists() or json.loads(meta.read_text(encoding="utf-8")).get("small"):
                continue  # never score a wiring run
            seed = json.loads(meta.read_text(encoding="utf-8"))["seed"]
            actors, truth = _load_cell(seed_dir)
            spread = _model_constancy(actors)
            # The question the spread only hints at: does the live model score
            # bots above humans at all? Actor = max model score over its
            # requests; 0.5 means no separation.
            scored_actors = [
                (max((d.model_score for d in a.decisions), default=None),
                 truth[ip]["class"] == "bot")
                for ip, a in actors.items() if a.decisions
            ]
            scored_actors = [(s, lbl) for s, lbl in scored_actors if s is not None]
            if scored_actors:
                spread["actor_auc"] = roc_auc([s for s, _ in scored_actors],
                                              [lbl for _, lbl in scored_actors])
            model_spread[config].append(spread)

            # Offline scan: real `microguard scan` over this seed's access log,
            # one verdict per IP, joined back by actor.
            scan = scan_verdicts(str(seed_dir / "access.log"))
            crowd = crowdsec_flagged_ips(seed_dir / "access.log")
            detectors = dict(LIVE_DETECTORS)
            detectors["mg_scan"] = offline_scan(scan)
            if crowd is not None:
                detectors["crowdsec"] = offline_scan({ip: Verdict(True) for ip in crowd})

            # Bots grouped by level; humans pooled (level == "human").
            by_level: dict[str, list[str]] = defaultdict(list)
            humans: list[str] = []
            for ip, info in truth.items():
                if info["class"] == "bot":
                    by_level[info["level"]].append(ip)
                else:
                    humans.append(ip)

            for name, detect in detectors.items():
                def flagged(ip: str, d=detect, actors=actors) -> bool:
                    a = actors.get(ip)
                    return bool(a and (a.requests or a.decisions) and d(a).flagged)

                for level, ips in by_level.items():
                    cell = cells.setdefault(_cell_key(config, level), {}).setdefault(
                        name, {"recall": Rate(0, 0), "delay_flags": [], "delay_missed": 0}
                    )
                    hits = sum(flagged(ip) for ip in ips)
                    cell["recall"] = cell["recall"] + Rate(hits, len(ips))
                    per_seed_recall[_cell_key(config, level)][name].append(Rate(hits, len(ips)))
                    for ip in ips:
                        a = actors.get(ip)
                        v = detect(a) if a else None
                        if v and v.flagged and v.first_flag:
                            cell["delay_flags"].append(v.first_flag)
                        elif not (v and v.flagged):
                            cell["delay_missed"] += 1
                # Humans: one pooled FPR per detector per config.
                hcell = cells.setdefault(_cell_key(config, "humans"), {}).setdefault(
                    name, {"fpr": Rate(0, 0)}
                )
                hfp = sum(flagged(ip) for ip in humans)
                hcell["fpr"] = hcell["fpr"] + Rate(hfp, len(humans))
            seeds_seen[config].add(seed)

    return _render(cells, seeds_seen, per_seed_recall, model_spread)


def _render(cells, seeds_seen, per_seed_recall, model_spread) -> dict:
    out: dict = {"cells": {}, "seeds": {k: sorted(v) for k, v in seeds_seen.items()},
                 "model_spread": {}}
    for config, spreads in model_spread.items():
        medians = [s["median"] for s in spreads if s.get("n")]
        iqrs = [s["iqr"] for s in spreads if s.get("n")]
        aucs = [s["actor_auc"] for s in spreads if s.get("actor_auc") is not None]
        out["model_spread"][config] = {
            "median_of_medians": statistics.median(medians) if medians else None,
            "max_iqr": max(iqrs) if iqrs else None,
            "near_constant": (max(iqrs) < 0.05) if iqrs else None,
            "mean_actor_auc": statistics.mean(aucs) if aucs else None,
        }
    for cell_key, detectors in cells.items():
        rendered = {}
        for name, data in detectors.items():
            entry: dict = {}
            if "recall" in data:
                entry["recall"] = data["recall"].as_dict()
                delay = DetectionDelay(tuple(data["delay_flags"]), data["delay_missed"])
                entry["delay"] = delay.as_dict()
                seed_rates = per_seed_recall[cell_key][name]
                entry["per_seed_recall"] = [r.as_dict() for r in seed_rates]
            if "fpr" in data:
                entry["fpr"] = data["fpr"].as_dict()
            rendered[name] = entry
        out["cells"][cell_key] = rendered

    # "Beats" table (rule 2): the shipped blend, and separately the rule
    # labeler, vs each baseline per bot level. The pre-registered test is on
    # mg_blend; mg_heuristic is added because "the rules beat the baselines" is
    # the stronger honest claim and the recall table already shows the gap.
    baselines = ("ua_regex", "rate_limit", "path_blocklist", "crowdsec", "mg_scan")
    for subject in ("mg_blend", "mg_heuristic"):
        key = "beats" if subject == "mg_blend" else "beats_heuristic"
        out[key] = {}
        for cell_key, detectors in cells.items():
            if "/humans" in cell_key or subject not in detectors:
                continue
            config = cell_key.split("/")[0]
            us = detectors[subject]["recall"]
            us_fp = cells[f"{config}/humans"][subject]["fpr"]
            row = {}
            for name in baselines:
                if name not in detectors:
                    continue
                base = detectors[name]["recall"]
                base_fp = cells[f"{config}/humans"][name]["fpr"]
                row[name] = bool(clearly_above(us, base) and us_fp.k <= base_fp.k)
            out[key][cell_key] = row
    return out


def main() -> None:
    result = score()
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    scored_cells = len([k for k in result["cells"] if "/humans" not in k])
    print(f"scored {scored_cells} bot cells across configs {list(result['seeds'])}")
    print(f"model spread: {result['model_spread']}")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
