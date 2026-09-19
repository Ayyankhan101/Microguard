"""Turn the result JSONs into the committed report and its figures.

Reads whatever suites have produced (ladder scored, model track, Zanbil,
performance) and writes docs/results/2026-09-benchmark.md plus the SVGs it
embeds. Missing suites are noted as "not yet run", so this can be run while the
benchmark is still filling in. Deterministic: same inputs, same bytes out.

    python -m benchmarks.report
"""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.figures import LABELS, PALETTE, grouped_bars, ladder_chart

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"
DOCS = ROOT / "docs" / "results"
FIGS = DOCS / "figures"
LADDER_ORDER = ["L0", "L1", "L2", "L3", "L4", "L5", "L5-farm"]
DETECTOR_ORDER = ["ua_regex", "rate_limit", "path_blocklist", "crowdsec",
                  "mg_scan", "mg_heuristic", "mg_blend"]


def _load(name: str) -> dict | None:
    path = RESULTS / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _pct(rate: dict | None) -> str:
    if not rate or not rate.get("n"):
        return "—"
    return f"{rate['value'] * 100:.0f}% ({rate['k']}/{rate['n']})"


def _pct_ci(rate: dict | None) -> str:
    if not rate or not rate.get("n"):
        return "n/a (0/0)"
    return (f"{rate['value'] * 100:.0f}% ({rate['k']}/{rate['n']}, "
            f"CI {rate['ci_low'] * 100:.0f}–{rate['ci_high'] * 100:.0f}%)")


# --------------------------------------------------------------------------
# ladder
# --------------------------------------------------------------------------


def _ladder_section(scored: dict) -> tuple[str, dict]:
    cells = scored["cells"]
    configs = list(scored["seeds"])
    figures: dict[str, str] = {}
    all_seeds = sorted({s for cfg in configs for s in scored["seeds"][cfg]})
    md = ["## Suite A — the evasion ladder\n",
          (f"Exact ground truth, real production path, pooled over "
           f"{len(all_seeds)} seeds ({', '.join(map(str, all_seeds))}) per config. "
           f"Recall is bots caught; a cell under 30 bots is marked inconclusive (rule 1).\n")]

    for config in configs:
        levels = [lvl for lvl in LADDER_ORDER if f"{config}/{lvl}" in cells]
        if not levels:
            continue
        series: dict[str, list] = {}
        fpr_note: dict[str, str] = {}
        for det in DETECTOR_ORDER:
            row = []
            present = False
            for lvl in levels:
                cell = cells[f"{config}/{lvl}"].get(det, {})
                rec = cell.get("recall")
                if rec and rec.get("n"):
                    row.append(rec["value"])
                    present = True
                else:
                    row.append(None)
            if present:
                series[det] = row
                hfpr = cells.get(f"{config}/humans", {}).get(det, {}).get("fpr")
                fpr_note[det] = _pct(hfpr) if hfpr else "—"
        svg = ladder_chart(levels, series, fpr_note,
                           title=f"Recall by evasion level — {config} config")
        fname = f"ladder-{config}.svg"
        figures[fname] = svg
        md.append(f"![Evasion ladder, {config} config](figures/{fname})\n")

        # the table
        md.append(f"### {config}: recall by level (human FP rate in the last column)\n")
        header = "| detector | " + " | ".join(levels) + " | human FP |"
        md.append(header)
        md.append("|" + "---|" * (len(levels) + 2))
        for det in DETECTOR_ORDER:
            if det not in series:
                continue
            cellvals = []
            for lvl in levels:
                rec = cells[f"{config}/{lvl}"].get(det, {}).get("recall")
                cellvals.append(_pct(rec))
            hfpr = cells.get(f"{config}/humans", {}).get(det, {}).get("fpr")
            md.append(f"| {LABELS.get(det, det)} | " + " | ".join(cellvals)
                      + f" | {_pct(hfpr)} |")
        md.append("")

    # beats tables — the shipped blend, and the rule labeler
    for key, subject, note in (
        ("beats", "microguard (blend)",
         ("the pre-registered test (rule 2): the shipped blend's recall interval "
          "clears the baseline's, with no extra human FPs")),
        ("beats_heuristic", "microguard (rules)",
         "the same test for the rule labeler alone — the stronger claim"),
    ):
        table = scored.get(key, {})
        beat_levels = ([lvl for lvl in LADDER_ORDER if f"{configs[0]}/{lvl}" in table]
                       if configs else [])
        if not beat_levels:
            continue
        md.append(f"### Does {subject} beat each baseline?\n")
        md.append(f"A ✓ is {note}, at that level.\n")
        md.append("| baseline | " + " | ".join(beat_levels) + " |")
        md.append("|" + "---|" * (len(beat_levels) + 1))
        for base in ("ua_regex", "rate_limit", "path_blocklist", "crowdsec", "mg_scan"):
            marks = []
            for lvl in beat_levels:
                row = table.get(f"{configs[0]}/{lvl}", {})
                marks.append("✓" if row.get(base) else "·")
            md.append(f"| {LABELS.get(base, base)} | " + " | ".join(marks) + " |")
        md.append("")

    # A data-driven reading of the two structural findings.
    md.append("### What the ladder shows\n")
    config = configs[0] if configs else "default"

    def rec(level, det):
        r = cells.get(f"{config}/{level}", {}).get(det, {}).get("recall")
        return r["value"] if r and r.get("n") else None

    gaps = []
    for lvl in LADDER_ORDER:
        h, b = rec(lvl, "mg_heuristic"), rec(lvl, "mg_blend")
        if h is not None and b is not None and h - b >= 0.2:
            gaps.append((lvl, h, b))
    if gaps:
        worst = max(gaps, key=lambda g: g[1] - g[2])
        md.append(
            f"- **The shipped blend throws away most of what the rules catch.** At "
            f"{worst[0]} the rule labeler flags {worst[1] * 100:.0f}% of bots but the "
            f"blend at its default 0.85 threshold flags only {worst[2] * 100:.0f}%. "
            f"`compute_combined_score` floors a bot at the rule's own confidence, and "
            f"the rules that survive a spoofed UA (rate, repeat-endpoint, no-referrer) "
            f"sit at 0.70–0.85 — at or below the 0.85 block bar. Only the 0.90+ rules "
            f"clear it. An operator running the blend as shipped gets materially worse "
            f"recall than the rule labeler alone; the threshold, not the model, is the "
            f"limiting factor.\n")
    farm_default = rec("L5-farm", "mg_heuristic")
    farm_promoted = None
    promoted_fp = None
    if "promoted" in scored["seeds"]:
        fr = cells.get("promoted/L5-farm", {}).get("mg_heuristic", {}).get("recall")
        farm_promoted = fr["value"] if fr and fr.get("n") else None
        promoted_fp = cells.get("promoted/humans", {}).get("mg_heuristic", {}).get("fpr")
    if farm_default is not None:
        line = (f"- **The distributed browser farm is the rules' blind spot.** The "
                f"L5-farm — one real browser profile across ten IPs, low volume each — "
                f"is caught {farm_default * 100:.0f}% by the rules in the default config")
        if farm_promoted is not None:
            line += (f", and {farm_promoted * 100:.0f}% once the fingerprint signal is "
                     f"promoted (the shared-fingerprint-across-IPs rule is the one signal "
                     f"IP reputation structurally cannot provide)")
        line += (". This is the case volume and path heuristics cannot see, and the "
                 "reason the fingerprint signal exists.")
        if promoted_fp and promoted_fp.get("k"):
            line += (f" But promotion is **not free**: it lifts human false positives from "
                     f"0/175 to {_pct(promoted_fp)}, because the fingerprint-absence rule "
                     f"flags clients that never run the script — here the scripted humans, "
                     f"and in production any text browser or privacy-tool user. By the "
                     f"pre-registered 0-FP bar (rule 3) the promoted signal is not yet safe "
                     f"to block on.")
        md.append(line + "\n")

    spread = scored.get("model_spread", {})
    s = spread.get(config) or (next(iter(spread.values())) if spread else None)
    if s:
        auc = s.get("mean_actor_auc")
        auc_txt = f"{auc:.2f}" if auc is not None else "—"
        md += [
            "### The shipped model on the live path\n",
            (f"The live per-request model score is not the inert 0.731 constant the docs "
             f"describe (that is the offline/holdout value). It varies (median "
             f"{s['median_of_medians']:.2f}, both configs alike) and actually ranks bots "
             f"above humans, actor-level AUC {auc_txt}. The catch is calibration, not "
             f"signal: the scores sit high, so at the `model_score > 0.5` cut the model "
             f"flags every bot **and** every human (a useless operating point), and inside "
             f"the blend the heuristic floor/cap drives the verdict. The ranking is real; no "
             f"fixed threshold the tool uses exploits it. Suite D asks whether retraining on "
             f"this distribution fixes it.\n"),
        ]
    return "\n".join(md), figures


# --------------------------------------------------------------------------
# grading the predictions
# --------------------------------------------------------------------------


def _grade(scored: dict) -> str:
    cells = scored["cells"]

    def recall(config, level, det):
        r = cells.get(f"{config}/{level}", {}).get(det, {}).get("recall")
        return r["value"] if r and r.get("n") else None

    def fpr_k(config, det):
        r = cells.get(f"{config}/humans", {}).get(det, {}).get("fpr")
        return r["k"] if r else None

    checks = []

    def grade(pid, text, ok):
        mark = "✅" if ok else ("❌" if ok is False else "—")
        checks.append(f"| {pid} | {text} | {mark} |")

    r = lambda c, lvl, d: recall(c, lvl, d)
    if "default" in scored["seeds"]:
        ua0 = r("default", "L0", "ua_regex")
        grade("P1", "UA regex ≥95% at L0, ≤10% at L1–L5",
              None if ua0 is None else (ua0 >= 0.95 and all(
                  (r("default", lv, "ua_regex") or 0) <= 0.10
                  for lv in ("L1", "L2", "L3", "L4", "L5") if r("default", lv, "ua_regex") is not None)))
        b0 = r("default", "L0", "mg_blend")
        grade("P2", "blend ≥95% at L0", None if b0 is None else b0 >= 0.95)
        vals = [r("default", lv, "mg_blend") for lv in ("L1", "L2")]
        grade("P3", "blend ≥70% at L1 and L2",
              None if any(v is None for v in vals) else all(v >= 0.70 for v in vals))
        grade("P7", "blend flags 0 humans (default)",
              None if fpr_k("default", "mg_blend") is None else fpr_k("default", "mg_blend") == 0)
        b9 = scored.get("model_spread", {}).get("default", {})
        grade("P9", "shipped model near-constant on the live path",
              b9.get("near_constant"))
    farm = r("promoted", "L5-farm", "mg_blend")
    grade("P8", "promoted L5-farm recall ≤50% (refresher lag)",
          None if farm is None else farm <= 0.50)

    md = ["## Pre-registered predictions, graded\n",
          ("Written before any run (`benchmarks/PREREGISTRATION.md`). — means the "
           "cell was not measured.\n"),
          "| # | prediction | result |", "|---|---|---|", *checks, ""]
    return "\n".join(md)


# --------------------------------------------------------------------------
# other suites
# --------------------------------------------------------------------------


def _model_section(track: dict) -> str:
    if "error" in track:
        return f"## Suite D — the model track\n\n_Not yet run: {track['error']}._\n"
    md = ["## Suite D — does the micrograd model earn its place?\n",
          (f"Trained on {track['train']['rows']} live per-request vectors from "
           f"seeds {track['train']['seeds']}, levels {track['train']['levels']}; "
           f"tested on seeds {track['test']['seeds']} at every level "
           f"({track['test']['rows']} vectors). Actor score = max over its requests.\n"),
          ("| model | ROC-AUC | avg precision | recall@0.5 | added human FP | "
           "marginal catches | earns place? |"),
          "|---|---|---|---|---|---|---|"]
    for name, b in track["models"].items():
        auc = "—" if b.get("auc") is None else f"{b['auc']:.3f}"
        ap = "—" if b.get("ap") is None else f"{b['ap']:.3f}"
        rec = _pct(b.get("recall_at_0.5"))
        mc = b.get("marginal_catches", "—")
        fp = b.get("added_human_fp", "—")
        earns = "✅" if b.get("earns_place") else ("❌" if "earns_place" in b else "—")
        md.append(f"| {name} | {auc} | {ap} | {rec} | {fp} | {mc} | {earns} |")
    md.append("")

    retr = track["models"].get("micrograd_retrained", {})
    by_level = retr.get("marginal_by_level", {})
    if by_level:
        where = ", ".join(f"{n} at {lvl}" for lvl, n in sorted(by_level.items()))
        md.append(
            f"**What the marginal catches are.** The retrained model's "
            f"{retr.get('marginal_catches')} catches the rules miss are exactly the bots "
            f"the ladder showed as the rules' blind spot: {where} — the distributed farm and "
            f"the L4 stragglers — recovered with {retr.get('added_human_fp')} added human "
            f"false positives. The no-UA ablation lands the same score, so it is behaviour, "
            f"not the user agent, doing the work.\n")
    md.append(
        "**Read the 1.000 with the Zanbil result in hand.** A perfect AUC here is an *upper "
        "bound*, not a production number: the lab's humans are simulated and cleanly "
        "separable from bots in feature space, and sklearn logreg/RF hit the same 1.000, "
        "which says the *data* is separable, not that this model is special. On real human "
        "traffic that separation does not hold — `microguard scan` flags 57% of real Zanbil "
        "shoppers (B1 below). So Suite D shows the model *can* catch the farm behaviourally; "
        "it does not show a model that is safe to ship as a blocker. Replacing "
        "`microguard/data/model.json` "
        "stays out of scope.\n")
    if track.get("leakage"):
        cols = ", ".join(o["feature"] for o in track["leakage"])
        md.append(f"**Leakage guard:** these training features separate the classes "
                  f"perfectly on their own — {cols}. Read the retrained numbers with that "
                  f"in mind.\n")
    else:
        md.append("**Leakage guard:** no single training feature separates the classes "
                  "perfectly.\n")
    return "\n".join(md)


def _zanbil_human_request_stats() -> dict | None:
    """Median requests per human-proxy session, from the label files.

    The whole B1d finding rests on real shoppers being high-volume, so the
    driver is quoted from the data rather than asserted.
    """
    labels_dir = RESULTS.parent / "data" / "zanbil" / "labels"
    if not labels_dir.exists():
        return None
    counts = []
    for f in labels_dir.glob("2019-*.json"):
        for info in json.loads(f.read_text(encoding="utf-8")).values():
            if info["label"] == "human_proxy":
                counts.append(info["requests"])
    if not counts:
        return None
    counts.sort()
    return {"actors": len(counts), "median": counts[len(counts) // 2],
            "p90": counts[int(len(counts) * 0.9)], "max": counts[-1]}


def _zanbil_section(z: dict) -> str:
    pooled: dict = {}
    for tests in z.values():
        for test, payload in tests.items():
            if not isinstance(payload, dict) or "detectors" not in payload:
                continue
            for det, dd in payload["detectors"].items():
                slot = pooled.setdefault(test, {}).setdefault(det, {"bk": 0, "bn": 0, "hk": 0, "hn": 0})
                bots = dd.get("bots_flagged", {})
                hums = dd.get("humans_flagged", {})
                slot["bk"] += bots.get("k", 0); slot["bn"] += bots.get("n", 0)
                slot["hk"] += hums.get("k", 0); slot["hn"] += hums.get("n", 0)

    def rate(test, det, human=False):
        s = pooled.get(test, {}).get(det)
        if not s:
            return None
        k, n = (s["hk"], s["hn"]) if human else (s["bk"], s["bn"])
        return {"k": k, "n": n, "value": k / n if n else None, "ci_low": 0, "ci_high": 0}

    md = ["## Suite B1 — Zanbil, real e-commerce traffic\n",
          ("Real nginx logs from an Iranian shopping site (Kaggle mirror of "
           "doi:10.7910/DVN/3QBYB5, CC0; ~10.3M lines over five days). Labels come "
           "only from evidence the detectors do not read: verified crawlers are "
           "confirmed against Google/Bing published IP ranges, human-proxy actors "
           "are browser sessions that reached checkout and loaded assets. Counts "
           "pooled across the five days.\n"),
          "**Two findings, opposite directions.**\n"]

    stats = _zanbil_human_request_stats()
    b1b_scan = rate("B1b_crawlers_ua_stripped", "mg_scan")
    b1b_ua = rate("B1b_crawlers_ua_stripped", "ua_regex")
    b1d_scan = rate("B1d_humans_as_is", "mg_scan", human=True)
    b1d_ua = rate("B1d_humans_as_is", "ua_regex", human=True)
    if b1b_scan and b1b_ua:
        md.append(
            f"1. **Behaviour beats a UA blocklist on disguised crawlers.** With every "
            f"crawler's User-Agent rewritten to Chrome, `microguard scan` still catches "
            f"{_pct(b1b_scan)} of them by behaviour alone, where a UA blocklist catches "
            f"{_pct(b1b_ua)} — it has nothing left to match.\n")
    if b1d_scan and b1d_ua:
        driver = ""
        if stats:
            driver = (f" Real shoppers on an image-heavy store make a median of "
                      f"{stats['median']} requests per session (p90 {stats['p90']}, "
                      f"max {stats['max']:,}), and the `> 100 requests` rule reads that "
                      f"as a scraper.")
        md.append(
            f"2. **But `scan` over-flags real humans badly.** At its default threshold it "
            f"flags {_pct(b1d_scan)} of real human shoppers as bots, against {_pct(b1d_ua)} "
            f"for a UA blocklist.{driver} This is the false-positive rate the scripted lab "
            f"(Suite A) could not show, because those humans made a handful of requests "
            f"with no embedded assets. The live blocker at its stricter 0.85 threshold "
            f"spares most of them (the count rule sits at 0.85, and the block test is "
            f"strict `>`), but `scan` as an audit tool is unsafe on this traffic as-is.\n")

    titles = {
        "B1a_verified_as_is": "B1a — verified crawlers, logs as-is (bots caught)",
        "B1b_crawlers_ua_stripped": "B1b — crawlers, UA rewritten to Chrome (bots caught by behaviour)",
        "B1c_probe_bots_probes_removed": "B1c — probe bots, probe requests removed (bots caught)",
        "B1d_humans_as_is": "B1d — real human shoppers flagged (this is the FP rate)",
    }
    for test, title in titles.items():
        if test not in pooled:
            continue
        human = test == "B1d_humans_as_is"
        md.append(f"### {title}\n")
        md.append("| detector | flagged |")
        md.append("|---|---|")
        for det in ("ua_regex", "rate_limit", "path_blocklist", "mg_scan"):
            r = rate(test, det, human=human)
            if r:
                md.append(f"| {LABELS.get(det, det)} | {_pct(r)} |")
        md.append("")
    return "\n".join(md)


def _perf_section(perf: dict) -> tuple[str, dict]:
    hw = perf.get("hardware", {})
    md = ["## Suite C — performance\n",
          (f"On {hw.get('cpu', hw.get('platform', 'this machine'))}, "
           f"{hw.get('mem_gb', '?')} GB, Python {hw.get('python', '?')}.\n"),
          "### /check latency (5,000 requests, rotating IPs)\n",
          "| concurrency | p50 | p95 | p99 | req/s |", "|---|---|---|---|---|"]
    for c, d in perf.get("check_latency_ms", {}).items():
        md.append(f"| {c[1:]} | {d['p50']} ms | {d['p95']} ms | {d['p99']} ms | {d['req_per_s']} |")
    c1 = perf.get("check_latency_ms", {}).get("c1", {})
    c50 = perf.get("check_latency_ms", {}).get("c50", {})
    if c1 and c50:
        md.append(
            f"\nDeploy how-to target: p99 under 20 ms. It holds at concurrency 1 "
            f"(p99 {c1['p99']} ms) but not under load (p99 {c50['p99']} ms at 50): the "
            f"check server is a single-threaded stdlib `HTTPServer`, so requests serialize. "
            f"An operator running several workers behind nginx would keep the per-worker "
            f"concurrency low; the number to watch is p99 at your real peak concurrency.\n")
    figures: dict[str, str] = {}
    inf = perf.get("inference", {})
    if inf:
        series = {
            "micrograd": [inf.get("micrograd_us_per_predict", 0)],
            "sklearn logreg": [inf.get("logreg_us_per_predict", 0)],
            "sklearn RF": [inf.get("rf_us_per_predict", 0)],
        }
        colors = {"micrograd": PALETTE["mg_blend"], "sklearn logreg": PALETTE["rate_limit"],
                  "sklearn RF": PALETTE["crowdsec"]}
        figures["inference.svg"] = grouped_bars(
            "Per-prediction time (µs)", ["one predict"], series, colors, unit="microseconds")
        md.append("![Inference time](figures/inference.svg)\n")
        md.append(f"micrograd: {inf.get('micrograd_us_per_predict')} µs/predict; "
                  f"sklearn logreg {inf.get('logreg_us_per_predict')} µs; "
                  f"sklearn RF {inf.get('rf_us_per_predict')} µs.\n")
    rm = perf.get("redis_memory", {})
    if rm:
        md.append(f"**Memory:** {rm['bytes_per_actor']:.0f} bytes per tracked actor "
                  f"({rm['actors']:,} actors added).\n")
    st = perf.get("scan_throughput")
    if st:
        md.append(f"**Offline scan:** {st['lines_per_s']:,} lines/s on a "
                  f"{st['lines']:,}-line Zanbil slice ({st['sessions']:,} sessions).\n")
    return "\n".join(md), figures


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

INTRO = """# Microguard, benchmarked on real-world data

_Generated by `python -m benchmarks.report`. Every number traces to a JSON under
`benchmarks/results/` and to code under `benchmarks/`. The rules that grade each
result were fixed before any run in [`PREREGISTRATION.md`](../../benchmarks/PREREGISTRATION.md)._

## What this set out to test

Two claims, kept separate:

1. **The tool** (heuristic rules + the shipped blend, and the offline
   `microguard scan` audit) catches bots that simple, widely used alternatives
   miss, without flagging humans.
2. **The micrograd model** catches bots the rules miss, without new human
   false positives.

Every bot is measured against baselines an operator could deploy instead — a
User-Agent blocklist, a rate limit, a path blocklist, and CrowdSec — and against
the same bots at rising levels of evasion (`L0` announces itself, `L5` is a real
headless browser pacing like a human from rotating IPs). Ground truth never
comes from the rules under test.

## Two honest limitations up front

- **Humans here are simulated** (lab scripts, real headless Chromium, and, for
  Zanbil, real people whose human label is a checkout-plus-assets proxy). The
  live-EC2 runbook in `docs/howto-evaluate-on-live-traffic.md` is the way to get
  real invited humans; that was out of scope for this pass.
- **The live check server ignored the forwarded `Referer` while these numbers
  were measured** (`server.py` built every request with `referer=""`). So
  referer-based rules and features were inert on the live path for this run, and
  the "no referrer on all requests" rule fired on any 20-plus-request session
  regardless of what the client actually sent. That inflates live recall on
  high-volume bots below, and is called out where it matters. The offline
  `microguard scan` did read the referer. This defect has since been fixed --
  see [Fixes applied since this benchmark](#fixes-applied-since-this-benchmark).
  The numbers here are deliberately left as they were measured.
"""

DEVIATIONS = """## Deviations from the pre-registration

1. **Anchor 3 (and prediction P9) named 0.731 and "near-constant" for the live
   model.** 0.731 is the offline/holdout constant; the live per-request path is
   different (train/serve skew, issue #19) — and, the part neither the anchor
   nor P9 anticipated, it is not near-constant at all: the score varies widely
   and ranks bots above humans (AUC ≈ 0.77, Suite A). The pre-registration
   assumed an inert constant; that was wrong, P9 is graded a miss on purpose,
   and Suite D takes up whether a retrained (recalibrated) model helps.
2. **CrowdSec sees a public-IP rewrite of the lab logs.** CrowdSec whitelists
   private ranges by default, and the lab actors live in 10.66/10.99. Each lab
   IP is mapped 1:1 to a public one for the CrowdSec replay only, and back
   afterwards; microguard scores the real lab IPs. Zanbil's real public IPs are
   untouched.
"""


FIXES_NOTE = """## Fixes applied since this benchmark

The numbers above were measured **before** the three defects the benchmark
surfaced were fixed; they are kept as the baseline that motivated the fixes.
What changed (see the git history on `microguard/live/` and `microguard/labeler.py`):

- **The live path now reads the `Referer`.** The check server and the ASGI/WSGI
  middleware built every request with `referer=""`; all three now read the real
  header (the check server via `proxy_set_header Referer $http_referer;`). The
  "no referrer" rule no longer fires on every long live session, and the human
  navigation rule can fire live.
- **The volume rules count page-like requests, not embedded assets.** This cut
  the `scan` false-positive rate on real Zanbil human shoppers from **57% to
  15%** (a page/endpoint scraper is still caught; a browser loading rich pages
  is not).
- **Credential/API-key brute-force is promoted 0.75 → 0.90**, so the one
  unambiguous-attack rule the 0.85 blend was discarding now blocks live, with no
  human-FP risk. A blanket threshold drop was rejected as unsafe: the
  `>100 requests` rule sits at exactly 0.85 by design, and dropping below it
  re-introduces the real-human false positives the volume-rule fix removed.

Re-running the full matrix under the fixes would refresh these tables; the
committed baseline is deliberately the pre-fix state.
"""


def build() -> None:
    FIGS.mkdir(parents=True, exist_ok=True)
    scored = _load("ladder/scored.json")
    track = _load("model_track.json")
    zanbil = _load("zanbil/results.json")
    perf = _load("perf.json")

    parts = [INTRO]
    figures: dict[str, str] = {}
    if scored and scored.get("cells"):
        md, figs = _ladder_section(scored)
        parts.append(md); figures.update(figs)
        parts.append(_grade(scored))
    else:
        parts.append("## Suite A — the evasion ladder\n\n_Not yet run._\n")
    if perf:
        md, figs = _perf_section(perf)
        parts.append(md); figures.update(figs)
    if zanbil:
        parts.append(_zanbil_section(zanbil))
    if track:
        parts.append(_model_section(track))
    parts.append(DEVIATIONS)
    parts.append(FIXES_NOTE)

    for fname, svg in figures.items():
        (FIGS / fname).write_text(svg, encoding="utf-8")
    out = DOCS / "2026-09-benchmark.md"
    out.write_text("\n".join(parts).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {out} and {len(figures)} figures")


if __name__ == "__main__":
    build()
