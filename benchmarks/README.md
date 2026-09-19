# Benchmarks

Measures microguard against baselines on traffic it did not label, and measures
the micrograd model's own contribution separately. The rules that grade every
result were fixed **before any run** in [`PREREGISTRATION.md`](PREREGISTRATION.md);
the committed report is [`docs/results/2026-09-benchmark.md`](../docs/results/2026-09-benchmark.md).

This lives outside the `microguard` package on purpose: it imports tools the
package must never depend on (Playwright, scikit-learn, Docker) and is not part
of CI's `pytest tests/` or its coverage gate.

## Layout

| path | what |
|---|---|
| `PREREGISTRATION.md` | detectors, thresholds, decision rules, predictions — committed first |
| `metrics.py` | Wilson intervals, tie-aware AP/ROC-AUC, actor bootstrap, detection delay |
| `detectors.py` | every detector behind one `Verdict` interface |
| `ladder/` | Suite A: the evasion ladder (real nginx → `serve` → real scorer) |
| `public/zanbil.py` | Suite B1: label + score the Zanbil e-commerce log |
| `public/crowdsec.py` | the CrowdSec baseline, via Docker replay |
| `perf/latency.py` | Suite C: `/check` latency, memory, throughput, inference time |
| `model/track.py` | Suite D: retrain the MLP, compare vs sklearn, marginal catches |
| `report.py` + `figures.py` | render the results JSONs into the report and SVGs |
| `tests/` | unit tests for the metrics and detectors (not run by CI's `pytest tests/`) |

## Prerequisites

```bash
pip install playwright scikit-learn && playwright install chromium
brew install nginx ffuf sqlmap nuclei          # macOS; missing tools are skipped
redis-server &                                  # the lab uses db 15
# Docker Desktop running, for the CrowdSec baseline (skipped if absent)
```

Public datasets (git-ignored, fetched once):

```bash
# Zanbil e-commerce nginx logs (Kaggle mirror of doi:10.7910/DVN/3QBYB5, CC0)
mkdir -p benchmarks/data/zanbil
curl -L -o benchmarks/data/zanbil/archive.zip \
  https://www.kaggle.com/api/v1/datasets/download/eliasdabbas/web-server-access-logs
# Published crawler IP ranges (for verifying Google/Bing crawlers)
mkdir -p benchmarks/data/crawler_ranges
curl -Lo benchmarks/data/crawler_ranges/googlebot.json \
  https://developers.google.com/static/search/apis/ipranges/googlebot.json
curl -Lo benchmarks/data/crawler_ranges/bingbot.json https://www.bing.com/toolbox/bingbot.json
```

## Run

```bash
pytest benchmarks/tests                                   # the harness's own tests

# Suite A — the evasion ladder (one cell per seed × config)
python -m benchmarks.ladder.run --seed 1 --config default
#   ... seeds 1-5 for both `default` and `promoted` ...
python -m benchmarks.ladder.score                         # -> results/ladder/scored.json

# Suite B1 — Zanbil
python -m benchmarks.public.zanbil split                  # zip -> one log per day
python -m benchmarks.public.zanbil label                  # actor labels
python -m benchmarks.public.zanbil gaps                   # human gaps -> ladder pacing
python -m benchmarks.public.zanbil run                    # -> results/zanbil/results.json

python -m benchmarks.perf.latency                         # Suite C
python -m benchmarks.model.track                           # Suite D

python -m benchmarks.report                                # -> docs/results/
```

Every step writes JSON under `benchmarks/results/` (git-ignored); `report.py`
renders whatever exists, so it can run while the suite is still filling in.
`ladder/run.py --small --no-browser` is a fast wiring check and is never scored.
Nothing in Suite A leaves `127.0.0.1`; the attack tools only ever hit loopback.
