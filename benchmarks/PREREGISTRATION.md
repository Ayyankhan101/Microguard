# Benchmark pre-registration

Written and committed **before any detector was run on any benchmark data**.
The commit that adds this file is the timestamp. Every decision below is fixed
from here on; anything changed later is listed under "Deviations" in the report
with the reason, rather than edited in place here.

What had been seen when this was written, so it can be discounted:

- The existing lab run (`scripts/lab/.run/scorecard.md`): heuristic and blend
  at 43/43 bots, 0/50 humans; the shipped model a constant ~0.731.
- The shape of the public data (file lists, URL patterns, row formats). No
  detector output on it.

## The question

Two claims, measured separately:

1. **The tool** (what ships: heuristic rules + blend, plus the offline
   `microguard scan` audit) catches bots that simple, widely used alternatives
   miss, without flagging humans.
2. **The micrograd model** catches bots the rules miss, without flagging humans
   the rules leave alone.

Either can come out false. Both outcomes get published.

## Detectors, fixed parameters

Actor = one client IP (per day-slice for Zanbil). An actor is **flagged** if any
one of its requests is flagged: one flagged request is one blocked page.

| name | what | flag rule |
|---|---|---|
| `ua_regex` | one-line User-Agent blocklist | UA empty or `-`, or matches, case-insensitive: `bot\|crawl\|spider\|slurp\|curl\|wget\|python\|go-http\|java/\|libwww\|perl\|ruby\|php/\|scrapy\|httpclient\|okhttp\|axios\|node-fetch\|headless\|phantom\|selenium\|nmap\|sqlmap\|nikto\|nuclei\|ffuf\|gobuster\|dirbuster\|wfuzz\|masscan\|zgrab\|hydra` |
| `rate_limit` | fail2ban / nginx `limit_req` style | more than **60 requests in any 60 s window** |
| `path_blocklist` | path + payload blocklist | path starts with `microguard.evaluate.PROBE_PREFIXES` or `/server-status`, `/actuator`, `/.DS_Store`; or the URL-decoded, lower-cased request contains `../`, `/etc/passwd`, `union select`, `<script`, `' or `, `sleep(`, `${jndi:`, `waitfor delay` |
| `crowdsec` | CrowdSec replaying the access log | IP has any alert from collections `crowdsecurity/nginx`, `crowdsecurity/base-http-scenarios`, `crowdsecurity/http-cve`. Run only if Docker is available; otherwise reported as not run |
| `mg_heuristic` | live rules alone | any archived decision with `heuristic_label == "bot"` |
| `mg_blend` | **what ships, live** | any archived decision with `score > 0.85` (`BLOCK_THRESHOLD_DEFAULT`) |
| `mg_model` | shipped model alone, live | any archived decision with `model_score > 0.5` |
| `mg_scan` | **what ships, offline audit** | `microguard.cli.scan_logfile` session `label == "bot"` (its default threshold, 0.7) |
| `mg_model_retrained`, `mg_blend_retrained` | Suite D only | model score `> 0.5`; blend `> 0.85` recomputed with the retrained model |

Threshold sweeps are reported as information. **No threshold is chosen by
looking at test data.**

## Decision rules

1. **Minimum sample.** A cell with fewer than 30 bot actors or 30 human actors
   is *inconclusive*: counts are reported, rates are not claimed.
2. **"Beats."** Detector A beats B in a cell only if the lower bound of A's
   95% Wilson recall interval is above the upper bound of B's, **and** A's human
   false-positive count is not higher than B's.
3. **Safe to block.** A detector is called safe to block in a suite only at
   0 flagged humans. The Wilson upper bound on that 0/N is reported beside it.
4. **The model earns its place** only if, on held-out runs, `mg_blend_retrained`
   averages at least 1 *marginal catch* per run (a bot it flags that
   `mg_heuristic` does not) **and** adds 0 human false positives in total.
   Otherwise the report says the model adds nothing measurable.
5. **Pooling.** Suite A pools the 5 seeds per (config, level, detector) by summing
   counts. Per-seed values are reported too, so one bad seed is visible.

## Suite A: evasion ladder (local lab, exact ground truth)

Real production path: nginx `auth_request` to `microguard serve` to the real scorer
and Redis, observe-only (`--block-threshold 1.0`), archive via `--collect-to`.
Truth is assigned by construction: each actor gets its IP and class before it
sends anything. Nothing leaves loopback.

**Site:** index, catalog of 200 product pages, `/search` (GET), `/login.html`,
`/login` (POST, always refused). Every HTML page loads `/microguard/fingerprint.js`.

**Human pacing:** gaps between page views are sampled from real human
page-view gaps in the Zanbil log (Suite B's human proxies), clipped to
[1 s, 30 s] to bound run time. The quantile table is committed as
`benchmarks/ladder/human_gaps.json`. Bots at "human pacing" levels draw
from the **same** table.

**Humans per run: 35.**
- 20 scripted: 3-7 page views; on the first page, fetch the fingerprint
  script and POST a random 64-hex hash after 0.3-0.9 s. 30% do one search, 15%
  one login POST.
- 15 real headless Chromium (Playwright), same plan. The fingerprint script
  runs for real. Each has a unique profile (viewport, timezone, locale, scale factor).

**Bot jobs** (fixed request budget per job, same at every level):

| job | budget | shape |
|---|---|---|
| scraper | 25 | `/catalog/` then product pages p001..p024 in order |
| credential | 16 | `GET /login.html`, then 15 `POST /login` |
| vulnscan | tools / 20 | L0-L2: real `ffuf`, `sqlmap`, `nuclei` (one actor each). L3-L5: 20 fixed attack requests (10 probe paths, 10 injection payloads on `/search`) |
| poller | 15 | `GET /catalog/p007.html` repeatedly, 2.0 s apart (L0-L2, L4) |

**Levels** (2 actors per job per level, except vulnscan L0-L2 = 3):

| level | UA | extra headers | pacing | client |
|---|---|---|---|---|
| L0 | tool default (`python-requests/2.31.0`; `Go-http-client/1.1` for poller; tools' own) | none | as fast as served (poller 2 s) | scripted |
| L1 | fixed desktop Chrome UA | none | as L0 | scripted |
| L2 | Chrome UA | Accept, Accept-Language, Accept-Encoding, Referer chain | as L0 | scripted |
| L3 | Chrome UA | as L2 | human gaps | scripted |
| L4 | Chrome UA (headless marker removed) | real browser | as fast as pages load (poller 2 s) | Playwright, unique profile |
| L5 | Chrome UA | real browser | human gaps | Playwright, unique profile |
| L5-farm | Chrome UA | real browser | human gaps | Playwright, **one identical profile on 10 IPs**, 8 page views each |

**Configs**, 5 seeds each:
- `default`: as shipped, every signal observe-only.
- `promoted`: `promoted_signals = ["fingerprint"]`, with `microguard signals`
  running at its **documented default interval (300 s)**.

**Pre-run observation:** `LiveScorer._promote` attaches promotions only when
`signals.resolved`, and only the refresher sets that. Under `promoted`, the
fingerprint rules therefore cannot fire for an IP until a refresher pass has
visited it. This is measured as shipped, not worked around.

**Sanity anchors** (if any fails, the run is broken and is not reported as a result):
- `ua_regex` recall at L0 is at least 95%.
- Every assigned actor has at least one archived decision.
- `mg_model` scores stay near the known constant (0.731 ± 0.01) on at least 90% of decisions.

### Predictions (graded in the report)

| # | prediction |
|---|---|
| P1 | `ua_regex` L0 recall at least 95%, L1-L5 at most 10% |
| P2 | `mg_blend` L0 recall at least 95% |
| P3 | `mg_blend` L1 and L2 recall at least 70% (rate and uniform-timing rules survive a spoofed UA) |
| P4 | `mg_blend` beats `ua_regex` at L1 and L2 (rule 2) |
| P5 | `mg_blend` does **not** beat `rate_limit` at any level |
| P6 | `mg_blend` L3 and L5 recall at most 50% |
| P7 | `mg_blend` flags 0 humans in `default` |
| P8 | `promoted` L5-farm recall at most 50% (refresher lag) |
| P9 | `mg_model` (shipped) has ROC-AUC between 0.4 and 0.6 at every level |

## Suite B: public real-world logs

Leakage exclusions: `organization-x` (training bots) and **Zanbil's derived
timing files** (training humans, `data/dataverse/`) were used in training.
So Zanbil is used **only** for rule/baseline/offline-scan detectors, never to
evaluate the model. `organization-x` is not used at all.

### B1: Zanbil (Kaggle mirror of doi:10.7910/DVN/3QBYB5, CC0)

~10.3M nginx lines, 22-26 Jan 2019, real IPs and UAs. Processed one local
calendar day at a time. Actor = (day, IP). Labels come only from evidence
the tested detectors do not use, or from evidence that is removed before
detection:

- **verified_crawler**: UA claims Googlebot, Bingbot/msnbot, YandexBot,
  Applebot, or Baiduspider, **and** either the IP is in the engine's
  published range file (Google `googlebot.json`, Bing `bingbot.json`), or
  `client_hostname.csv` gives a hostname under the engine's domain
  (`googlebot.com`/`google.com`, `search.msn.com`, `yandex.ru|.net|.com`,
  `applebot.apple.com`, `baidu.com|.jp`) whose address list contains the IP.
- **fake_crawler**: claims one of those engines and is not verified.
- **probe_bot**: requested any `PROBE_PREFIXES` path (Zanbil runs none of that software).
- **human_proxy**: browser-like UA (`Mozilla/`, no crawler token), requested
  `/basket/add/`, `/basket/checkout` or `/order/create`, and requested at least one
  `/image/` or `/static/` asset. Actors touching `/orderAdministration/` are
  split out as **staff** and reported separately.
- Any actor matching both a bot label and human_proxy is a **conflict**: counted, then excluded.

Tests:
- **B1a** verified crawlers, logs as they are (sanity: UA rules should catch them).
- **B1b** verified + fake crawlers with **every UA replaced by the fixed Chrome UA**:
  can behaviour alone catch real crawlers?
- **B1c** probe bots with **their probe requests removed** (actors left with no requests are counted apart).
- **B1d** human_proxy and staff false-positive rates, logs as they are.

### B2: AIT Log Data Set V2.0 (doi:10.5281/zenodo.5789064)

Apache access logs and labels for all 8 testbeds, pulled with range requests
(no full 7-26 GB download). Actor = client IP per testbed. Bot = any access-log
line of that IP labeled as an attack. Everything else = simulated user or
infrastructure (AIT's simulation, independent of this project).
There are only ~8 attacker IPs in total, so by rule 1 bot recall is
**inconclusive**: each attack chain is reported as a case study (which
detector flagged it, at which request). Human FPR is pooled with CI.

## Suite C: performance

Informational, no pass/fail. The one reference target is the existing how-to's
**p99 under 20 ms** for `/check`. Measured on this machine (hardware recorded):
- `/check` p50/p95/p99 and req/s at concurrency 1/10/50, 20 000 requests,
  each from one of 5 000 rotating IPs.
- `serve` RSS and Redis `used_memory` after 10 000 distinct actors.
- `scan_logfile` lines/s on a 1M-line Zanbil slice.
- Per-prediction time: micrograd `BotDetector.predict` vs sklearn `predict_proba`.

## Suite D: model track

- **Train:** `default` config, seeds 1-2. Bots at L0-L2 plus all humans of those runs.
  Rows are per-request feature vectors from the archive, at most 20 per actor
  (the approach in `scripts/lab/retrain_from_lab.py`). Normalization is fitted on
  training rows only.
- **Test:** `default` config, seeds 3-5, **all** levels (L3-L5 never seen in
  training). Also AIT (B2) as a cross-dataset check, reported as case studies.
- **Models:** shipped; micrograd retrained (`BotDetector.train_until_it_learns`,
  must pass `check_not_degenerate`); sklearn `LogisticRegression(max_iter=1000,
  class_weight="balanced")`; sklearn `RandomForestClassifier(n_estimators=200,
  random_state=0)`.
- **Actor score** = max over its requests. Report ROC-AUC and average precision with
  actor-bootstrap 95% CIs, recall at 0.5, marginal catches, added human FPs.
- **Ablation:** retrain without `ua_category`, `has_accept_language`, `header_consistency_score`.
- **Leakage guard:** before training, the training rows must have no feature
  that separates the classes perfectly with a single threshold. If one
  does, it is reported and the model is also trained without it.

Replacing `data/model.json` is out of scope whatever the result.
