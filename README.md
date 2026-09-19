# 🔍 Microguard

**Bot Traffic Audit Tool powered by micrograd** · v2.0.0-beta

Detect malicious bot traffic in your API logs and live endpoints. Zero external dependencies beyond micrograd.

> **Beta:** trained on real ground-truth attack data (not synthetic) and now
> [benchmarked](docs/results/2026-09-benchmark.md) against baselines on bots at
> rising evasion levels and on real public logs. The rules beat every baseline
> with zero human false positives — but the results also pin down where it
> breaks (the shipped blend threshold, and a high false-positive rate for the
> offline `scan` on real e-commerce traffic). Read the [Benchmarks](#benchmarks)
> summary and [Known Limitations](#known-limitations-read-before-relying-on-this-for-production-blocking)
> before using this as a production blocking gate.

```
$ microguard scan access.log

  Microguard Bot Traffic Report
  ─────────────────────────────

  🚨 Bot Traffic: 50.0%  CRITICAL

  Total sessions:  4
  Human sessions:  2
  Bot sessions:    2

  █████░░░░░  50.0%

  IP                 Score Bar          Risk      Label    Reqs    Dur Heuristic Rule
  ─────────────────────────────────────────────────────────────────────────────────────
  10.0.0.50          0.95 █████████░ DANGER    bot     1   0.0s known bot/monitoring UA
  192.168.1.100      0.39 ███░░░░░░░ LOW       human     5  34.0s known browser, reasonable session
```

## Features

- **19 HTTP-level features** for bot detection (timing, behavioral, header analysis) from real access logs — REST-style, path-per-resource traffic
- **Single-endpoint API aware** — GraphQL, SOAP, RPC, and gRPC traffic is exempted from the "same endpoint = scraper" heuristics that would otherwise flag every legitimate client of a single-endpoint API
- **Webhook/integration allowlist** — recognized senders (Stripe, GitHub, Shopify, ...) are labeled `automated-integration`, not scored as malicious bots
- **24+ heuristic rules** across 4 confidence tiers (Cloudflare WAF, API key, botnet detection)
- **micrograd neural network** — 85 parameters, ~1.8KB model size, trained on real ground-truth-labeled attack traffic + real human sessions (see [Model Training](#model-architecture))
- **Live URL probing** — fingerprints how automated/hardened an HTTP or WebSocket endpoint looks from a single probe. This is *not* visitor classification (it scores the tool's own request against the target, not third-party traffic) — use `scan` against access logs for that
- **Continuous monitoring** — watch mode tails log files in real time
- **Real-time blocking** — nginx auth_request server or in-process ASGI/WSGI middleware blocks bots at the edge before they reach your app
- **Web dashboard** — `microguard dashboard` serves a TypeScript UI on localhost: live blocking decisions as they happen, an interactive scan explorer, and the model's evaluation. Bundled with the package; no Node needed to run it
- **Multiple output formats** — terminal, JSON, colored JSON, and HTML reports
- **Auto-generated firewall rules** — nginx deny-list or Cloudflare Firewall Rule expression for DANGER-scored IPs
- **Score interpretation** — SAFE / LOW / WARNING / DANGER risk labels
- **Zero external dependencies** — only requires micrograd (the WebSocket probe hand-rolls the RFC 6455 handshake over stdlib `socket`/`ssl` rather than pulling in a client library)

## Benchmarks

Microguard is measured against the alternatives an operator would actually
deploy — a User-Agent blocklist, a rate limit, a path blocklist, and
[CrowdSec](https://crowdsec.net) — on the **same bots at rising levels of
evasion** (`L0` announces itself; `L5-farm` is a real headless-Chromium bot
pacing like a human across ten IPs), plus two real public logs. Every grading
rule was fixed **before any run** in
[`benchmarks/PREREGISTRATION.md`](benchmarks/PREREGISTRATION.md); the full
methodology, tables with confidence intervals, and the pre-registration grading
are in [**the benchmark report**](docs/results/2026-09-benchmark.md).

**The evasion ladder** — recall (bots caught) by evasion level, default config,
pooled over 5 seeds, exact ground truth:

| detector | L0 | L1 | L2 | L3 | L4 | L5 | L5-farm | human FP |
|---|---|---|---|---|---|---|---|---|
| UA blocklist | 89% | 0% | 0% | 0% | 0% | 0% | 0% | 0/175 |
| rate limit | 11% | 11% | 11% | 0% | 0% | 0% | 0% | 0/175 |
| CrowdSec | 18% | 20% | 20% | 30% | 48% | 40% | 0% | 0/175 |
| **microguard (rules)** | **100%** | **100%** | **100%** | **100%** | **75%** | **100%** | **0%** | **0/175** |
| microguard (blend, shipped) | 100% | 44% | 44% | 33% | 25% | 33% | 0% | 0/175 |

![Evasion ladder](docs/results/figures/ladder-default.svg)

What the numbers say, honestly:

- **The rules beat every baseline.** The moment a bot spoofs a browser
  User-Agent, a UA blocklist drops to 0% and a rate limit to ~11%, while
  microguard's rules hold 100% recall through L5 (75% at L4) at **zero human
  false positives**.
- **The shipped 0.85 blend leaves recall on the table.** Its floor/cap means
  only high-confidence (0.90+) rules clear the bar, so the blend catches 44%
  at L1 where the rules catch 100%. If you run microguard, trust the rule
  labeler or lower the threshold.
- **The distributed browser farm is the blind spot.** Volume and path
  heuristics catch 0% of a low-and-slow farm sharing one browser profile across
  ten IPs. Promoting the fingerprint signal recovers 22% — but at a 6% human
  false-positive cost (it flags clients that don't run JavaScript), so it is not
  yet safe to block on. A micrograd model *retrained* on the live distribution
  recovers the whole farm with zero added false positives (on cleanly-separable
  simulated humans — an upper bound, see below).
- **On real e-commerce traffic** (Zanbil, 10.3M real nginx lines): behaviour
  alone catches **31%** of crawlers whose UA is disguised as Chrome (a UA
  blocklist catches 0%) — but `microguard scan` flags **57% of real human
  shoppers** as bots, because real sessions make 100+ requests on image-heavy
  pages and trip the volume rules. This false-positive rate is the one the
  synthetic lab could not show.

**Honest limits:** the lab's humans are simulated (real headless browsers, but
scripted intent); only the Zanbil human labels are real, and they are proxies.
The live check server also ignores the forwarded `Referer`, so referer rules are
inert on the live path. The benchmark report spells all of this out.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/microguard.git
cd microguard

# Install in development mode
pip install -e .

# Or install directly
pip install .
```

### Requirements

- Python 3.10+ (the codebase uses `X | Y` union type hints throughout)
- [micrograd](https://github.com/karpathy/micrograd) (installed automatically)

## Documentation

Full docs live in [`docs/`](docs/README.md), organized by what you are trying to
do. The fastest ways in:

| If you want to… | Read |
|---|---|
| Find bots in a log file | [Your first scan](docs/tutorial-first-scan.md) |
| Block bots in real time | [Block your first bot](docs/tutorial-real-time-blocking.md) |
| Watch decisions in a browser | [Watch a bot get blocked](docs/tutorial-the-dashboard.md) |
| Look up a flag or a payload | [CLI reference](docs/reference-cli.md) · [Live API reference](docs/reference-live-api.md) |
| Understand a verdict | [The heuristic rules](docs/reference-heuristic-rules.md) · [The 19 features](docs/reference-features.md) |
| Judge whether to trust it | [How detection works](docs/explanation-how-detection-works.md) · [Where the labels come from](docs/explanation-training-data.md) |

## Quick Start

```bash
# Run with no arguments — auto-scans a sample log file
microguard

# Scan your own logs
microguard scan /var/log/nginx/access.log

# Probe a live URL
microguard probe https://example.com

# Watch mode — continuously monitor a log file
microguard scan access.log --watch
```

### Scan a Log File

```bash
# Basic scan
microguard scan /var/log/nginx/access.log

# Verbose output (feature vectors + heuristic rules)
microguard scan access.log --verbose

# Colored JSON for terminal reading
microguard scan access.log --json-pretty

# Machine-readable JSON
microguard scan access.log --output json

# Save HTML report
microguard scan access.log --output html --output-file report.html

# Adjust bot threshold (default: 0.7)
microguard scan access.log --threshold 0.5
```

### Generate Firewall Rules

Emit a ready-to-use block list for IPs scored DANGER (0.80-1.00) — nothing to
review by hand, just drop it into your infra:

```bash
# nginx deny-list (include in a server block)
microguard scan access.log --output nginx --output-file blocklist.conf

# Cloudflare Firewall Rule expression
microguard scan access.log --output cloudflare
# → (ip.src in {10.0.0.50 203.0.113.7})
```

Both formats dedupe and sort IPs, and print a clean "nothing to block"
message instead of an empty rule when no session scores DANGER.

### Probe a Live URL

`probe` fingerprints how automated/hardened a *target* looks from a single
live request — it does not classify third-party visitors (it can't: it's
this tool making the request and reading the response, not observing who
else calls the endpoint). Use `scan` against access logs to classify real
visitor traffic.

```bash
# Single HTTP(S) probe
microguard probe https://example.com

# Multiple probes for timing analysis
microguard probe https://example.com --count 5

# Verbose probe (full feature breakdown)
microguard probe https://example.com --verbose

# Save results as HTML
microguard probe https://example.com --output html --output-file probe.html

# Custom User-Agent
microguard probe https://example.com --user-agent "MyBot/1.0"

# WebSocket handshake + one-frame probe (ws:// or wss://)
microguard probe wss://example.com/socket
```

### Continuous Monitoring

```bash
# Watch a log file for new bot traffic
microguard scan access.log --watch

# Lower threshold for more sensitivity
microguard scan access.log --watch --threshold 0.5
```

### Real-Time Blocking

Block bots at the edge before they reach your app. Two deployment options:

#### nginx auth_request (recommended for nginx stacks)

```bash
# Start the check server
microguard serve --port 8400 --redis-url redis://localhost:6379

# nginx config — add to your server block:
#   location /api/ {
#       auth_request /_microguard_check;
#       auth_request_set $microguard_label $upstream_http_x_microguard_label;
#       proxy_set_header X-Microguard-Label $microguard_label;
#       proxy_pass http://backend;
#   }
#
#   location = /_microguard_check {
#       internal;
#       proxy_pass http://127.0.0.1:8400/check;
#       proxy_pass_request_body off;
#       proxy_set_header Content-Length "";
#       proxy_set_header X-Original-URI $request_uri;
#       proxy_set_header X-Original-Method $request_method;
#       proxy_set_header X-Real-IP $remote_addr;
#       proxy_set_header User-Agent $http_user_agent;
#       proxy_set_header Referer $http_referer;
#       # Drop client-supplied X-Forwarded-For. Sessions are keyed on the
#       # client IP, so a spoofable value lets a bot get a fresh session
#       # per request and never build a detectable history.
#       proxy_set_header X-Forwarded-For "";
#   }
```

#### In-process middleware (FastAPI / Flask)

```python
# FastAPI
from fastapi import FastAPI
from microguard.live.middleware import MicroguardASGI

app = FastAPI()
app.add_middleware(
    MicroguardASGI,
    redis_url="redis://localhost:6379",
    block_threshold=0.85,
)

# Flask
from flask import Flask
from microguard.live.middleware import MicroguardWSGI

app = Flask(__name__)
app.wsgi_app = MicroguardWSGI(
    app.wsgi_app,
    redis_url="redis://localhost:6379",
    block_threshold=0.85,
)
```

Every block/allow decision returns the full breakdown, not just a verdict:

```json
{
  "ip": "203.0.113.10",
  "label": "bot",
  "score": 0.95,
  "model_score": 0.87,
  "heuristic_label": "bot",
  "heuristic_confidence": 0.95,
  "heuristic_reason": "vulnerability scanner pattern detected",
  "request_count": 4,
  "duration": 1.82,
  "model_loaded": true
}
```

The same fields travel as `X-Microguard-Label`, `-Score`, `-Model-Score`,
`-Heuristic` and `-Reason` headers, so an nginx `auth_request_set` or a wrapped
app can forward them upstream. `score` is what the decision used; `model_score`
and `heuristic_confidence` tell you which half drove it, which is what you need
to tune the threshold or explain a block to a customer.

The default block threshold is **0.85**. The blend floors a confident heuristic
rule at its own confidence, so the threshold decides which rules can block
unaided: at 0.85 only the 0.90-0.95 rules do (known bot UA, scanner paths,
attack tools, uniform timing, HTTP/1.0-only), while weaker signals like "all
requests to one endpoint" (0.80) and "high request rate" (0.75) need the model
to agree. Those weaker rules also describe a legitimate polling client or a
single-endpoint GraphQL app, which is why they do not get to block on their own.

**Live-path documentation:** [tutorial](docs/tutorial-real-time-blocking.md) ·
[deploy behind nginx](docs/howto-deploy-behind-nginx.md) ·
[deploy in-process](docs/howto-deploy-in-process.md) ·
[tune blocking](docs/howto-tune-blocking.md) ·
[API reference](docs/reference-live-api.md) ·
[how it works](docs/explanation-how-blocking-works.md)

**Everything else:** [the documentation index](docs/README.md).

Two settings matter before you deploy:

- **`trust_forwarded_for` is off by default.** The client IP comes from
  `X-Real-IP` or the transport peer, never from the client-supplied
  `X-Forwarded-For`. Sessions key on that IP, so a spoofable value lets a bot get
  a fresh session per request and never build a detectable history. Turn it on
  only behind a proxy that overwrites the header.
- **The block threshold defaults to 0.85.** Only the highest-confidence rules
  block on their own; weaker signals need the model to agree. See
  [tuning](docs/howto-tune-blocking.md).

If Redis is unreachable, all three entrypoints fail open: the request is allowed
and logged rather than turned into a 500 for a real visitor.

Install with: `pip install microguard[live,fastapi]` or `pip install microguard[live,flask]`

#### Options

```
--host TEXT              Bind address (default: 127.0.0.1)
--port INT               Listen port (default: 8400)
--redis-url TEXT         Redis connection URL (default: redis://localhost:6379)
--block-threshold FLOAT  Score above which requests are blocked (default: 0.85)
--session-ttl INT        Session expiry in seconds (default: 1800)
```

Headers returned by the server:
- `X-Microguard-Label`: `human` or `bot`
- `X-Microguard-Score`: float score (0.0–1.0)

## Dashboard

```bash
pip install 'microguard[dashboard,live]'
microguard dashboard          # http://127.0.0.1:8500
```

Three tabs, one page:

- **Live** — every decision the check server and the middleware made, streamed over
  SSE. Each row plots what the rules said, what the model said, where the blend
  landed, and where the threshold sat, on one scale. Two states that quietly change
  every verdict — no model loaded, and failing open — are called out rather than
  buried.
- **Scan** — drop in an access log or pick a bundled sample, then move the bot
  threshold and watch the verdicts re-slice without re-parsing. Every session opens
  to its 19 features and the rule that fired. Exports the same JSON, HTML, nginx and
  Cloudflare output the CLI produces.
- **Model** — the 19 → 4 → 1 network, what each input contributes, and a confusion
  matrix, ROC and score distribution that move with the threshold.

The dashboard binds loopback and has no accounts. With `--allow-config-writes` it
can move the live block threshold — every scoring process sharing that Redis picks
the change up within seconds, with no restart. Use `--token` if it has to be
reachable from elsewhere.

**Building the UI from a source checkout** (a pip install already ships it):

```bash
cd gui && npm ci && npm run build
```

See [watch a bot get blocked](docs/tutorial-the-dashboard.md) for a walk-through,
[how to run the dashboard](docs/howto-run-the-dashboard.md) for the reference,
and [working on the UI](docs/howto-work-on-the-gui.md) if you are changing it.

## Score Interpretation

| Score Range | Risk Level | Meaning |
|-------------|------------|---------|
| 0.00 - 0.30 | **SAFE** | No bot signals detected |
| 0.31 - 0.59 | **LOW** | Minor signals, likely human |
| 0.60 - 0.79 | **WARNING** | Suspicious, investigate |
| 0.80 - 1.00 | **DANGER** | High confidence bot traffic |

Sessions from a recognized webhook/integration sender (Stripe, GitHub,
Shopify, ...) get a separate `automated-integration` label instead of a
score — they're automated by definition, not a security threat, so they're
excluded from bot-rate counts entirely rather than forced into bot/human.

## CLI Reference

```
microguard scan <logfile> [OPTIONS]
microguard probe <url> [OPTIONS]
microguard serve [OPTIONS]
microguard info
```

### Scan Options

```
  -f, --format {auto,nginx,json}     Log file format (default: auto-detect)
  -t, --threshold FLOAT              Bot score threshold (default: 0.7)
  -m, --model PATH                   Path to pre-trained model file
  -o, --output {terminal,json,html,  Output format (default: terminal).
      nginx,cloudflare}              nginx/cloudflare emit a firewall
                                      rule for DANGER-scored IPs.
  -O, --output-file PATH             Write report to file instead of stdout
  --timeout INT                      Session timeout in minutes (default: 30)
  -v, --verbose                      Show feature vectors and heuristic rules
  -j, --json-pretty                  Colored JSON for terminal reading
  -w, --watch                        Continuously monitor log file
```

### Probe Options

```
  -n, --count INT                   Number of probes to send (default: 3)
  -d, --delay FLOAT                 Delay between probes in seconds (default: 0.5)
  --method {GET,POST,HEAD,OPTIONS}  HTTP method (default: GET)
  -t, --threshold FLOAT             Bot score threshold (default: 0.7)
  -m, --model PATH                  Path to pre-trained model file
  -o, --output {terminal,json,html} Output format (default: terminal)
  -O, --output-file PATH            Write report to file instead of stdout
  --timeout FLOAT                   Request timeout in seconds (default: 10)
  --no-verify-ssl                   Disable SSL certificate verification
  --user-agent TEXT                 Custom User-Agent header
  -v, --verbose                     Show feature vectors and heuristic rules
  -j, --json-pretty                 Colored JSON for terminal reading
```

### Python API

```python
from microguard import scan_logfile, probe_and_analyze, BotDetector

# Scan a log file
results = scan_logfile(
    filepath="access.log",
    fmt="auto",
    threshold=0.7,
    model_path="microguard/data/model.json",
)
print(f"Bot rate: {results['bot_rate']:.1%}")

# Probe a live URL
results = probe_and_analyze(
    url="https://example.com",
    count=3,
    delay=0.5,
    threshold=0.7,
    verbose=True,
)
print(f"Score: {results['combined_score']:.2f} ({results['label']})")

# Load and use the model directly
model = BotDetector("microguard/data/model.json")
features = [...]  # 19-dimensional feature vector
score = model.predict(features)  # 0.0 to 1.0
```

## Architecture

```mermaid
graph TB
    subgraph CLI["🔍 Microguard CLI"]
        S[scan] --> P[parser.py]
        PR[probe] --> SC[scanner.py]
        W[watch] --> WT[watch.py]
    end

    P --> F[features.py<br/>19 extractors]
    SC --> F
    WT --> F

    F --> L[labeler.py<br/>24 heuristic rules]
    F --> M[model.py<br/>MLP 19→4→1]

    L --> SF[Score Fusion<br/>60% model + 40% heuristic]
    M --> SF

    SF --> R[report.py]
    R --> T1[Terminal<br/>ANSI colors + score bars]
    R --> T2[JSON<br/>machine-readable]
    R --> T3[JSON Pretty<br/>colored for terminal]
    R --> T4[HTML<br/>dark theme + charts]
    R --> T5[Verbose<br/>feature vectors + rules]

    style CLI fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style F fill:#8b5cf6,stroke:#a78bfa,color:#fff
    style L fill:#f59e0b,stroke:#fbbf24,color:#000
    style M fill:#10b981,stroke:#34d399,color:#fff
    style SF fill:#ef4444,stroke:#f87171,color:#fff
    style R fill:#3b82f6,stroke:#60a5fa,color:#fff
```



### Data Flow

```mermaid
graph TB
    IN["📥 Log File / Live URL"] --> PAR["Parsing Layer<br/>Nginx / JSON / HTTP"]
    PAR --> FEAT["Feature Extraction<br/>19 features: timing + behavioral + header + payload + context"]
    
    FEAT --> HEUR["Heuristic Rules<br/>24 patterns, confidence 0-1"]
    FEAT --> ML["micrograd MLP<br/>85 params, score 0-1"]
    
    HEUR --> FUSION["Score Fusion<br/>60% model + 40% heuristic"]
    ML --> FUSION
    
    FUSION --> OUT["Output Layer<br/>Terminal / JSON / HTML / Verbose"]
    
    style IN fill:#64748b,stroke:#94a3b8,color:#fff
    style PAR fill:#3b82f6,stroke:#60a5fa,color:#fff
    style FEAT fill:#8b5cf6,stroke:#a78bfa,color:#fff
    style HEUR fill:#f59e0b,stroke:#fbbf24,color:#000
    style ML fill:#10b981,stroke:#34d399,color:#fff
    style FUSION fill:#ef4444,stroke:#f87171,color:#fff
    style OUT fill:#3b82f6,stroke:#60a5fa,color:#fff
```

## Heuristic Rules (24 patterns)

### High Confidence (0.90-0.99)
- Known bot/monitoring user agents (80+ patterns)
- Vulnerability scanner URL patterns (`/wp-admin`, `/phpmyadmin`, etc.)
- Uniform timing patterns (all requests within 1ms)
- HTTP/1.0-only clients
- Cloudflare WAF bypass detection
- Attack tool signatures (Nuclei, ffuf, Masscan, etc.)
- Botnet scanning patterns (Mirai, IoT endpoints)

### Medium Confidence (0.70-0.89)
- High request rates (>100 requests, >50 req/min)
- Same-endpoint scraping (>10 requests to same URL)
- No referrer on all requests (>20 requests)
- High error rate (>50% failed requests)
- Repeated API endpoint abuse
- API key parameter scanning (`?key=`, `?token=`, `?api_key=`)
- Credential brute-force (rapid auth endpoint hits)
- Directory brute-force (70%+ 403/404 responses)
- UA rotation (distributed attacks)

### Low Confidence (0.55-0.69)
- Unknown user agents
- Short fast sessions (<5s, >20 requests)
- Night-time activity patterns

### Human Signals (0.55-0.75)
- Known browser user agents with normal behavior
- Variable timing patterns (high CV)
- Multiple different endpoints explored
- Natural referrer chains
- Behind Cloudflare with normal browser

## Model Architecture

```mermaid
graph LR
    A["Input<br/>19 features"] -->|19×4 + 4| B["Linear + ReLU<br/>76 params"]
    B -->|4×1 + 1| C["Linear + Logit<br/>5 params"]
    C --> D["Score<br/>0.0 - 1.0"]

    style A fill:#8b5cf6,stroke:#a78bfa,color:#fff
    style B fill:#3b82f6,stroke:#60a5fa,color:#fff
    style C fill:#10b981,stroke:#34d399,color:#fff
    style D fill:#f59e0b,stroke:#fbbf24,color:#000
```

| Property | Value |
|----------|-------|
| Architecture | MLP 19 → 4 → 1 |
| Parameters | 85 |
| Model size | ~1.8KB |
| Inference time | < 0.5ms per request |

### Model Training

The bot class is trained on **real, ground-truth-labeled attack traffic**,
not synthetic data: `microguard/training/build_real_dataset.py` extracts
sessions from a real production Apache log (`data/zenodo_data/organization-x/`)
and labels them using that dataset's own forensic ground-truth rules (SQL
injection, RCE, directory scanning, brute-force login, etc. — see
`microguard/training/groundtruth.py`), falls back to the heuristic labeler
for the rest of that real traffic, and uses real human session timing data
from the Harvard Dataverse dataset for the human class. A capped, clearly-
tagged synthetic top-up fills in attack subtypes underrepresented in the
real data. Retrain with:

```bash
python -m microguard.training.build_real_dataset   # builds data/real_bot_training_data.json
python -m microguard.training.train                # trains + writes data/eval_holdout.json
```

Accuracy is reported two ways — `tests/test_training_quality.py::TestModelAccuracy`
is a train-set fit sanity check (expect it to look near-perfect; that's not
a generalization claim), while `TestHeldOutAccuracy` evaluates the model on
sessions carved out *before* training even started, split so no single
actor's sessions appear on both sides — including a recall check isolated
to the organization-x forensic ground-truth labels specifically, since
that's the one label source in this dataset that's fully independent of
the model's own input features.

## File Structure

```
microguard/
├── setup.py                    # Package installation
├── README.md                   # This file
├── LICENSE                     # MIT License
├── .github/workflows/test.yml  # CI: tests on push/PR
├── microguard/
│   ├── __init__.py             # Package exports
│   ├── cli.py                  # CLI entry point (scan, probe, watch, serve, info)
│   ├── parser.py               # Nginx + JSON log parsers (transparent .gz support)
│   ├── features.py             # 19 feature extractors
│   ├── labeler.py              # 24+ heuristic bot/human/automated-integration rules
│   ├── model.py                # micrograd MLP wrapper (85 params)
│   ├── scanner.py              # HTTP + WebSocket live probing (automation fingerprint)
│   ├── scoring.py              # Shared heuristic/model score blending (single source of truth)
│   ├── watch.py                # Continuous log monitoring
│   ├── report.py               # Terminal + JSON + HTML + Verbose output
│   ├── live/
│   │   ├── __init__.py         # Import guard (requires redis)
│   │   ├── state.py            # LiveSession + SessionStateStore Protocol
│   │   ├── redis_store.py      # Redis-backed session state (JSON + TTL)
│   │   ├── scorer.py           # LiveScorer — real-time request scoring
│   │   ├── server.py           # nginx auth_request HTTP server
│   │   └── middleware.py       # ASGI + WSGI middleware (FastAPI / Flask)
│   └── training/
│       ├── train.py            # Model training + held-out split/eval
│       ├── generate.py         # Synthetic bot/human data (top-up only)
│       ├── groundtruth.py      # organization-x forensic rule matcher
│       └── build_real_dataset.py  # Builds the real (+capped synthetic) training set
├── tests/
│   ├── conftest.py             # Shared LogEntry/Session/log-file fixtures
│   ├── test_cli.py             # 20 tests (scan_logfile + main() end-to-end)
│   ├── test_parser.py          # 19 tests
│   ├── test_features.py        # 21 tests
│   ├── test_labeler.py         # 7 tests
│   ├── test_labeler_rules.py   # 19 tests (Cloudflare, API key, botnet, single-endpoint APIs)
│   ├── test_model.py           # 7 tests
│   ├── test_scanner.py         # 16 tests
│   ├── test_scanner_extended.py # 13 tests
│   ├── test_scanner_ws.py      # 15 tests (WebSocket probe + RFC 6455 framing)
│   ├── test_groundtruth.py     # 16 tests
│   ├── test_training_quality.py # 38 tests (train-set fit + held-out generalization)
│   ├── test_report.py          # 45 tests
│   ├── test_watch.py           # 12 tests (incl. watch_logfile() end-to-end)
│   └── live/
│       ├── test_redis_store.py # 13 tests (real Redis, skip if unavailable)
│       ├── test_scorer.py      # 10 tests (in-memory store)
│       ├── test_server_integration.py # 7 tests (subprocess + real HTTP)
│       └── test_middleware.py  # 6 tests (ASGI + WSGI, in-memory store)
└── data/
    ├── model.json                    # Pre-trained model weights (1.8KB)
    ├── normalization.json            # Feature normalization params
    ├── eval_holdout.json             # Held-out generalization eval set (never trained on)
    ├── real_bot_training_data.json   # Real ground-truth + heuristic + capped synthetic bot data
    ├── harvard_training_data.json    # Real human session timing data
    ├── zenodo_data/organization-x/   # Real Apache logs + forensic ground-truth rules
    └── sample_access.log             # Example log file (auto-scanned on first run)
```

## Testing

```bash
# Run all tests (264 tests)
python -m pytest tests/

# Run with verbose output
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_features.py

# Run live tests (requires Redis)
python -m pytest tests/live/

# Coverage report (pip install pytest-cov first — dev-only, see requirements-dev.txt)
pytest --cov=microguard --cov-report=term-missing
```

**Test coverage:** 264 tests (264 passing when Redis available; 20 skipped
without Redis for live tests). Line coverage baseline: **71%**
(no hard CI gate yet — `cli.py` and `watch.py`, previously untested at the
integration level, are now at 85%/83%; `training/*.py` scripts are at 0%
since they're one-shot data pipelines validated by manual runs, not unit
tests). Shared `LogEntry`/`Session`/log-file fixtures live in
`tests/conftest.py` — reuse them in new tests instead of hand-rolling
another builder.

## CI/CD

GitHub Actions workflow runs on every push and PR:

- **Matrix:** 3 OS (ubuntu, macOS, Windows) × 6 Python versions (3.8–3.13)
- **Steps:** Install → pytest → CLI smoke test
- **Config:** `.github/workflows/test.yml`

## Known Limitations (read before relying on this for production blocking)

This is a v2.0 beta: the architecture is real and the detection is trained
on real data, but it has not been adversarially tested. Specifically:

- **Sophisticated bots: now measured, with mixed results.** The
  [evasion-ladder benchmark](docs/results/2026-09-benchmark.md) drives the same
  bots at rising evasion levels up to a real headless-Chromium farm. The rule
  labeler holds 100% recall through browser-UA-spoofing and human pacing (L1–L3)
  and 75–100% against a real browser (L4–L5) at zero human false positives — but
  the **distributed browser farm** (one profile across ten IPs, low volume each)
  evades the rules entirely (0%), and the **shipped 0.85 blend** catches far less
  than the rules alone. So there is now real evidence: microguard's rules are
  strong against evasive-but-noisy bots and blind to the low-and-slow distributed
  case. The old synthetic `data/adversarial_eval.json` number is superseded by
  this; treat the ladder as the reference.
- **The model now trains on real human traffic.** It used to learn the human
  class from one file whose feature columns were constant placeholders — a leak
  that made the shipped model score **ROC-AUC 0.34 on real traffic** (worse than
  chance). The human class is now real Zanbil shopper sessions extracted the
  same way as the bots; on held-out real traffic the model scores **AUC 0.97,
  catching 70% of real bots at zero human false positives**, and the three
  dataset-integrity leakage guards now pass. Full account, with caveats (proxy
  labels, one e-commerce site, an offline-scan-first model):
  [A realistic model, trained on real human traffic](docs/results/2026-09-realistic-model.md).
- **gRPC and webhook traffic are labeled `automated-integration`, not
  bot/human.** Correct in spirit (neither has a human operator), but it
  means microguard doesn't attempt bot-vs-human classification for those
  protocols at all — by design, not oversight.
- **`probe` fingerprints a target, it doesn't classify visitors.** Live
  HTTP/WebSocket probing scores how automated/hardened the *target* looks
  from this tool's own request — it cannot see or classify third-party
  traffic. Only `scan` (against real access logs) does that.
- **Default `--threshold 0.7` is validated, not scientifically optimal.**
  On held-out real data, the model's own raw score clusters narrowly
  (~0.35–0.73) — the heuristic layer's floor/cap does most of the
  decisive work near that boundary. Validate against your own traffic
  before using this as an automated blocking gate.
- **GraphQL/SOAP endpoint differentiation only works for GET+query-param
  patterns.** Standard access logs never capture a POST body, so most real
  GraphQL/SOAP traffic (POST, JSON/XML body) can't be operation-differentiated
  from logs alone — the single-endpoint-path exemption is the real fix for
  those, not per-operation tracking.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`python -m pytest tests/`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [micrograd](https://github.com/karpathy/micrograd) — The tiny autograd engine that makes this possible
- [Nescio98](https://github.com/Nescio98/Machine-Learning-Model-for-Bot-Detection) — Research on HTTP-level bot detection features
- [Harvard Dataverse](https://dataverse.harvard.edu/) — Web server access log datasets
- Organization X (Zenodo) — Real, ground-truth-labeled Apache attack-traffic dataset used to train the bot class on genuine forensic labels instead of synthetic data

---

**Powered by micrograd** 🧠
