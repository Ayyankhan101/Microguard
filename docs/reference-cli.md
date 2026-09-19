# CLI reference

Every command, flag, exit code, and output format. Microguard's entry point is
`microguard` (`microguard.cli:main`); each command is also reachable as a Python
function, noted per section.

```
microguard scan <logfile> [options]      Analyze an access log
microguard probe <url> [options]         Fingerprint a live endpoint
microguard serve [options]               nginx auth_request check server
microguard dashboard [options]           Web UI and its API
microguard info                          Version and feature summary
microguard                               Auto-scan the bundled sample
```

## `microguard scan`

Groups a log file into sessions, scores each one, and prints a report.

```bash
microguard scan data/sample_access.log
```

| Flag | Type | Default | Effect |
|---|---|---|---|
| `logfile` | path | required | Log to analyze. `.gz` is decompressed transparently. |
| `--format`, `-f` | `auto` \| `nginx` \| `json` | `auto` | Log format. `auto` reads up to 10 lines to decide. |
| `--threshold`, `-t` | float | `0.7` | Blended score at or above which a session is labeled `bot`. |
| `--model`, `-m` | path | `microguard/data/model.json` | Trained model. Missing or unreadable means heuristics only. |
| `--output`, `-o` | `terminal` \| `json` \| `html` \| `nginx` \| `cloudflare` | `terminal` | Report format. |
| `--output-file`, `-O` | path | stdout | Write the report to a file instead of stdout. |
| `--timeout` | int | `30` | Session gap in minutes. A larger gap starts a new session for the same IP. |
| `--verbose`, `-v` | flag | off | Per-session dump: all 19 features and the rule that fired. |
| `--json-pretty`, `-j` | flag | off | ANSI-colored JSON-shaped output for reading. **Not parseable JSON.** |
| `--watch`, `-w` | flag | off | Tail the file instead of scanning it once. See [monitoring a log](howto-monitor-a-log-in-real-time.md). |

**Flag precedence.** These are checked in order, and an earlier one silently wins:

```
--watch  >  --verbose  >  --json-pretty  >  --output-file  >  --output
```

So `--verbose --output html` prints the verbose terminal dump, not HTML, and
`--json-pretty --output-file report.txt` prints to stdout and writes nothing.
Pass one at a time.

**Output streams.** Progress goes to stderr (`📂 Parsing…`, `📊 Found N log
entries`, `👥 Grouped into N sessions`, and whether a model loaded). The report
goes to stdout. So this works:

```bash
microguard scan access.log --output json 2>/dev/null | jq '.bot_rate'
```

**Exit codes.**

| Code | Meaning |
|---|---|
| `0` | Scan completed, bot rate at or below 10% |
| `1` | Bot rate above 10%, **or** the log file does not exist, **or** the report could not be written |

Exit 1 does not distinguish "found bots" from "crashed". In CI, check stdout for
a traceback rather than relying on the code.

**Python API.** `microguard.cli.scan_logfile(filepath, fmt='auto',
threshold=0.7, model_path=DEFAULT_MODEL_PATH, timeout_minutes=30) -> dict`.
Returns the dict every formatter consumes; see [Scan result](#scan-result-schema).

## `microguard probe`

Fingerprints how automated or hardened a live endpoint looks. Accepts `http://`,
`https://`, `ws://`, `wss://`; the scheme selects the prober.

```bash
microguard probe https://example.com --count 5
```

**This does not classify visitors.** A probe is microguard making its own
requests and reading the target's responses. The score describes the target, not
its traffic. Use `scan` on access logs to classify visitors. See
[probing an endpoint](howto-probe-an-endpoint.md).

| Flag | Type | Default | Effect |
|---|---|---|---|
| `url` | URL | required | `http(s)://` or `ws(s)://`. |
| `--count`, `-n` | int | `3` | Probes to send. More than 2 enables timing-consistency analysis. |
| `--delay`, `-d` | float | `0.5` | Seconds between probes. |
| `--threshold`, `-t` | float | `0.7` | Score at or above which the target is labeled `bot`. |
| `--output`, `-o` | `terminal` \| `json` \| `html` | `terminal` | Report format. |
| `--output-file`, `-O` | path | stdout | Write to a file instead. |
| `--verbose`, `-v` | flag | off | Full feature breakdown and per-probe progress. |
| `--json-pretty`, `-j` | flag | off | ANSI-colored JSON-shaped output. Not parseable. |

**Accepted but not wired up:** `--method`, `--model`, `--timeout`,
`--no-verify-ssl`, `--user-agent`. `main()` parses them and never passes them to
the prober, so they have no effect on an HTTP probe. `--model` is inert by
design — the session-trained network has no valid input shape for probe data
(`scanner.py:331`) — the rest are gaps. Do not build on them.

**Exit codes.** `1` when the target is labeled `bot`, `0` otherwise.

**Python API.** `scanner.probe_and_analyze(url, model=None, count=1, delay=0.0,
threshold=0.7, verbose=False) -> dict` and
`scanner.probe_ws_and_analyze(url, count=1, delay=0.0, threshold=0.7,
timeout=10.0, verbose=False) -> dict`.

## `microguard serve`

Starts the nginx `auth_request` check server. Requires Redis and the `live`
extra. Blocks until interrupted. Full detail in the
[live API reference](reference-live-api.md).

| Flag | Type | Default |
|---|---|---|
| `--host` | str | `127.0.0.1` |
| `--port` | int | `8400` |
| `--redis-url` | str | `redis://localhost:6379` |
| `--block-threshold` | float | `0.85` |
| `--session-ttl` | int | `1800` |
| `--deployment-id` | none | Use this deployment's retrained model when one exists. Without it the shipped baseline is always used, and a deployment model on disk is ignored |
| `--trust-forwarded-for` | flag | off |

## `microguard signals`

Resolves external reputation data out of the request path. Needs Redis.

```bash
microguard signals [--redis-url URL] [--interval 300] [--session-ttl 1800]
```

| Flag | Default | What it does |
|---|---|---|
| `--redis-url` | `redis://localhost:6379` | Must be the same Redis the check server uses |
| `--interval` | `300` | Seconds between refresh passes |
| `--session-ttl` | `1800` | Expiry on each written signal record |

Fetches the Tor exit-node list and AWS prefix ranges from their published
keyless endpoints, caches them under `$XDG_CACHE_HOME/microguard` with a
stale-on-failure fallback, and writes a record only for actors that already
have a live session — so the keyspace is bounded by real traffic rather than by
the size of the internet.

Set `ABUSEIPDB_API_KEY` to add AbuseIPDB. Without it that signal is inert and
nothing is broken.

**This process is why the fetches are not in the check server.** nginx turns a
slow `auth_request` into a 500 for the visitor, so a slow feed inside `/check`
would be an outage. If this process dies, records go stale and then expire and
the check server scores without them — degraded, not down.

It writes `mg:v1:signals:heartbeat`, which never expires, so an absent
heartbeat means "never ran" rather than "died an hour ago".

## `microguard explain`

Why one actor got the verdict it did. Read-only, and needs Redis.

```bash
microguard explain <ip> [--redis-url URL] [--promote tor,abuseipdb]
```

| Flag | Default | What it does |
|---|---|---|
| `--promote` | none | Treat these sources as enforced when explaining |

Prints the session, the resolved signals with their promotion state, the bound
fingerprint, and the rule that decided. It reads the session back rather than
recording a request: diagnosis must not change the thing being diagnosed.

The dashboard answers this better when you have a browser. This exists for a
headless box with the dashboard on loopback.

## `microguard evaluate`

How the collected verdicts held up against ground truth built into the site.
Offline: reads files, needs no Redis.

```bash
microguard evaluate --access-log access.log [--access-log access.log-20260917.gz] \
  --collected collected.jsonl --invite-token k7q2 [--invite-token m3x9]
```

| Flag | Default | What it does |
|---|---|---|
| `--access-log` | required | nginx combined log. Repeat for rotated files |
| `--collected` | required | The archive `serve --collect-to` wrote |
| `--invite-token` | required | A `?ref=` value shared privately. Repeat per channel |
| `--redact-ips` | off | Mask IPs in the unlabeled-flagged table (IPv4 last octet, IPv6 past the first three groups), for a report you commit |

An actor is a client IP. It is a **bot** if it requested `/_hp/` or an exploit
probe, a **human** if it arrived with an invite token and posted
`/microguard/fp`, and **unlabeled** otherwise. Its verdict is its highest
score. Prints markdown: actor counts, a fingerprint health line, caught and
flagged counts per threshold (with a honeypot-only column — bots that never
requested a path in the probe list, which narrows but does not eliminate
overlap with the scanner rule, whose patterns are wider), the heuristic
reasons by class, and the unlabeled actors the default threshold would block.
Fewer than 30 labeled actors in either class is reported as inconclusive. See
[howto-evaluate-on-live-traffic.md](howto-evaluate-on-live-traffic.md).

## `microguard retrain`

Fine-tunes the model on one deployment's confirmed corrections.

```bash
microguard retrain --deployment-id <id> [--feedback-dir DIR]
                   [--min-examples 50] [--epochs 20]
```

| Flag | Default | What it does |
|---|---|---|
| `--deployment-id` | *required* | Corrections never mix across ids |
| `--feedback-dir` | `$XDG_DATA_HOME/microguard/feedback` | Where corrections live |
| `--min-examples` | `50` | Refuse to train below this many |
| `--epochs` | `20` | Adaptation, not training from scratch |

Refuses rather than crashing when the data will not support it — fewer than
`--min-examples` corrections, or more than 90% of them one class — and prints
what would change the answer.

**`microguard/data/model.json` is never written.** The retrained model goes beside the
corrections, and `microguard serve --deployment-id <id>` picks it up within
about five seconds with no restart. Rolling back is deleting that one file.

## `microguard dashboard`

Serves the web UI and its API on one port. Requires the `dashboard` extra.
See [running the dashboard](howto-run-the-dashboard.md).

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--host` | str | `127.0.0.1` | Bind address. No authentication by default — binding off loopback exposes every decision. |
| `--port` | int | `8500` | Listen port. |
| `--redis-url` | str | `redis://localhost:6379` | Redis the live path writes to. Unreachable means an empty Live tab; Scan and Model still work. |
| `--token` | str | none | Require this secret in `X-Microguard-Token` on every `/api` request. |
| `--allow-config-writes` | flag | off | Let the dashboard change the live block threshold. |

## `microguard info`

Prints version and a feature summary. No arguments, always exits 0.

## No command

Scans `data/sample_access.log` and prints a short "what just happened"
explainer. Falls back to `--help` if the sample is missing. Always exits 0.

## Scan result schema

Returned by `scan_logfile()` and emitted verbatim by `--output json`.

```jsonc
{
  "total_sessions": 2,
  "bot_count": 1,
  "human_count": 1,
  "integration_count": 0,
  "bot_rate": 0.5,              // bot_count / total_sessions
  "threshold": 0.7,
  "model_used": true,
  "sessions": [
    {
      "ip": "10.0.0.50",
      "score": 0.95,             // blended, this is the one the verdict used
      "model_score": 0.7312,     // the model alone
      "heuristic_label": "bot",  // "bot" | "human" | "automated-integration"
      "heuristic_confidence": 0.95,
      "heuristic_reason": "known bot/monitoring UA: python-requests/2.28.0",
      "label": "bot",
      "request_count": 1,
      "duration": 0.0,           // seconds
      "top_endpoint": "/api/products",   // most common path, query stripped
      "user_agent": "python-requests/2.28.0",  // truncated to 100 chars
      "features": { "time_since_last_request": 0.0, /* …19 keys… */ }
    }
  ],
  "summary": {
    "total_entries": 6, "total_sessions": 2, "bot_sessions": 1,
    "human_sessions": 1, "integration_sessions": 0, "bot_rate": 0.5
  }
}
```

Two things to handle:

- **`sessions` is unsorted.** Each formatter sorts it; a consumer must too.
- **The error variant drops keys.** A missing file or an unparseable log returns
  a shorter object with an `error` string and no `threshold`, `model_used`,
  `integration_count`, or `summary`:

```jsonc
{
  "total_sessions": 0, "bot_count": 0, "human_count": 0, "bot_rate": 0.0,
  "sessions": [], "error": "Log file not found: does-not-exist.log"
}
```

Every formatter checks `error` first. So should yours.

`features` keys are the 19 names in
[`FEATURE_NAMES`](reference-features.md), in order.

## Probe result schema

```jsonc
{
  "url": "https://example.com",
  "probes": 3,
  "features": { "response_time": 0.13, /* …16 keys… */ },
  "heuristic_score": 0.2,
  "heuristic_reason": "well-protected site (4 security headers)",
  "model_score": 0.0,          // always 0.0 — the model is not applied to probes
  "combined_score": 0.2,       // equals heuristic_score, for the same reason
  "label": "human",
  "threshold": 0.7,
  "timing": { "ttfb": 0.09, "total": 0.13 },
  "status_code": 200,
  "headers": { "Server": "nginx" },
  "body_preview": "<!doctype html>…"   // first 500 chars
}
```

A WebSocket probe adds `"protocol": "websocket"`, `connected`, `handshake_ok`,
and `error`, and drops `body_preview`.

## Output formats

| Format | Function | Notes |
|---|---|---|
| `terminal` | `report.format_terminal` | ANSI table, top 10 sessions only |
| `json` | `report.format_json` | `json.dumps(results, indent=2, default=str)` — the full dict |
| `html` | `report.format_html` | Standalone document, no external assets, no scripts. **Does not HTML-escape its input** — do not serve it from a trusted origin |
| `nginx` | `report.format_nginx_denylist` | `deny 1.2.3.4;` lines for DANGER-scored IPs |
| `cloudflare` | `report.format_cloudflare_rule` | `(ip.src in {1.2.3.4 5.6.7.8})` |
| `--json-pretty` | `report.format_json_pretty` | ANSI-colored, JSON-shaped, **not parseable** |
| `--verbose` | `report.format_verbose` | Per-session features and rule breakdown |

## Risk bands

`report.score_label()` maps a blended score to a band, used by every formatter
and by the dashboard:

| Score | Band |
|---|---|
| 0.00 – 0.30 | SAFE |
| 0.31 – 0.59 | LOW |
| 0.60 – 0.79 | WARNING |
| 0.80 – 1.00 | DANGER |

`--output nginx` and `--output cloudflare` emit rules for DANGER IPs only.

## Thresholds, and why there are two

| Constant | Value | Used by |
|---|---|---|
| `cli.DEFAULT_THRESHOLD` | `0.7` | `scan`, `probe`, `watch` |
| `scoring.BLOCK_THRESHOLD_DEFAULT` | `0.85` | `serve`, the middleware |

Batch analysis is advisory, so it can afford to flag more. Live blocking turns a
score into a 403 for a real visitor, so it demands more agreement. The
comparison also differs: batch uses `>=`, the live path uses a strict `>`.
[Tuning blocking](howto-tune-blocking.md) covers the live side.

## Related

- [How to scan log files](howto-scan-log-files.md)
- [The 19 features](reference-features.md) · [The heuristic rules](reference-heuristic-rules.md)
- [How detection works](explanation-how-detection-works.md)
- [Live API reference](reference-live-api.md)
