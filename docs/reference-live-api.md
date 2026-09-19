# Real-time blocking API reference

Complete technical description of `microguard/live/` — the inline path that scores
a request and blocks it before it reaches your application. For a guided
walkthrough see the [tutorial](tutorial-real-time-blocking.md); for why it behaves
this way see [how blocking works](explanation-how-blocking-works.md).

Everything here requires the `live` extra:

```bash
pip install 'microguard[live]'        # adds redis>=5.0,<6
pip install 'microguard[live,fastapi]'  # + fastapi, uvicorn
pip install 'microguard[live,flask]'    # + flask
```

Importing `microguard.live` without `redis` installed raises `ImportError` with an
actionable message. The base `pip install microguard` stays dependency-free and
`microguard scan` keeps working.

---

## `microguard serve`

Starts the HTTP check server for nginx's `auth_request` module. One endpoint,
`GET /check`.

```bash
microguard serve [--host HOST] [--port PORT] [--redis-url URL]
                 [--block-threshold FLOAT] [--session-ttl SECONDS]
                 [--trust-forwarded-for]
```

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--host` | str | `127.0.0.1` | Bind address. Keep on loopback unless nginx is on another host. |
| `--port` | int | `8400` | Listen port. |
| `--redis-url` | str | `redis://localhost:6379` | Redis connection URL. Accepts `redis://host:port/db`. |
| `--block-threshold` | float | `0.85` | Blocks when the blended score **exceeds** this. See [tuning](howto-tune-blocking.md). |
| `--session-ttl` | int | `1800` | Seconds of inactivity before a session expires. Refreshed on every request. |
| `--trust-forwarded-for` | flag | off | Honor `X-Forwarded-For` for the client IP. **Only** enable behind a proxy that overwrites it. |

The server refuses to start if Redis is unreachable (it pings once at boot). It
prints its resolved configuration, including whether the model loaded:

```
microguard check server listening on 127.0.0.1:8400
  redis: redis://localhost:6379
  threshold: 0.85
  session TTL: 1800s
  model: loaded
  trust X-Forwarded-For: False
```

`model: NOT LOADED (heuristics only)` means scoring is running without the
trained model. Requests are still scored, but only by the heuristic rules.

### `GET /check`

Reads request metadata from headers, scores it, and answers 200 (allow) or
403 (block). Any other path returns 404.

| Request header | Used for | Fallback |
|---|---|---|
| `X-Real-IP` | Client IP (session key) | `X-Forwarded-For` if `--trust-forwarded-for`, else the transport peer address |
| `X-Forwarded-For` | Client IP, **only** when trusted | ignored by default |
| `User-Agent` | Heuristic rules, feature extraction | `""` |
| `X-Original-Method` | HTTP method of the real request | `GET` |
| `X-Original-URI` | Path of the real request | `/` |

The check server reads these headers, `Referer` included — so it must be
forwarded (`proxy_set_header Referer $http_referer;`, see
[deploy behind nginx](howto-deploy-behind-nginx.md)). The
[benchmark](results/2026-09-benchmark.md) originally found the server dropping
the referer (it built the `LogEntry` with `referer=""`), which made the
referer-based rules inert on the live path; that is now fixed, and the same is
true for the ASGI and WSGI middleware, which read the referer directly from the
request.

Responds with the [decision payload](#decision-payload) as a JSON body and as
`X-Microguard-*` headers.

---

### `GET /fingerprint.js` · `POST /fp`

**Public**, unlike `/check`. Served by all three hosts: the check server, and
both middleware. Behind nginx they need a second, non-`internal` location — see
[deploying behind nginx](howto-deploy-behind-nginx.md).

```
GET  /fingerprint.js   ->  the client probe, cacheable
POST /fp               ->  {"fingerprint_hash": "<64 hex chars>"}
```

Both spellings of each path are accepted (`/fp` and `/microguard/fp`), because
nginx may or may not strip the location prefix depending on whether
`proxy_pass` carries a trailing path.

**Every outcome answers `200` with identical bytes.** A 4xx would hand an
unauthenticated caller an oracle for which IPs are bindable, and would surface
a microguard problem as an error on someone else's page. Submissions are
silently ignored when the body is malformed or oversized, when the actor has no
session history, when the session already has a different hash bound, or when
Redis is unreachable.

**A hash is only bound to an IP that already has session history, and only
once per session**, claimed atomically. Without that, `/fp` is an amplification
vector: canvas fingerprints collide heavily across identical hardware and
browser versions, so an attacker who harvests one real browsers produce could
replay it from a botnet and get those users blocked by the cross-IP rule.

**Fingerprinting needs HTTPS.** The script hashes with SubtleCrypto, which only
exists in a secure context. On a plain-HTTP origin it logs a console warning and
sends nothing.

## Middleware

Both classes take identical arguments, matching the `microguard serve` flags.

```python
MicroguardASGI(app, redis_url="redis://localhost:6379",
               block_threshold=0.85, session_ttl=1800,
               trust_forwarded_for=False)

MicroguardWSGI(app, redis_url="redis://localhost:6379",
               block_threshold=0.85, session_ttl=1800,
               trust_forwarded_for=False)
```

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `app` | ASGI app / WSGI callable | required | The application to wrap. |
| `redis_url` | str | `redis://localhost:6379` | Connection is lazy; construction does not contact Redis. |
| `block_threshold` | float | `0.85` | Blocks when the score **exceeds** this. |
| `session_ttl` | int | `1800` | Seconds of inactivity before a session expires. |
| `trust_forwarded_for` | bool | `False` | Honor `X-Forwarded-For` for the client IP. |

Unknown keyword arguments raise `TypeError`. A misspelled `block_treshold` fails
at construction rather than silently running at the default.

**`MicroguardASGI`** — Starlette, FastAPI, or any ASGI 3 app. Non-HTTP scopes
(WebSocket, lifespan) pass through unscored. Client IP comes from headers, then
`scope["client"][0]`.

**`MicroguardWSGI`** — Flask or any WSGI app. Client IP comes from
`HTTP_X_REAL_IP`, then `HTTP_X_FORWARDED_FOR` when trusted, then `REMOTE_ADDR`.

On a block, both return 403 with the decision payload as the body and never call
the wrapped app. On a pass, both attach the decision as request headers
(`scope["headers"]` / `HTTP_X_MICROGUARD_*`) and forward. Client-supplied
`X-Microguard-*` headers are stripped first, so an app reading them sees only
microguard's values.

See [deploying in-process](howto-deploy-in-process.md).

---

## Decision payload

Returned by `LiveScorer.score_request()`, sent as the JSON body of `/check` and of
any 403.

| Key | Type | Description |
|---|---|---|
| `ip` | str | The client IP used as the session key. |
| `label` | `"bot"` \| `"human"` | The decision. |
| `score` | float 0.0-1.0 | The blended score the decision used. |
| `model_score` | float 0.0-1.0 | What the model alone said. `0.0` when no model is loaded. |
| `heuristic_label` | `"bot"` \| `"human"` \| `"automated-integration"` | What the rules alone said. |
| `heuristic_confidence` | float 0.0-1.0 | How sure the rules were. |
| `heuristic_reason` | str | Which rule fired, in plain English. |
| `request_count` | int | Requests in the retained session history (capped at 200). |
| `duration` | float | Seconds spanned by the retained history. |
| `model_loaded` | bool | Whether the model contributed at all. |
| `block_threshold` | float \| null | The bar this request was judged against, after any runtime override. `null` on the fail-open payload, where no threshold was consulted. |
| `reason` | str | Alias of `heuristic_reason`, kept for older callers. |

```json
{
  "ip": "203.0.113.9",
  "label": "bot",
  "score": 0.95,
  "model_score": 0.7312,
  "heuristic_label": "bot",
  "heuristic_confidence": 0.95,
  "heuristic_reason": "vulnerability scanner pattern detected",
  "request_count": 3,
  "duration": 0.0041,
  "model_loaded": true,
  "block_threshold": 0.85
}
```

### Response headers

The same decision travels as headers, because nginx's `auth_request_set` can only
read response headers, not bodies.

| Header | Source key |
|---|---|
| `X-Microguard-Label` | `label` |
| `X-Microguard-Score` | `score` |
| `X-Microguard-Model-Score` | `model_score` |
| `X-Microguard-Heuristic` | `heuristic_label` |
| `X-Microguard-Reason` | `heuristic_reason` |

---

## Dashboard API

Served by `microguard dashboard`, default `127.0.0.1:8500`. Every path below is
under the same origin as the UI. See
[how to run the dashboard](howto-run-the-dashboard.md).

With `--token`, every `/api` request must carry a matching
`X-Microguard-Token` header; without it the endpoint answers `401`. The SPA
itself is not gated, so a browser can still load the page.

### `GET /api/health`

```json
{ "version": "2.0.0", "model_loaded": true, "redis_connected": true }
```

The two fields that matter are the degraded ones. `model_loaded: false` means
every score is heuristics-only. `redis_connected: false` means the dashboard is
reading a process-local recorder and the Live tab will stay empty no matter how
much traffic the check server sees.

### `GET /api/live/stats`

```json
{
  "total": 40, "blocked": 37, "allowed": 3,
  "bot_rate": 0.925, "avg_score": 0.916,
  "histogram": [0, 0, "…20 buckets…", 37],
  "top_blocked_ips": [{ "ip": "192.0.2.44", "count": 25 }],
  "started_at": null
}
```

Counters are cumulative since the recorder started, not derived from the event
ring. `histogram` has exactly 20 buckets of 0.05. `top_blocked_ips` is capped at
10, ordered by count. `started_at` is a float epoch for the in-process recorder
and `null` for the Redis one, where "started" has no single meaning across
processes.

### `GET /api/live/events?limit=100`

```json
{ "events": [ { "…decision payload…": "", "ts": 1789124850.91 } ] }
```

Newest first. `limit` is 1 to 1000; outside that range the endpoint answers
`422`. Each event is the decision payload documented above plus a `ts` float
epoch added by the recorder.

### `GET /api/live/stream`

Server-sent events, `text/event-stream`:

| Event | Payload | Cadence |
|---|---|---|
| `stats` | The `/api/live/stats` body | Every 2 seconds |
| `decision` | One decision, oldest-first within a tick | As they arrive |

The stream polls the recorder rather than subscribing to it — decisions are
written by a different process, so there is no in-process callback to hang off,
and polling keeps the recorder interface to three methods. A client that
reconnects will not receive decisions it already saw within the same connection;
across reconnects, deduplicate on `(ts, ip)`.

### `GET /api/live/config` · `PUT /api/live/config`

```json
{ "block_threshold": 0.25, "writable": true }
```

`block_threshold` is `null` when no override is set, meaning each scoring
process uses whatever it was started with. `writable` is true only when the
dashboard was started with `--allow-config-writes` **and** has a shared Redis.

`PUT` takes `{"block_threshold": 0.25}` or `{"block_threshold": null}` to clear
it. Responses:

| Status | Meaning |
|---|---|
| `200` | Written; every scoring process on this Redis picks it up within about 5 seconds |
| `403` | Config writes are disabled — start with `--allow-config-writes` |
| `422` | Threshold outside 0.0–1.0 |
| `503` | No shared config store; the dashboard needs the Redis the live path uses |

Every accepted change is logged at warning level with its old and new value.

### `POST /api/live/feedback`

Records an operator's correction against one decision.

```json
{ "decision_id": "a1b2c3...", "label": "human" }
```

`label` is what the session **actually** was, not what microguard said.

| Response | When |
|---|---|
| `200 {"recorded": true, "decision_id": "..."}` | Recorded |
| `404` | No such decision — the feed keeps the most recent 1000 |
| `422` | That decision carries no features, so there is nothing to train on. Fail-open rows look like this |
| `503` | No `--deployment-id` was set. Corrections are per-deployment by definition |

**Open by default**, unlike the config writes above. A recorded correction
changes nothing until someone deliberately runs `microguard retrain`, and the
safety rails refuse thin or skewed data at that point — so the gate belongs
there. Gating collection instead would leave the control dark on a default
install, and a retrain needs 50 corrections before it runs at all.

Keyed by decision id, so a double-click records one example rather than two.

### `GET /api/scan/samples`

```json
{ "samples": [ { "name": "sample_access.log", "bytes": 2980, "lines": 20 } ] }
```

Only `.log` files directly inside the package's `data/` directory.

### `POST /api/scan`

```json
{ "sample": "sample_access.log", "format": "auto", "threshold": 0.7, "timeout_minutes": 30 }
```

Returns `scan_logfile()`'s dict unchanged — see the
[scan result schema](reference-cli.md#scan-result-schema), including the error
variant. Unknown keys are rejected with `422` rather than ignored, so a typo'd
`treshold` fails loudly instead of silently scanning at the default.

Sample names resolve inside `data/` through `realpath`, so `../setup.py` and
absolute paths answer `404`. There is no endpoint that scans an arbitrary
server-side path.

### `POST /api/scan/upload`

`multipart/form-data` with `file`, plus optional `format`, `threshold` and
`timeout_minutes` form fields. Returns the same dict.

The upload streams to a temporary file with a 64 MB cap and is deleted in a
`finally`, including on the `413` rejection path.

### `POST /api/scan/export`

```json
{ "results": { "…a scan result…": "" }, "format": "json" }
```

`format` is `json`, `html`, `nginx` or `cloudflare`, rendered by the
corresponding `report.py` formatter.

Always returned as `text/plain` with `Content-Disposition: attachment`, never
`text/html`. `report.format_html()` interpolates user agents, URLs and reasons
without escaping them, so serving it inline would be stored XSS on the
dashboard's own origin.

### `GET /api/model`

```json
{
  "num_features": 19,
  "architecture": [4, 1],
  "feature_names": ["time_since_last_request", "…"],
  "weights": ["…85 floats…"],
  "normalization": { "mins": ["…19…"], "maxs": ["…19…"] }
}
```

`normalization` is `null` when the file is missing, which is also the state in
which scores stop meaning anything. Answers `503` when there is no trained
model. See [the model](reference-model.md).

### `POST /api/model/evaluate`

```json
{ "dataset": "holdout", "threshold": 0.5 }
```

`dataset` is `holdout` or `adversarial`; anything else is `422`. Returns:

```json
{
  "dataset": "holdout", "threshold": 0.5, "n_samples": 623,
  "confusion": { "tp": 423, "fp": 0, "fn": 0, "tn": 200 },
  "precision": 1.0, "recall": 1.0, "f1": 1.0, "accuracy": 1.0,
  "roc": [ { "fpr": 1.0, "tpr": 1.0 }, "…" ],
  "score_distribution": ["…20 buckets…"]
}
```

Positives use a strict `>` against the threshold, matching the live scorer. The
ROC sweeps every observed score as a candidate threshold. Scores are cached per
dataset, so dragging a threshold slider does not re-run 623 forward passes.

### Redis keys

Written by whichever process scores — the check server, either middleware, or
both at once:

| Key | Type | Contents |
|---|---|---|
| `mg:v1:events` | LIST | JSON decisions, newest first, capped at 1000 |
| `mg:v1:counters` | HASH | `total`, `blocked`, `score_sum` |
| `mg:v1:hist` | HASH | bucket index `0`–`19` → count |
| `mg:v1:blocked_ips` | ZSET | IP → times blocked, trimmed to the busiest 1000 |
| `mg:v1:config` | HASH | `block_threshold` → float; `promoted_signals` → JSON array of enforced source names. Both absent means no override and observe-only |
| `mg:v1:signals:{ip}` | STRING | JSON of externally resolved signals for one actor. Written by `microguard signals`, expires with the session TTL |
| `mg:v1:signals:heartbeat` | STRING | JSON `{ts, resolved, sources}` from the last refresh pass. **Never expires** — an absent key means the refresher has never run, which is a different problem from one that died |
| `mg:v1:fp:{ip}` | STRING | `{hash, shared_ips}` for one actor. Its own key rather than a field on `mg:v1:signals:{ip}`, because the refresher `SET`s that key wholesale and would clobber it |
| `mg:v1:fp_ips:{hash}` | SET | IPs seen with this fingerprint inside the window (600s TTL) |
| `mg:v2:actor:{hash}` | HASH | `first_seen`, `last_seen`, `sightings`, `distinct_ips`. 30-day sliding TTL — the only structure here that outlives a session. A HASH so sightings use `HINCRBY`; the prefix is v2 because `HINCRBY` against a v1 JSON string is `WRONGTYPE` |
| `mg:v2:actor_index` | ZSET | Hash → last-seen epoch for every actor record, capped at 10,000. When over the cap, the least recently seen actors are evicted along with their `mg:v2:actor:{hash}` records. Evicted by recency, not sightings, because the busiest actor is usually the farm |

One decision is one pipeline: `LPUSH` + `LTRIM`, `HINCRBY` on the counters and
the histogram, and `ZINCRBY` on the blocked IPs for a block. Reads are one
pipeline too.

Counters are cumulative rather than derived from the capped ring. A "blocked
today" number that shrank as old decisions scrolled out of the ring would be
worse than no number.

The blocked-IP set is trimmed on write with `ZREMRANGEBYRANK`, keeping the
highest counts. It is the only structure that would otherwise grow with the
number of distinct attackers rather than with traffic volume. The trade is that
a brand-new address can be evicted before it surfaces there; the decision feed
is the place to look for whether a specific IP was blocked.

These keys never expire on their own — they are process-lifetime operator
counters, not per-visitor state. `FLUSHDB` or delete them explicitly to reset.
The version prefix exists for the same reason as `live:v2:`: a value-shape
change gets a new namespace rather than a `WRONGTYPE` on deploy.

---

## Python API

### `LiveScorer`

```python
from microguard.live.scorer import LiveScorer

LiveScorer(store, model_path=None, block_threshold=0.85,
           session_ttl=1800, short_circuit_label="automated-integration",
           recorder=None, threshold_source=lambda: None)
```

| Argument | Type | Default | Notes |
|---|---|---|---|
| `recorder` | `DecisionRecorder` \| None | `None` | Where each decision is stored for the dashboard. Errors from it are logged and swallowed; recording can never change or delay a verdict. |
| `threshold_source` | `() -> float \| None` | returns `None` | Consulted once per request. A value overrides `block_threshold`; `None`, or a raise, leaves the configured value standing. |

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `store` | `SessionStateStore` | required | Where session history lives. |
| `model_path` | str \| Path \| None | `None` | `None` resolves the packaged `microguard/data/model.json`. |
| `block_threshold` | float | `0.85` | Blocks when the score exceeds this. |
| `session_ttl` | int | `1800` | Passed to the store on every append. |
| `short_circuit_label` | str | `"automated-integration"` | Heuristic label that is never blocked. |

**`score_request(entry: LogEntry) -> dict`** — records the request, scores the
resulting session, returns the [decision payload](#decision-payload).

**`model_loaded: bool`** — whether scores include a model contribution. Read this
rather than inferring it from a `model_score` of 0.0.

A model that cannot be found or cannot be parsed logs a warning at `WARNING`
level and degrades to heuristics. It never raises.

### `RedisSessionStateStore`

```python
from microguard.live.redis_store import RedisSessionStateStore

RedisSessionStateStore(redis_client, prefix="live:v2:", default_ttl=1800)
```

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `redis_client` | `redis.Redis` | required | Construct with `decode_responses=True`. |
| `prefix` | str | `"live:v2:"` | Key namespace. The version guards against value-shape changes. |
| `default_ttl` | int | `1800` | Used when `record_request` is called without a TTL. |

**`record_request(ip, user_agent, entry, ttl_seconds=None) -> LiveSession`** —
appends atomically and returns the session ready to score. One pipeline:
`RPUSH`, `LTRIM`, `EXPIRE`, `LRANGE`.

**`delete(ip) -> None`** — removes a session.

Key schema: `live:v2:{ip}` holds a Redis LIST of JSON `LogEntry` payloads, newest
last, capped at `MAX_SESSION_ENTRIES`.

### `SessionStateStore`

A `typing.Protocol` with two methods, `record_request` and `delete`. Implement it
to back sessions with something other than Redis; `LiveScorer` accepts any object
satisfying it.

### `LiveSession`

Dataclass holding `ip`, `user_agent`, `requests` (a list of `LogEntry`),
`start_time` and `end_time` (float epochs), with `request_count` and `duration`
properties. Duck-types `microguard.features.Session`, so `extract_features()` and
`label_session()` accept it unchanged.

### Constants

| Constant | Module | Value | Meaning |
|---|---|---|---|
| `BLOCK_THRESHOLD_DEFAULT` | `microguard.scoring` | `0.85` | Shared by the scorer, server, middleware, and CLI. |
| `MAX_SESSION_ENTRIES` | `microguard.live.redis_store` | `200` | Retained requests per session. |

---

## Failure behavior

| Condition | Behavior |
|---|---|
| Redis unreachable at startup | `microguard serve` exits. Middleware constructs fine (the connection is lazy). |
| Redis fails during a request | **Fail open.** The request is allowed, a warning is logged, and the payload reports `heuristic_reason: "scoring unavailable"`. |
| Model file missing or corrupt | Warning logged, scoring continues on heuristics, `model_loaded` is `false`. |
| `normalization.json` missing | Warning logged. Scores will be wrong — the model expects normalized inputs. |
| Unknown middleware keyword | `TypeError` at construction. |
| Non-HTTP ASGI scope | Passed through unscored. |

Fail-open is deliberate: nginx treats any `auth_request` response that is not
2xx/401/403 as an error and returns 500 to the visitor, so a Redis blip would
otherwise take the site down. See
[how blocking works](explanation-how-blocking-works.md#failing-open).

---

## Related

- [Tutorial: block your first bot](tutorial-real-time-blocking.md)
- [How to deploy behind nginx](howto-deploy-behind-nginx.md)
- [How to deploy in-process](howto-deploy-in-process.md)
- [How to tune blocking](howto-tune-blocking.md)
- [How blocking works](explanation-how-blocking-works.md)
