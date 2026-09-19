# How to operate microguard

Run, monitor, diagnose and restart a live deployment by hand. By the end you
will be able to tell the three failure modes apart in under a minute and know
what each one costs you.

This is written for the case where you are managing it manually, which is the
default: microguard ships no service definition, no scheduler, and nothing that
restarts or retrains itself. Nothing runs unless you run it.

## What runs itself, and what does not

| Runs itself | Needs you |
|---|---|
| Session state expires (1800s sliding TTL) | Starting and restarting the process |
| Session history caps at 200 requests per actor | Picking up a retrained model |
| Decision feed caps at 1000 entries | Retraining |
| Blocked-IP tracking caps at 1000 addresses | Noticing that anything is wrong |
| Threshold changes reach every process in ~5s | Resetting the cumulative counters |
| Redis failure mid-flight fails open | Exporting deny lists |
| Signal records expire with the session | Running `microguard signals` |
| A dead feed falls back to its last cache | Noticing a feed has been dead for a week |
| A retrained model is picked up in ~5s | Running the retrain |
| A corrupt model is refused, not loaded | Fixing the model it refused |

The counters in `mg:v1:counters` and `mg:v1:hist` are cumulative for the life of
the Redis instance and never expire. That is deliberate — see
[housekeeping](#housekeeping) — but it means they are the one thing that
accumulates until you clear it.

## Is it running?

Three processes matter now. The check server is the one in the request path:

```bash
microguard serve
```

```
microguard check server listening on 127.0.0.1:8400
  redis: redis://localhost:6379
  threshold: 0.85
  session TTL: 1800s
  model: loaded
  trust X-Forwarded-For: False
```

Read two lines of that banner every time:

- **`model: loaded`** — if it says `NOT LOADED (heuristics only)`, every score
  from now on is missing 60% of its signal. The process runs fine and blocks
  nothing differently enough to notice.
- **`redis:`** — the URL it will use. It pings before binding, so if you got a
  banner at all, Redis was reachable at startup.

For the dashboard, one request answers both questions:

```bash
curl -s http://127.0.0.1:8500/api/health
# {"version":"2.0.0","model_loaded":true,"redis_connected":true}
```

## Telling the three failure modes apart

They look nothing alike from the outside, and only one of them is an outage.

### Everything returns 500

**The check server is not running, or nginx cannot reach it.**

This is the one that takes the site down, and it is the case people expect
fail-open to cover. It does not. nginx treats any `auth_request` response that
is not 2xx, 401 or 403 as an error, and a connection refused is not a response
at all — so every visitor to the protected location gets a 500.

```bash
curl -si http://127.0.0.1:8400/check -H "X-Real-IP: 1.2.3.4" | head -1
# HTTP/1.0 403 Forbidden
```

A 403 here is a healthy answer, not a problem: curl sends its own user agent,
which trips the known-bot rule. You are checking that the process *responds* at
all. **No answer means it is gone** — restart it.

Any other path answers 404 with a short explanation of what this server is and
where the UI lives, so opening it in a browser tells you something useful
instead of nothing. The status stays 404 either way, which is what a
misconfigured `proxy_pass` depends on.

If that curl works and nginx still 500s, the problem is on the nginx side:
check `proxy_pass` points at `/check` and the `location` is marked `internal`.

**Note the startup asymmetry.** If Redis is down when you start the check
server, it does *not* start — it pings first and exits with a connection error.
So "Redis is down" produces a 500 outage when it happens before startup, and
fails open when it happens afterwards. Same dependency, opposite outcomes,
depending only on timing.

### Everything is allowed, nothing is blocked

**The process is alive and failing open.** Redis went away while it was
running. The site is up and completely unprotected.

The signature is in the response body:

```bash
curl -s http://127.0.0.1:8400/check -H "X-Real-IP: 1.2.3.4" | grep -o '"heuristic_reason":"[^"]*"'
# "heuristic_reason":"scoring unavailable"
```

The dashboard shows this as a **Failing open** banner on the Live tab. It is
deliberately loud: an unprotected site that looks healthy is worse than one
that is obviously broken. Treat it as an alert, not as noise.

Fix Redis. The check server recovers on its own once Redis answers again — no
restart needed, because it reconnects per request.

### Everything is allowed, and no decision mentions a signal

**The signal refresher is not running.** Threat-intel signals are absent, and
an actor with no resolved signals looks exactly like a clean one. Nothing
fails, nothing warns, and no rule that depends on a signal will ever fire.

```bash
redis-cli GET mg:v1:signals:heartbeat
# (nil)  -> it has never run against this Redis
```

The dashboard sidebar says `signals never ran` in amber. Start it:

```bash
microguard signals
```

It resolves signals only for actors that already have a live session, so the
keyspace is bounded by real traffic, and each record expires with the session
it describes. If the process dies, records go stale and then expire, and the
check server simply scores without them — degraded, not down. That is why the
fetches live here and not in the check server: a slow feed inside `/check`
would be a 500 for every visitor.

A source can also fail while the process is healthy, which is the case worth
watching for. The sidebar reports it per source:

```bash
curl -s http://127.0.0.1:8500/api/health | python3 -m json.tool
```

`signals.sources[].ok` false with an `error` means that one feed is serving
from a stale cache, or from nothing. Every signal degrades silently by design,
so this readout is the only place it surfaces.

### Everything is allowed, and every model score is 0.00

**No model is loaded.** Decisions are running on heuristics alone.

Nothing fails, nothing warns at request time, and the scores stay in range —
they just carry less signal. Check the startup banner, or the dashboard's
sidebar, which shows `model NOT LOADED` in amber. Confirm the file:

```bash
python -c "
from microguard.model import BotDetector, DEFAULT_MODEL_PATH
d = BotDetector(DEFAULT_MODEL_PATH)
print('weights loaded:', len(d.model.parameters()))
print('normalization loaded:', d.norm_mins is not None)
"
```

If `normalization loaded` is `False`, the scores are worse than useless — the
model was trained on scaled inputs and is being fed raw ones. See
[retraining](howto-retrain-the-model.md).

## Restarting

```bash
# Ctrl-C the existing process, then:
microguard serve
```

**A restart is cheap.** All the state lives in Redis — session history,
decision feed, counters, threshold override — and the process holds nothing but
the loaded model and its configuration. Restarting reconnects to the same keys
and carries straight on.

**Flushing Redis is not cheap.** The per-actor session history is what the
timing, rate and volume rules read. Clear it and every visitor looks brand new,
so expect a quiet window where nothing trips those rules until history
accumulates again. On a low-traffic site that window can be long.

So: restart the process freely. Flush Redis deliberately.

### Scores look plausible but the model never changes

**A retrained model was refused.** The scorer loads a candidate, finds it
unreadable, and keeps the one that was already working rather than falling
through to no model at all.

That fallback is the point. Before it, a corrupt deployment model produced
`model_score` 0.0 on every request, which collapses the blend to the heuristic
alone: scores stayed in range, nothing raised, nothing warned, and every
decision was quietly missing 60% of its signal.

The refusal travels on the decision itself, so the dashboard shows a **model
swap refused** badge on the detail panel, and:

```bash
microguard explain <ip> | head -5
redis-cli LINDEX mg:v1:events 0 | python3 -m json.tool | grep model_refused
```

Fix the file it names, or delete it: a deleted deployment model falls straight
back to the shipped baseline, which is the documented rollback.

## Picking up a retrained model

Two different things, and they behave differently.

**Retraining the baseline** still needs a restart. `LiveScorer` loads the
baseline once, in its constructor.

```bash
python -m microguard.training.train   # writes microguard/data/model.json
# nothing changes yet
microguard serve                      # restart: now it is in use
```

**A per-deployment model does not.** It is checked every few seconds and
swapped in place:

```bash
microguard retrain --deployment-id prod
# live within ~5s, no restart, no dropped sessions
```

That path needs the check server to have been started with the same id:

```bash
microguard serve --deployment-id prod
```

Without the flag the baseline is always used, and a deployment model sitting on
disk is ignored. That is deliberate: a process that did not ask for one must
never pick one up.

Corrections come from the dashboard, which also needs the id:

```bash
microguard dashboard --deployment-id prod
```

`retrain` refuses rather than crashing when the data will not support it: fewer
than 50 confirmed corrections, or more than 90% of them one class. Both print
what would change the answer. The shipped `microguard/data/model.json` is never written by
any of this — rolling back is deleting one file.

Confirm the new model is live by watching `model_score` move on the dashboard,
or by comparing a known request before and after.

Full detail in [how to retrain](howto-retrain-the-model.md). Note the runtime:
a full training pass is 2 to 3 minutes, not seconds.

## Tuning without a restart

The block threshold is the one setting you can change on a running system:

```bash
microguard dashboard --allow-config-writes
```

Drag the slider on the Live tab. Every scoring process sharing that Redis picks
it up within about five seconds. Or set it directly:

```bash
curl -X PUT http://127.0.0.1:8500/api/live/config \
  -H 'content-type: application/json' -d '{"block_threshold": 0.9}'
```

Clear it with `{"block_threshold": null}` and each process falls back to
whatever it was started with.

**1.00 is observe-only mode.** Nothing is ever blocked, but every decision is
still scored and recorded. That is the supported way to watch real traffic
before enforcing anything, and it is where a new deployment should start.

[Tuning blocking](howto-tune-blocking.md) covers which rules block at which
threshold.

## Housekeeping

Five `mg:v1:` keys, plus the per-visitor session keys:

| Key | Grows with | Bounded? |
|---|---|---|
| `mg:v1:events` | traffic | Yes — last 1000 decisions |
| `mg:v1:counters` | nothing | Fixed fields, values grow |
| `mg:v1:hist` | nothing | 20 fixed buckets |
| `mg:v1:blocked_ips` | distinct blocked IPs | Yes — top 1000 |
| `mg:v1:config` | nothing | One field |
| `live:v2:{ip}` | active visitors | Yes — 1800s TTL, 200 entries each |

Nothing here leaks. The counters are cumulative on purpose: a "blocked today"
number that shrank as old decisions scrolled out of the ring would be worse
than no number.

To reset the statistics without touching session state:

```bash
redis-cli DEL mg:v1:events mg:v1:counters mg:v1:hist mg:v1:blocked_ips
```

To check size:

```bash
redis-cli ZCARD mg:v1:blocked_ips     # never exceeds 1000
redis-cli LLEN mg:v1:events           # never exceeds 1000
redis-cli HGETALL mg:v1:counters
```

The blocked-IP set keeps the **busiest** addresses, not the most recent. Once
it is full, a brand-new attacker at one block can be evicted before it appears
there. That is the right trade for a "top blocked IPs" display; if you need to
know whether a specific address was ever blocked, read the decision feed
instead.

## A periodic check, if you want one

Nothing schedules this. Run it when you think of it:

```bash
curl -s http://127.0.0.1:8500/api/health
curl -s http://127.0.0.1:8500/api/live/stats | python3 -m json.tool | head -8
microguard explain <an-ip-you-saw-blocked>
```

What to look for:

- `redis_connected: false` → the Live tab is blind, and if the check server
  shares that Redis it is failing open.
- `model_loaded: false` → heuristics only.
- `bot_rate` far from what you expect → either an attack, or a threshold that
  no longer matches your traffic.
- `total` not moving between checks → nothing is being scored. Traffic is
  bypassing microguard, or the check server is down.
- `signals.running` false, or any source `ok: false` → threat-intel rules
  are quietly contributing nothing.

## Appendix: running it under supervision

Manual is the default and the rest of this document assumes it. If you later
want the process restarted for you, a systemd unit is the smallest thing that
works:

```ini
[Unit]
Description=microguard check server
After=network.target redis.service
Requires=redis.service

[Service]
ExecStart=/usr/local/bin/microguard serve --redis-url redis://localhost:6379
Restart=on-failure
RestartSec=5s
User=microguard

[Install]
WantedBy=multi-user.target
```

`Requires=redis.service` matters more than it looks: the check server exits if
Redis is not reachable at startup, so without ordering the unit will fail-loop
through a reboot.

This is not shipped, and adopting it is a decision to make deliberately — it
trades "I know exactly when it is running" for "it comes back without me".

## Related

- [Deploy behind nginx](howto-deploy-behind-nginx.md) · [Deploy in-process](howto-deploy-in-process.md)
- [Run the dashboard](howto-run-the-dashboard.md) — the monitoring surface
- [Tune blocking](howto-tune-blocking.md) — diagnosing a specific verdict
- [How blocking works](explanation-how-blocking-works.md) — why fail-open is built this way
- [Live API reference](reference-live-api.md) — every endpoint and key
