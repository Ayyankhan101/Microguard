<!-- Promoted from a /plan-ceo-review session on 2026-09-12. -->
<!-- Status: SHIPPED in v3.0.0 (29aaf79). Supersedes specs/0002, 0003 and 0004 where they conflict. -->

# Close the remaining epic: signal seam, fingerprinting, adaptive learning

> **Shipped.** Every task below landed in v3.0.0 (`29aaf79`) and its follow-up
> fixes; the checkboxes were ticked on 2026-09-16, after the fact. The body is
> kept as written at review time. Where the shipped system differs:
>
> - **Actor records live under `mg:v2:actor:{hash}`, not `mg:v1:actor:{hash}`.**
>   They became a Redis HASH so sightings use `HINCRBY`; the version changed
>   because `HINCRBY` against a v1 JSON string is `WRONGTYPE` (`da6812d`).
> - **The count cap this plan deferred is done** (#10): `mg:v2:actor_index`
>   holds at most 10,000 actors, evicting the least recently seen.
>
> `docs/reference-live-api.md` is the current key schema; trust it over this file.

## Context

`specs/0000-epic-paid-alternative-parity.md` and its four children were drafted
2026-09-06 against a **draft** of spec 0001. 0001 shipped (merge `6df9f01`), and
it shipped differently: a class-based `LiveScorer`, a `SessionStateStore` cut
down to `record_request` + `delete`, a `live:v2:` LIST session format, an
`mg:v1:` decision feed, a runtime threshold, and a dashboard nobody had planned.

Specs 0002, 0003 and 0004 are still DRAFT. Every one of them names an API that
no longer exists, and all three share a root cause: they assume `labeler.py` is
offline batch code. It is not. `live/scorer.py:126` calls `label_session` inline
on every nginx `auth_request`.

Four consequences, each verified against the code:

1. **0002 puts a blocking HTTP call in front of a real visitor.** AbuseIPDB on
   cache miss, inside `label_session`, inside `/check`. nginx turns a slow or
   failed `auth_request` into a 500.
2. **0002's cache is a JSON file** under `data/`, read-modify-written from a
   `ThreadingHTTPServer` — and `data/` lives inside the installed package.
3. **0003 tells the browser to fetch from an nginx `internal` location.** The
   check server also has no `do_POST`.
4. **0004 cannot get its feature vector.** `mg:v1:events` stores the decision,
   not the features; `live:v2:{ip}` is a 200-entry sliding window on a 1800s TTL.

This plan re-bases all three onto what shipped, fixes the shared root cause
once, and adds five accepted expansions.

**Premise note, recorded not acted on:** 0002's value (known-bad-IP reputation)
is what CrowdSec already delivers with a network effect this project does not
have. It stays in scope by decision D2, but it is the cut candidate if the
plan needs to shrink.

## Decisions made in this review

| # | Decision | Chosen |
|---|---|---|
| D1 | Review scope | Whole remaining epic (0002 + 0003 + 0004) |
| D2 | Approach | Signal layer first, specs on top |
| D3 | Mode | Selective expansion |
| D4.1 | Actor identity from fingerprint hash | **In scope** |
| D4.2 | Feedback control on dashboard rows | **In scope** |
| D4.3 | Signal health panel | **In scope** |
| D4.4 | Shadow-mode "would block" counter | **In scope** |
| D4.5 | `microguard explain <ip>` | **In scope** |
| D4.f | Assembly | Three milestones |
| 1A | Seam shape | `label_session(session, signals=EMPTY_SIGNALS)` |
| 2A | Slow tier owner | Separate `microguard signals` process |
| 3A | Fingerprint transport | Second **public** nginx location to the check server |
| 4A | Feature capture | Features stored in the decision event |
| 5A | Actor record bound | Sliding TTL, no count cap (risk accepted) |
| 6A | Corrupt model | Atomic write + scorer refuses the swap, loudly |
| 7A | `/fp` poisoning | Hash binds to an IP with existing session history |
| 8A | Feedback auth | Open by default; **retrain** is the gated step |
| 9A | Browser tests | Playwright, one CI job, not the 12-job matrix |
| 10A | New signal posture | Observe-only until explicitly promoted |
| 11A | Dashboard IA | Health to sidebar, feedback and shadow inline |

## Architecture

```
 nginx
   ├─ location /api/       auth_request ──┐          (internal, unchanged)
   ├─ location = /_mg_check  internal ────┤
   └─ location /microguard/  PUBLIC ──────┤          (NEW, decision 3A)
                                          ▼
                            CheckHandler  :8400
                              ├─ GET  /check           (unchanged)
                              ├─ GET  /fingerprint.js  (NEW)
                              └─ POST /fp              (NEW — first do_POST)
                                          │
                                          ▼
                            LiveScorer.score_request
                              ├─ record_request + signals read  ── ONE pipeline
                              ├─ label_session(session, signals)
                              ├─ extract_features   (now UNCONDITIONAL, 4A)
                              ├─ model.predict      (baseline OR deployment model)
                              └─ recorder.record    (event now carries id + features)

 microguard signals   (NEW process, 2A)        microguard dashboard  :8500
   ├─ Tor list refresh                           ├─ sidebar: signal health (11A)
   ├─ AbuseIPDB lookups + quota                  ├─ row: feedback control (D4.2)
   ├─ writes mg:v1:signals:*                     ├─ shadow counter by slider (D4.4)
   └─ writes mg:v1:signals:heartbeat             └─ POST /api/live/feedback
```

The seam's job is to keep this arrow from ever being drawn:
`labeler.py ──> network`. `label_session` stays a pure function of its
arguments, so `scan`, `probe` and `watch` are *structurally* incapable of a
network call. That satisfies epic Definition-of-Done item 2 by construction
rather than by an env var.

## Milestones

### M1 — The seam (~3-4 days human / ~1.5 hrs CC)

- `microguard/signals/` package. `EMPTY_SIGNALS` frozen mapping, `resolve_signals(ip)`.
- `label_session(session, signals=EMPTY_SIGNALS)`. Empty default, so all five
  existing call sites are byte-identical in behavior.
- `microguard signals` process: Tor exit list, hosting CIDR ranges (both
  keyless, offline set membership), heartbeat key.
- `mg:v1:signals:{ip}` with the same sliding-TTL discipline as `live:v2:{ip}`.
- Signals read folded into the **existing** `record_request` pipeline — one
  Redis round trip on `/check`, not two.
- `_check_threat_intel_signals(session, signals)` in `labeler.py`, reading
  only from `signals`, never fetching.
- Observe-only by default per 10A.
- Sidebar health block (11A) and `microguard explain <ip>` (D4.5).

Proves the seam against two trivial offline signals before anything risky
depends on it.

### M2 — Fingerprint + actor identity (~6-7 days human / ~3 hrs CC)

- `microguard/live/static/fingerprint.js` — canvas, WebGL, hardwareConcurrency,
  screen, timezone, font probe; SHA-256 client-side, only the hash transmitted.
- `CheckHandler.do_POST` for `/fp`, `GET /fingerprint.js`. Public nginx location.
- **7A binding:** a hash counts only for an IP that already has `live:v2:{ip}`
  history; first hash per session wins. Redis failure in `/fp` returns 200, not 500.
- Input validation before parse: content-length cap, hex-only, fixed length.
- `mg:v1:actor:{hash}` with a 30-day sliding TTL (5A).
- `_check_fingerprint_signals(session, signals)` — grace-period rule with the
  page-route exemption from 0003, and the cross-IP rule counting **bound** pairs.
- AbuseIPDB joins the slow tier here (quota accounting surfaces in health).
- Playwright CI job (9A): stable hash, environment-sensitive hash, and a network
  payload inspection proving only the hash leaves the page.

### M3 — Adaptive learning (~6-7 days human / ~2.5 hrs CC)

- Decision events gain an **id** and a **features** array (4A). Without the id,
  a feedback click has nothing to reference.
- `record_correction` (renamed from 0004's `record_outcome`), keyed by decision
  id, idempotent. fsync'd; `OSError` surfaces to the caller.
- `POST /api/live/feedback`, open by default (8A). Feedback control on each
  dashboard row (D4.2).
- `retrain_deployment_model` with 0004's two safety rails, plus: skips
  unparseable JSONL lines and reports the count, and **never** writes
  `base_model_path`.
- **6A:** atomic `os.replace` on publish; the scorer refuses to swap in a model
  that fails to load, keeps the previous one, and shows the refusal in health.
- Deployment-model selection in `LiveScorer`, mtime checked at most once per 5s
  (mirroring `RedisRuntimeConfig`'s existing cache), not per request.
- Shadow counter beside the threshold slider (D4.4).

## Files

| Path | Change |
|---|---|
| `microguard/signals/` | New — `EMPTY_SIGNALS`, `resolve_signals`, refresher, sources |
| `microguard/labeler.py` | `signals` param; two new `_check_*`; new constants |
| `microguard/live/scorer.py` | Signals read into the existing pipeline; unconditional `extract_features`; deployment-model selection + guarded reload |
| `microguard/live/server.py` | `do_POST` for `/fp`; `GET /fingerprint.js` |
| `microguard/live/redis_events.py` | Event gains `id` and `features` |
| `microguard/live/static/fingerprint.js` | New |
| `microguard/training/online_update.py` | New — `record_correction`, `retrain_deployment_model`, exception classes |
| `microguard/cli.py` | `signals`, `explain`, `retrain` subcommands |
| `gui/src/` | Sidebar health, row feedback control, shadow counter |
| `docs/howto-operate-microguard.md` | Two new failure modes; the fourth process |
| `docs/reference-live-api.md` | `/fp`, `/fingerprint.js`, `/api/live/feedback`, `mg:v1:signals:*`, `mg:v1:actor:*` |
| `.github/workflows/` | One Playwright job (not matrixed) |

## Reuse (do not rebuild)

- `RedisRuntimeConfig` (`live/runtime_config.py`) — the 5s-cached, fail-to-`None`
  pattern is exactly what the mtime check and signal freshness need.
- `RedisDecisionRecorder.record` (`live/redis_events.py:95`) — one pipeline per
  decision. Event changes go inside it, adding no round trip.
- `compute_combined_score` (`scoring.py`) — unchanged. Signals reach the score
  through `label_session`'s confidence, not a third blend term.
- The `ZREMRANGEBYRANK` cap pattern from `blocked_ips` — the template if actor
  records ever need a count bound.
- `tests/conftest.py` `make_entry` / `make_session` / `nginx_log_file`.

## NOT in scope

- CrowdSec integration or any shared reputation network (epic-level exclusion;
  and it is the reason 0002 is the cut candidate).
- Paid CAPTCHA / challenge vendors, and proof-of-work challenges.
- Federated cross-deployment learning.
- Automated (non-human-confirmed) feedback.
- Mobile / non-browser fingerprinting.
- Rewriting `microguard scan`, `probe`, or `watch`.
- A count cap on actor records — deliberately deferred, see TODOs.

## Known accepted risks

1. **Actor records are unbounded in count** during a fingerprint flood (5A).
   Upgrade trigger: `mg:v1:actor:*` key count exceeding ~50k, or the health
   panel showing sustained novel-hash growth. Fix is the `blocked_ips`
   `ZREMRANGEBYRANK` pattern.
2. **`labeler.py` rule order is semantics.** First-match-wins, and the file
   already contains one rule proven unreachable. Two more `_check_*` calls make
   reordering riskier.
3. **0002 duplicates CrowdSec** with a weaker version. Kept by decision.

## Verification

```bash
python -m pytest tests/ -q --cov=microguard --cov-fail-under=98
ruff check . && mypy microguard && vulture microguard microguard/vulture_whitelist.py
cd gui && npm run test && npx tsc --noEmit
```

Per milestone, end to end:

**M1.** `microguard scan data/sample_access.log` produces byte-identical output
before and after — the seam is additive or it is broken. Start `microguard
signals`, confirm `mg:v1:signals:heartbeat` moves, confirm the dashboard sidebar
reports each source's age. Kill it; confirm `/check` still answers and the
panel goes stale rather than the site going down.

**M2.** Playwright: load a page embedding `fingerprint.js` in headless Chromium,
assert a stable hash across runs, a different hash under a changed timezone and
viewport, and that the captured network payload contains the hash and nothing
else. Then the 7A check: `curl` a hash from an IP with no session history and
assert it is not recorded.

**M3.** Record 50 balanced corrections, run `microguard retrain`, assert
`data/model.json` is byte-identical afterwards, and that the deployment model
scores better on that deployment's pattern than the baseline. Then corrupt the
deployment model file and confirm the scorer keeps the previous model and says
so in health — rather than silently dropping to heuristics.

The single most important assertion across all three: `data/model.json` is never
written by anything in `online_update.py`.

## Scope expansion decisions

- **Accepted (5 of 5):** actor identity from the fingerprint hash; feedback
  control on dashboard rows; signal health panel; shadow would-block counter;
  `microguard explain <ip>`.
- **Deferred:** none.
- **Skipped:** none.
- **Held back, available on request:** decision replay against a retrained
  model; per-decision permalink.

Two of the five changed category during the review. The health panel became
load-bearing for decision 2A (a refresher you have to remember to start needs a
liveness readout) and for the AbuseIPDB 429 gap. The shadow counter became
load-bearing for decision 10A (observe-only has no readout without it).

## Deferred, with triggers

Written up in full in [TODOS.md](../../TODOS.md).

| # | Item | Priority | Effort | Trigger |
|---|---|---|---|---|
| 1 | Cap `mg:v1:actor:*` by count, `ZREMRANGEBYRANK` pattern | P2 | S | key count > ~50k, or sustained novel-hash growth in the health panel |
| 2 | `labeler.py` rule-order debt; one rule already unreachable | P3 | M | when the chain passes ~250 lines or a reorder is needed |
| 3 | Evaluate CrowdSec in place of spec 0002 | P2 | S | before M1 starts, or whenever the plan needs to shrink |

## Implementation Tasks

Synthesized from this review's findings. Each derives from a specific decision
above. JSONL artifact:
`~/.gstack/projects/micrograd-end-sem-ML-project/tasks-ceo-review-20260912-101125.jsonl`

**M1 — the seam**

- [x] **T1 (P1, human: ~1d / CC: ~20min)** — signals — Add the seam: `EMPTY_SIGNALS` + `signals` param on `label_session`
  - Surfaced by: Section 1, decision 1A — `labeler.py` must stay pure so `scan`/`probe`/`watch` cannot make a network call
  - Files: `microguard/signals/__init__.py`, `microguard/labeler.py`
  - Verify: `microguard scan data/sample_access.log` byte-identical before/after
- [x] **T2 (P1, human: ~1d / CC: ~20min)** — signals — `microguard signals` process + heartbeat key
  - Surfaced by: Section 1, decision 2A — the slow tier must not live in the process whose death is a 500
  - Files: `microguard/signals/refresher.py`, `microguard/cli.py`
  - Verify: `redis-cli GET mg:v1:signals:heartbeat` moves; kill it, `/check` still answers
- [x] **T3 (P1, human: ~0.5d / CC: ~15min)** — scorer — Fold the signals read into the existing `record_request` pipeline
  - Surfaced by: Section 7 — a separate GET doubles hot-path round trips on a remote Redis
  - Files: `microguard/live/scorer.py`, `microguard/live/redis_store.py`
  - Verify: assert one round trip per `/check` against a counting fake
- [x] **T4 (P1, human: ~0.5d / CC: ~15min)** — labeler — `_check_threat_intel_signals`, observe-only by default
  - Surfaced by: Section 9, decision 10A — a new signal must not change blocking before it is measured
  - Files: `microguard/labeler.py`
  - Verify: signal fires in the recorded decision but cannot solely produce a block
- [x] **T5 (P2, human: ~1d / CC: ~20min)** — dashboard — Sidebar signal health: source age, quota, heartbeat
  - Surfaced by: D4.3 + decision 11A — every signal here fails silently by design
  - Files: `gui/src/`, `microguard/dashboard/api_health.py`
  - Verify: stop the refresher; panel says "not running", not "healthy"
- [x] **T6 (P2, human: ~0.5d / CC: ~15min)** — cli — `microguard explain <ip>`
  - Surfaced by: D4.5 — "why was this blocked" stops being answerable from the decision payload once signals exist
  - Files: `microguard/cli.py`
  - Verify: prints session, resolved signals, and the deciding rule for a known IP

**M2 — fingerprint + actor identity**

- [x] **T7 (P1, human: ~0.5d / CC: ~15min)** — server — `do_POST /fp`, `GET /fingerprint.js`, public nginx location
  - Surfaced by: Section 1, decision 3A — 0003 told the browser to fetch from an nginx `internal` location
  - Files: `microguard/live/server.py`, `docs/howto-deploy-behind-nginx.md`
  - Verify: `curl` the script publicly; `/check` still unreachable from outside
- [x] **T8 (P1, human: ~0.5d / CC: ~15min)** — server — Validate `/fp` before parse; 200 not 500 on Redis failure
  - Surfaced by: Section 4 — a public non-critical route must not surface errors to a visitor
  - Files: `microguard/live/server.py`
  - Verify: oversized body, non-hex hash, and a downed Redis each return a non-5xx
- [x] **T9 (P1, human: ~0.5d / CC: ~15min)** — live — Bind the hash to an IP with existing session history; first hash wins
  - Surfaced by: Section 3, decision 7A — unauthenticated `/fp` otherwise lets an attacker get real users blocked
  - Files: `microguard/live/server.py`, `microguard/live/redis_store.py`
  - Verify: POST a hash from an IP with no `live:v2:` history; assert it is not recorded
- [x] **T10 (P2, human: ~0.5d / CC: ~10min)** — live — `mg:v1:actor:{hash}`, 30-day sliding TTL
  - Surfaced by: D4.1 + decision 5A — the hash is an identity key that survives IP rotation
  - Files: `microguard/live/redis_store.py`
  - Verify: same hash from a second IP links to one actor record; TTL refreshes on sighting
- [x] **T11 (P1, human: ~1d / CC: ~20min)** — labeler — `_check_fingerprint_signals`, page-route exemption, bound-pair counting
  - Surfaced by: spec 0003 rules 1 and 2, re-based onto decision 7A
  - Files: `microguard/labeler.py`
  - Verify: rule 1 does not fire for an API-only session; rule 2 counts bound pairs only
- [x] **T12 (P1, human: ~1d / CC: ~25min)** — ci — One non-matrixed Playwright job
  - Surfaced by: Section 6, decision 9A — the fingerprint claim is unfalsifiable without a real browser
  - Files: `.github/workflows/test.yml`, `tests/live/test_fingerprint.py`
  - Verify: stable hash across runs; different hash under changed timezone/viewport; payload carries only the hash

**M3 — adaptive learning**

- [x] **T13 (P1, human: ~0.5d / CC: ~15min)** — events — Decision `id` + `features` array on every recorded decision
  - Surfaced by: Section 4, decision 4A — events have no identifier and no features, so feedback can neither reference nor train on them
  - Files: `microguard/live/redis_events.py`, `microguard/events.py`
  - Verify: a decision read back from `mg:v1:events` carries 19 floats and a stable id
- [x] **T14 (P1, human: ~15min / CC: ~5min)** — scorer — Run `extract_features` unconditionally
  - Surfaced by: decision 4A — features are currently computed only when a model is loaded
  - Files: `microguard/live/scorer.py`
  - Verify: with no model present, the event still carries features
- [x] **T15 (P1, human: ~1.5d / CC: ~30min)** — training — `record_correction` + `retrain_deployment_model` with rails and atomic `os.replace`
  - Surfaced by: Section 2, decision 6A — a crash mid-write leaves a partial file the mtime watcher will load
  - Files: `microguard/training/online_update.py`
  - Verify: `data/model.json` byte-identical after a retrain; bad JSONL lines skipped and counted
- [x] **T16 (P1, human: ~1d / CC: ~20min)** — scorer — Deployment-model selection; refuse a bad swap and keep the previous model; mtime cached 5s
  - Surfaced by: Section 2 CRITICAL GAP + Section 7 — corrupt model currently degrades to heuristics silently
  - Files: `microguard/live/scorer.py`
  - Verify: corrupt the deployment model; the previous model stays live and health shows the refusal
- [x] **T17 (P2, human: ~1d / CC: ~20min)** — dashboard — Feedback control on rows + `POST /api/live/feedback` open by default
  - Surfaced by: D4.2 + decision 8A — corrections happen where the verdict is seen
  - Files: `gui/src/`, `microguard/dashboard/api_live.py`
  - Verify: double-click writes one row, not two
- [x] **T18 (P2, human: ~0.5d / CC: ~15min)** — dashboard — Shadow would-block counter beside the threshold slider
  - Surfaced by: D4.4 — the required readout for decision 10A's observe-only posture
  - Files: `gui/src/`
  - Verify: at threshold 1.00 the counter is non-zero while blocked stays 0

**Cross-cutting**

- [x] **T19 (P2, human: ~0.5d / CC: ~15min)** — docs — Fourth process + two new failure modes in the runbook
  - Surfaced by: Section 8 — the runbook documents three failure modes; this plan adds two
  - Files: `docs/howto-operate-microguard.md`
- [x] **T20 (P2, human: ~0.5d / CC: ~15min)** — docs — `/fp`, `/fingerprint.js`, `/api/live/feedback`, `mg:v1:signals:*`, `mg:v1:actor:*`
  - Surfaced by: Required outputs — new endpoints and key families
  - Files: `docs/reference-live-api.md`
- [x] **T21 (P3, human: ~15min / CC: ~5min)** — repo — Create `TODOS.md` with the three accepted items
  - Surfaced by: Question 12 — all three accepted, and this repo has no `TODOS.md`
  - Files: `TODOS.md`
- [x] **T22 (P2, human: ~15min / CC: ~5min)** — repo — Promote this plan to `docs/designs/remaining-epic.md`
  - Surfaced by: Question 14 — `specs/` is untracked, so the epic exists only on one machine
  - Files: `docs/designs/remaining-epic.md`

## Stale diagram audit

| Diagram | Location | Still accurate after this plan? |
|---|---|---|
| nginx `auth_request` config | `live/server.py:6-27` docstring | **No** — needs the new public `location /microguard/` |
| `live:v2:` key schema | `live/redis_store.py:7-14` | Yes |
| `mg:v1:` key schema | `live/redis_events.py:6-22` | **No** — `id`, `features`, `signals:*`, `actor:*` |
| Model architecture | `docs/reference-model.md:19` | Yes — the 19-feature vector is deliberately untouched |
| Threading rationale | `live/server.py:232-249` | **Partly** — still true, but now also covers a public POST route |

Three diagrams need updating as part of the work that changes them, not after.

## Engineering review decisions (2026-09-12)

Eleven findings from `/plan-eng-review`, all folded in. Six are P1.

| # | Decision | Chosen |
|---|---|---|
| E1A | Fingerprinting in middleware mode | ASGI and WSGI middleware host `/fp` and `/fingerprint.js` |
| 1A | Where `EMPTY_SIGNALS` lives | Stdlib-only `microguard/signals.py`; Redis side under `live/` |
| 2A | Signals read round trip | `record_request` returns a `SessionSnapshot` (session + signals) |
| 3A | Duplicated fail-open payload | One builder beside the decision shape |
| 4A | Browser test scope | Playwright against the check server; contract test across all three hosts |
| 5A | Cross-IP hash count | Denormalized onto the per-IP record at `/fp` write time |

### The three that change the architecture

**The signals package would have broken `microguard scan`.** `live/__init__.py:7-13`
raises `ImportError` without redis-py, and `events.py:8-11` documents that this is
exactly why `DecisionRecorder` lives outside `live/`. A `signals/` package holding both
`EMPTY_SIGNALS` (imported by `labeler.py`) and the refresher (needing redis and an HTTP
client) would have made `labeler.py` transitively import redis — inverting the seam's
entire guarantee into the failure it exists to prevent. Same split as `events.py`.

**Fingerprinting had no host in middleware mode.** `middleware.py` is a pure
pass-through: it reads `scope["path"]` / `PATH_INFO`, scores, and delegates. It hosts no
routes. The epic locked "both the nginx microservice and the Python middleware ship" as
its first decision, and M2 as originally written silently made one of them
second-class. The middleware now short-circuits the two routes before delegating.

**Rule 2 would have reintroduced the second round trip.** The cross-IP count lives under
`fp_ips:{hash}`, and the hash is only known after reading the IP's record — so the second
read depends on the first and cannot be pipelined. `/fp` knows both the IP and the hash
and runs once per page load rather than once per request, so it writes the count back
onto the per-IP record there. `/check` stays at one Redis round trip.

### Hard requirement, not a preference

`_check_fingerprint_signals` rule 1 must treat an empty `signals` mapping as **not
evaluated**, never as "no fingerprint arrived, therefore bot". In a batch
`microguard scan`, `signals` is empty for every session because fingerprints do not exist
on that path. Written naively, the rule labels every session in every log file a bot.

This is the same shape as the rate-rule bug already fixed in `labeler.py`: a rule written
for one path behaving differently on the other.

### Recorded without a question (no real alternative)

- Lock the deployment-model reload. `server.py:228` shares one `LiveScorer` across
  request threads, so two can both see a stale mtime and both load. The 6A refusal
  belongs in the reload path, not in `_load_model`, which is also called at construction
  where returning `None` is correct.
- Compute `extract_features` when a model **or** a recorder is present, rather than
  unconditionally. `redis_store.py:53-56` documents that call at roughly 2ms per request,
  the dominant per-request cost; with neither a model nor a recorder, nothing consumes it.
- Bound the new public nginx location: `client_max_body_size`, `client_body_timeout`,
  `limit_req`, and an explicit line that port 8400 is never exposed directly. Python's
  docs say `http.server` must not be exposed directly, and the stdlib confirms
  `StreamRequestHandler.timeout` is `None` with no thread cap on `ThreadingMixIn`. nginx
  buffers request bodies by default, so this is mitigated by architecture — but only if
  the documented snippet says so.

### Correction to this document

The M1 section says "all five existing call sites." There are six production call sites
for `label_session` — `cli.py:114`, `watch.py:183`, `labeler.py:424`,
`training/train.py:49`, `training/build_real_dataset.py:102`, `live/scorer.py:126` —
plus 58 in the test suite.

### Additional tasks

- [x] **E1 (P1, human: ~15min / CC: ~5min)** — signals — Split `EMPTY_SIGNALS` into a stdlib-only module
- [x] **E2 (P1, human: ~0.5d / CC: ~20min)** — live — `record_request` returns a `SessionSnapshot`
- [x] **E3 (P1, human: ~15min / CC: ~5min)** — live — **CRITICAL REGRESSION TEST**: real store and in-memory double return one shape
- [x] **E4 (P1, human: ~0.5d / CC: ~15min)** — labeler — Rule 1 treats empty signals as not-evaluated
- [x] **E5 (P1, human: ~1d / CC: ~25min)** — middleware — Host `/fp` and `/fingerprint.js` in ASGI and WSGI
- [x] **E6 (P1, human: ~0.5d / CC: ~15min)** — live — Denormalize the cross-IP count at `/fp` write time
- [x] **E7 (P2, human: ~20min / CC: ~5min)** — live — Merge the duplicated fail-open payload
- [x] **E8 (P2, human: ~20min / CC: ~5min)** — scorer — Lock the model reload; refusal in the reload path
- [x] **E9 (P2, human: ~0.5d / CC: ~15min)** — ci — Contract test across all three `/fp` hosts
- [x] **E10 (P2, human: ~15min / CC: ~5min)** — scorer — `extract_features` when model OR recorder present
- [x] **E11 (P3, human: ~20min / CC: ~5min)** — docs — Bound the public nginx location

Test coverage for the assembled plan: 58 code paths and user flows identified, 1 currently
covered (the existing rule chain with `signals` absent, which is what the empty default
preserves). Three were CRITICAL and are closed by E2/E3, the 6A refusal, and E4.

Revised totals: M1 ~4 days, M2 ~8 days, M3 ~7 days human. Roughly 8-10 hrs with CC.
