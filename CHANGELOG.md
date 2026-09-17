# Changelog

## [Unreleased]

### Removed

- **The entire Databricks + MLflow integration.** A 2 KB, 19-feature,
  4-neuron micrograd model does not need experiment tracking or a cloud model
  registry, and the surface was net-negative: the test suite once logged to a
  real workspace, and it drove the redis-type and normalization fallout. Gone:
  `microguard/tracking.py`, the `/api/mlflow/runs` dashboard route
  (`api_mlflow.py`), the `--model-source registry` / `--no-mlflow` CLI flags
  and `__registry__` model path, MLflow logging in `train`/`scan`, the
  `[mlflow]` extra, the `databricks-app/` deployment harness, and
  `scripts/deploy-databricks.sh`. The dashboard SPA never called the MLflow
  route. Detection is unchanged; it never depended on any of this. See #24.

## [3.0.1] - 2026-09-12

### Fixed

- **The Databricks integration was never connected, and never could have been.**
  `databricks-app/app.py` and `app.yaml` imported
  `microguard.dashboard.app:asgi_app`, which does not exist — the factory is
  `create_app` — so the Apps deploy would have failed at import. `app.yaml` and
  `databricks.yml` both used invented schemas rather than the real Databricks
  Apps / Asset Bundle ones, and `requirements.txt` installed
  `microguard>=0.2.0` from PyPI, where this package is not published. All four
  rewritten against the real contracts.

  The entry point now refuses to start without `MICROGUARD_API_TOKEN`.
  `microguard dashboard` binds loopback because the UI reports every blocked
  visitor; Databricks Apps is not loopback, so the shared-secret gate is
  mandatory there and `allow_config_writes` is pinned off.

- **A failed MLflow call said nothing.** `scan` runs with tracking ON by
  default pointing at `databricks`, which needs credentials to resolve.
  Without them `init()` raised, `cli.py` caught it with a bare `pass`, and the
  scan exited normally having recorded nothing — indistinguishable from a run
  that recorded everything. Failures now name the resolved tracking URI
  (`tracking.resolved_tracking_uri()`, which does not need mlflow imported to
  answer) and never change a scan's exit code. `ImportError` stays quiet:
  mlflow is an optional extra, and absent is not broken.

- **Version drift.** `setup.py` said `2.0.0` while `microguard/__init__.py`
  said `3.0.0` and `cli.py info` printed a third hardcoded literal. `setup.py`
  now parses the version out of the package, and both the CLI and the tests
  read `__version__` rather than restating it.

- **Train/serve normalization skew.** `training/train.py::normalize_features`
  maps a zero-range feature column to `0.5`; `model.py`'s `predict()` mapped
  the same column to `0.0`, so any column constant across the training set
  reached the network as a value it was never trained on. One column is
  affected in the shipped model (`method_mismatch_count`). `predict()` now
  goes through `BotDetector.normalize()`, the single implementation, and
  returns `0.5` to match training.

  Consequence worth knowing: the live path zeroes two features it cannot
  compute before the app responds, and the measured worst-case score shift
  from that went from 0.0183 to 0.1086. The model is more status-sensitive
  than the old number implied — the old number was low because the network
  was being run off its trained operating point, not because the margin was
  wide. No holdout decision flips.

- **`retrain_deployment_model` fitted the wrong scale.** It handed raw
  correction features to `train()` while `predict()` normalizes, so every
  per-deployment model was fitted on one scale and served another. Same
  family as the missing-`normalization.json` bug above, on the path an
  operator drives by hand. Corrections are now normalized before training.

- **Training could collapse to a constant classifier and be saved anyway.**
  Roughly a quarter of random initializations produce a network whose hidden
  units never fire: with non-negative inputs and zero biases, a unit whose
  weights sum negative cannot activate, and a ReLU that never fires has no
  gradient — the weights come back bit-for-bit unchanged. More epochs do not
  help. Neither does fan-in (He) weight scaling; both were measured and
  neither moved the failure rate.

  Two guards now:
  - `BotDetector.check_not_degenerate()` raises `DegenerateModelError` when a
    model labels every training session the same class while the labels
    contain both. Checked before `os.replace` in `retrain_deployment_model`
    and before `save()` in `train_model`.
  - `BotDetector.train_until_it_learns()` redraws and starts over on a
    collapse, up to five attempts. Fresh training redraws the network;
    fine-tuning reloads the baseline it is adapting. End-to-end retrain
    success went from ~28/40 seeds to 37/40.

  `BotDetector.has_live_hidden_units()` catches the case retries cannot fix:
  a baseline that is itself dead reloads identically every attempt, so it is
  named directly rather than reported as a generic collapse.

## [3.0.0] - 2026-09-12

### Breaking

- **`SessionStateStore.record_request` returns a `SessionSnapshot`**, not a
  `LiveSession`. The snapshot carries the session plus the signals resolved for
  that actor, so both arrive in one Redis round trip on the path nginx waits
  on. Anyone who implemented the Protocol — it is documented as an extension
  point in `reference-live-api.md` — needs to return the new shape; read
  `snapshot.session` where you previously had the session.
- **Actor records moved to `mg:v2:actor:`** and are a Redis HASH rather than a
  JSON string. v1 keys are never touched and expire on their own. The prefix is
  versioned because `HINCRBY` against a v1 string is `WRONGTYPE`.
- `label_session` takes a second `signals` argument. It defaults to
  `EMPTY_SIGNALS`, so every existing caller is unaffected.

### Added
- **Per-deployment adaptation.** An operator corrects a wrong verdict from the
  dashboard; `microguard retrain --deployment-id <id>` fine-tunes the baseline
  on that deployment's own confirmed corrections and publishes a model the
  running check server picks up within about five seconds, with no restart and
  no dropped sessions.
  - **The shipped baseline is never written.** One deployment's bad corrections
    must not corrupt what every other deployment, and every fresh install,
    starts from. Rolling back is deleting one file.
  - Decisions now carry an **id** and the **feature vector** they were made
    from. Neither existed, and without both a correction has nothing to point
    at and nothing to train on: the live session is a 200-entry sliding window
    on a 1800s TTL, so by the time anyone reviews a block, the inputs are gone.
  - Corrections are keyed by decision id, so a double-click or a changed mind
    is one example with one label. Recording is open by default and retraining
    is the gated step, because a recorded correction changes nothing until
    someone deliberately acts on it.
  - Both safety rails refuse rather than crash, and say what would change the
    answer: fewer than 50 corrections, or more than 90% one class.
- **Signal promotion.** `mg:v1:config` now carries the list of sources allowed
  to decide a verdict, settable from the dashboard and read per request. Every
  signal built in this release ships observe-only; nothing blocks until you
  promote it.
- **A shadow counter** beside the threshold slider: how many of the last N
  decisions a candidate threshold would block, and how many more or fewer that
  is than actually happened. Observe-only mode is the documented way to start a
  deployment, and until now it produced no number at all.

### Fixed
- A corrupt deployment model degraded the scorer to heuristics-only with **no
  symptom**: no exception, no warning at request time, `model_score` pinned at
  0.0 and every blend quietly missing 60% of its signal. The scorer now refuses
  a model it cannot load, keeps the one that works, and reports the refusal on
  every decision so the dashboard can show it.
- A retrained model was published without the `normalization.json` that
  `load()` reads from the directory beside it, so it would have scored **raw**
  features while trained on scaled ones — the same mismatch that once left this
  project with 2.4% held-out bot recall instead of 100%, silently. The
  baseline's normalization now travels with every deployment model.
- `/api/live/events` and the SSE stream no longer ship the stored feature
  vector. The browser has no use for 19 floats per row, and a per-session
  behavioural vector should not travel further than it needs to.

- **Browser fingerprinting.** `GET /fingerprint.js` and `POST /fp`, served by
  all three deployment hosts. The script collects canvas, WebGL, font, screen
  and timezone signals, hashes them with SHA-256 **in the browser**, and sends
  only the digest — the server never receives a raw component and cannot
  reconstruct one.
  - **This raises the bar; it does not win an arms race.** A determined
    operator running real headless Chrome produces a perfectly good
    fingerprint. The population this catches is the much larger one that never
    runs JavaScript at all: plain HTTP clients, simple scripts, naive scrapers.
  - **A hash is only accepted from an IP that already has session history, and
    only once per session.** Without that, `/fp` is an amplification vector: an
    attacker who harvests a hash real browsers produce could replay it from a
    botnet and get those real users blocked by the cross-IP rule.
  - Every outcome answers 200 with identical bytes. A 4xx would hand an
    unauthenticated caller an oracle for which IPs are bindable, and would
    surface a microguard problem as an error on someone else's page.
  - Both rules are observe-only until promoted, like every other signal.
- **Actor identity.** `mg:v2:actor:{hash}` links sessions across IP changes
  with a 30-day sliding TTL. A returning fingerprint from a new address is the
  one signal IP reputation structurally cannot provide.
- **AbuseIPDB**, optional and keyed. With no `ABUSEIPDB_API_KEY` the signal is
  inert and nothing is broken. Two budgets are respected: a response cache and
  a daily counter, because exhausting the free tier gets the key rate-limited,
  which takes the signal down for every address rather than one.
- **A browser CI job.** Playwright against real Chromium on a single runner,
  asserting the hash varies with the environment and that the network payload
  contains the digest and nothing else. The privacy claim is read off the wire
  rather than asserted in prose.

### Fixed
- **`/fp`'s first-hash-wins gate was a check-then-set race**, and an attacker
  could win it on purpose. Two concurrent submissions from one bound IP with
  different hashes both read "nothing bound", both passed the gate, and both
  recorded — letting a single IP with a live session credit an unlimited number
  of harvested hashes and inflate the cross-IP count for each. That is exactly
  the amplification the binding rule exists to prevent. The binding is now
  claimed atomically with `SET NX`.
- Actor records are a Redis HASH (`mg:v2:actor:`) rather than a JSON string, so
  sightings increment with `HINCRBY` instead of a read-modify-write that lost
  increments under precisely the traffic the number describes: a farm hitting
  one fingerprint from many addresses at once. The prefix carries a version
  because `HINCRBY` against a v1 string is `WRONGTYPE`.
- `hosting` is no longer offered as a promotable signal. It is resolved and
  recorded, but no rule reads it, so promoting it produced an "enforced" badge
  and zero enforcement — permanently and silently. A test now asserts every
  promotable source has a rule that reads it.
- The ASGI `/fp` handler no longer blocks the event loop on Redis I/O.
- The fingerprint script now says why it cannot run on a plain-HTTP origin.
  SubtleCrypto only exists in a secure context, so on HTTP the script was inert
  and no fingerprint ever arrived — which, because the absence rule reads a
  missing fingerprint as evidence, would have made an HTTP site look like it
  was full of bots. It logs a console warning instead of returning silently,
  and the deploy guide says so.

- **A signal seam, so external reputation data can reach the rules without
  reaching the request path.** `label_session` now takes a `signals` argument
  and stays a pure function of its arguments. It is called inline on every
  nginx `auth_request` (`live/scorer.py`), so a lookup performed inside a rule
  would put a network round trip in front of a real visitor, where nginx turns
  slowness into a 500. Signals are resolved before the call instead.
  - `microguard/signals.py` is stdlib-only and lives outside `live/` on
    purpose: `live/__init__.py` raises ImportError without redis-py, and
    `labeler.py` is on the `microguard scan` path. Two tests spawn a fresh
    interpreter and assert that importing either module leaves `redis` out of
    `sys.modules`.
  - `Signals.resolved` separates "we looked and found nothing" from "we never
    looked". In a batch scan nothing is ever resolved, so a rule reading
    absence as evidence would label every session in every log file a bot.
  - `Signals.promoted` carries the deployment's opt-in list. A resolved but
    unpromoted signal is recorded on the decision and decides nothing, so an
    operator can measure what enforcing it would cost before enforcing it.
- **`microguard signals`** — the slow tier, in its own process. Fetches the Tor
  exit-node list and AWS prefix ranges from their published keyless endpoints,
  caches them with a stale-on-failure fallback, and resolves signals only for
  actors that already have a live session. Writes a heartbeat that never
  expires, so "never started" stays distinguishable from "died an hour ago".
- **`microguard explain <ip>`** — the session, the resolved signals, their
  promotion state, and the rule that decided the verdict. Read-only: it reads
  the session back rather than recording a request, because diagnosis must not
  change the thing being diagnosed.
- **Signal health in the dashboard sidebar.** Every signal here fails silently
  by design, and a source that has been dead for a week looks identical to a
  clean actor. The sidebar names the source and the reason.

### Changed
- `SessionStateStore.record_request` returns a `SessionSnapshot` (session plus
  signals) rather than a bare session, so the signals read rides along in the
  existing pipeline. On a remote Redis that is one 15ms wait on the
  `auth_request` path instead of two. A test asserts exactly one pipeline
  execution per scored request, and another asserts the in-memory test double
  and the real store return the same shape — a drifted double would make every
  live test pass against something Redis never produces.
- `extract_features` now runs when a model **or** a recorder is present rather
  than only when a model is loaded. It is roughly 2ms and the dominant
  per-request cost, so a deployment with neither no longer pays for a vector
  nothing reads.

### Fixed
- The fail-open decision payload was duplicated verbatim in `live/server.py`
  and `live/middleware.py` — twelve identical keys and the same comment. Both
  now build it from one function. A payload missing a key the dashboard reads
  fails during an outage, which is the worst possible time to find it.

- **Test coverage raised from 77% to 100%**, 502 tests to 776. The number is
  the side effect; the work was fixing tests that could not fail and covering
  detection logic that had never run.
  - `labeler.py` 85% → 100%: all 21 previously-unexercised rule returns,
    including the WAF protected-endpoint scan, API-key scanning, credential
    and POST brute-force, botnet signatures, directory brute-force, UA
    rotation, HTTP/1.0-only, and the sustained-rate rule. Plus the two
    exemptions that exist to prevent false positives — a GraphQL session must
    not trip the single-endpoint rules, and a gRPC session must not trip
    uniform timing — and a guard test pinning evaluation order itself.
  - `training/` 0% → 100%: `generate.py`, `train.py` and
    `build_real_dataset.py`. Every writing path is redirected to `tmp_path`;
    `build_dataset` runs against fixtures in milliseconds rather than the 98
    seconds the real corpus takes.
  - `scanner.py` 77% → 100%, without adding network egress. New
    `tests/test_scanner_http.py` runs a loopback `ThreadingHTTPServer`,
    following the pattern `test_scanner_ws.py` already used, which covers
    `probe_url_multiple` and `probe_and_analyze` — both previously untouched.
  - `model.py` 70% → 100%: `BotDetector.train` had no test at all.
  - Live-path gaps: `LiveSession.add_request` (no test had ever called it),
    the ASGI middleware's fail-open path (the WSGI one was covered), and
    `_extract_ip`'s `trust_forwarded_for` branch, which is a documented trust
    boundary.
  - Two of the 19 features, `method_mismatch_count` and
    `max_sustained_click_rate`, had never been computed as anything but zero.
  - CI now gates at `--cov-fail-under=98`.
- **Real-time inline blocking** (`microguard/live/`, spec 0001) — the live path
  that had shipped across seven commits without a changelog entry:
  - `microguard serve` — a threaded stdlib HTTP server answering nginx
    `auth_request` on `GET /check` with 200/403 plus the full decision as JSON
    and `X-Microguard-*` headers.
  - `MicroguardASGI` / `MicroguardWSGI` — the same scoring in-process for
    FastAPI/Starlette and Flask/WSGI apps.
  - `LiveScorer` — the one place real-time scoring happens; returns the whole
    decision (blended score, model score, heuristic label/confidence/reason),
    not just the verdict.
  - `RedisSessionStateStore` — session history as a capped Redis LIST
    (`live:v2:{ip}`, 200 entries, sliding TTL), appended and read back in one
    atomic pipeline. The earlier get/mutate/set shape lost concurrent appends
    from the same actor: 9 of 20 survived under load.
  - `scoring.compute_combined_score()` — the single blend, shared by `scan`,
    `watch` and the live path.
  - Six Diataxis documents under `docs/` covering the live path.
- **Light mode in the dashboard.** A three-state preference — system, light,
  dark — resolved in `gui/src/theme.ts` and written to `<html>` as a concrete
  `data-theme`, so the CSS carries two token blocks and no media query that
  could fight an explicit choice. Defaults to the OS setting and tracks it live
  while on "system"; an explicit choice persists and outranks it. The light
  palette is the one `report.py` already uses for `@media print`, keeping the
  dashboard and the printed report recognizably one product, with the semantic
  colours darkened because `#f59e0b` amber measures 2.05:1 on the light card
  and fails WCAG AA — every light token now measures at or above 4.5:1. Also
  converted eleven `rgba()` literals in `index.css` into tokens; they were
  keyed to white and would have been invisible on a light background.
- **Web dashboard** — `microguard dashboard` serves a TypeScript SPA and its API
  on one port (default `127.0.0.1:8500`):
  - Live tab: decisions streamed over SSE, a score histogram, most-blocked IPs,
    and loud treatment of the two states that silently change every verdict —
    no model loaded, and failing open.
  - Scan tab: upload or pick a bundled log, re-slice verdicts against a
    threshold client-side, open any session's 19 features, and export through
    the existing `report.py` formatters.
  - Model tab: the 19 → 4 → 1 network, per-input influence, and a confusion
    matrix / ROC / score distribution that move with the threshold. A perfect
    result is labelled as a caution, not a win.
  - `gui/` — Vite + React + TypeScript, 87 tests. The build is copied into
    `microguard/dashboard/static/` and shipped in the wheel, so running the
    dashboard never needs Node. New `dashboard` extra.
- **Decision recording** — `microguard/events.py` (`DecisionRecorder` protocol,
  in-memory implementation) and `microguard/live/redis_events.py` (Redis-backed,
  `mg:v1:` keys). `LiveScorer` tees every decision to it, including the
  `automated-integration` short circuit. Recorder failures are logged and
  swallowed: recording exists for the dashboard, blocking exists for the site,
  and the second must never depend on the first.
- **Runtime block threshold** — `RedisRuntimeConfig` stores an override in
  `mg:v1:config`, and `LiveScorer` reads it once per request (cached ~5s). The
  dashboard can move the live threshold with `--allow-config-writes`, and every
  scoring process sharing that Redis follows within seconds, without a restart
  dropping in-flight sessions. An unreachable or unreadable config leaves the
  configured threshold standing.
- `block_threshold` added to the decision payload — the bar the request was
  actually judged against. `null` on the fail-open payload, where no threshold
  was consulted.
- `microguard dashboard --token` — a shared secret required in
  `X-Microguard-Token` on every `/api` request, for deployments that cannot stay
  on loopback.
- `docs/howto-run-the-dashboard.md`, plus a Dashboard API section in
  `docs/reference-live-api.md`.
- `docs/howto-operate-microguard.md` — running a deployment by hand: what runs
  itself versus what needs you, telling the three failure modes apart (a dead
  process is a 500 outage, not fail-open), what a restart costs versus what
  flushing Redis costs, why a retrained model needs a restart, and Redis
  housekeeping. Includes an optional systemd unit for anyone who later decides
  they want supervision after all.
- `tests/conftest.py` — shared `make_entry`/`make_session`/`nginx_log_file`
  fixtures, replacing three near-identical hand-rolled `_make_entry` copies
  across `test_features.py`, `test_labeler_rules.py`.
- `tests/test_cli.py` (20 tests) — `cli.py` (550 lines: `scan_logfile()`,
  `main()`, all argument parsing, score-blending) had zero dedicated tests
  before this. Covers exit codes, output formats, the `automated-integration`
  exclusion, the probe ws://-vs-http(s) dispatch, and a direct regression
  test for the heuristic/model score-blending symmetric cap.
- `TestWatchLogfile` in `tests/test_watch.py` (4 tests) — `watch_logfile()`'s
  130-line orchestration loop was untested (only its two small helpers
  were). Required adding a test-only `_max_iterations` seam to
  `watch.py::watch_logfile` to terminate its otherwise-infinite loop.
- Coverage tooling: `pytest-cov` (dev-only, `requirements-dev.txt`),
  `pyproject.toml` pytest/coverage config, wired into CI. Baseline: 71%
  overall; no hard gate yet.

### Known defects, recorded rather than fixed

These surfaced while writing the tests above. Each is pinned by a test that
names it as a defect, so the eventual fix reads as a deliberate change rather
than a regression.

- ~~**Train/serve normalization skew.**~~ Fixed — see [3.0.1].
- **Heuristic rule 22 is unreachable.** `Cloudflare-protected site, normal
  browser` (human, 0.65) exists to protect a real visitor whose UA carries a
  CDN marker. Rule 5 returns `bot` at 0.90 for any UA matching the same CDN
  pattern, seventeen rules earlier, so such a visitor is labeled a bot instead.
  Marked `# pragma: no cover` in the source with the explanation.
- **The synthetic top-up cap does not do what its comment says.**
  `build_real_dataset.py` says the cap keeps "real data the majority of the bot
  class", but it caps synthetic rows at 30% of a *target* derived from the human
  count. With a thin real-bot corpus the synthetic share reaches 60-75%. It
  does not bite today (2,500 real bots against 1,000 humans yields zero
  synthetic rows) but would if the corpus shrank.
- **`build_dataset` raises on an empty corpus.** With no sessions and no human
  class, the final `zip(*combined)` unpacks an empty list and raises
  `ValueError`.
- **`data/real_bot_training_data.json` is stale.** Rebuilding it today yields
  3,511 samples against the committed 3,580 (`heuristic_real` 2,029 versus
  2,098), because `label_session` has changed since it was generated. The
  `ground_truth` count is stable at 482 and is pinned as a regression anchor.

### Fixed
- **Eleven tests passed while exercising different code than their names
  claimed.** Coverage found them; the defect underneath is an assertion too
  weak to fail.
  - `tests/test_labeler_rules.py` (8): `label_session` evaluates ~24 rules in
    order and returns on first match, and every bot rule returns the label
    `bot`. Each of these tests built its session with a convenient bot-shaped
    user agent (`Go-http-client/1.1`, `python-requests`, `Bot0/1.0`) that
    tripped rule 1 or rule 3 long before the rule under test, then asserted
    only `label == 'bot'`. The directory-brute-force test exercised the
    known-bot-UA rule; the UA-rotation test exercised uniform timing; and so
    on. Thirteen of the ~24 detection rules had never executed in any test run.
    Every rule test now asserts the reason string and the confidence, which
    together identify a rule uniquely, and the sessions were rebuilt to reach
    the rule they name.
  - `tests/test_scanner.py` (2): `test_probe_bad_ssl` reached out to
    `self-signed.badssl.com` and asserted `timing >= 0`, true whether the
    probe succeeded, was refused, or never left the machine — on all 12 CI
    matrix jobs. Replaced with a loopback refusal that asserts an actual error.
  - `tests/test_parser.py` (1): `test_parse_missing_file` caught the
    `FileNotFoundError` from a bare `open()` inside `detect_format`, not the
    handler it was named for. It now passes an explicit format and matches the
    message.
- **The check server answered a browser with a bare 404.** `microguard serve`
  is the nginx `auth_request` backend, with one route and per-request logging
  suppressed, so a healthy server looks dead: the terminal stays blank, the
  prompt never returns, and opening `http://127.0.0.1:8400` in a browser
  produced the stdlib 404 page with no explanation. It now answers any path
  other than `/check` with plain text naming `/check`, pointing at
  `microguard dashboard` for the UI, and giving a working `curl` line built
  from the address actually bound rather than a hardcoded 8400. The status is
  still exactly 404 — nginx turns anything outside 2xx/401/403 into a 500, so a
  misconfigured `proxy_pass` must keep behaving as it did. The startup banner
  gained a matching line.
- **The blocked-IP set grew without bound.** `mg:v1:blocked_ips` held one entry
  per distinct blocked address, `ZINCRBY`'d on every block and never trimmed or
  expired — the only structure in the system that grew with the number of
  distinct attackers rather than with traffic volume, so against a rotating
  botnet it had no ceiling. The in-memory recorder's `Counter` had the same
  defect. Both are now capped at `MAX_TRACKED_IPS` (1,000, a hundred times the
  ten the dashboard displays). On the Redis side the trim rides the pipeline
  that was already being sent, so recording is still one round trip. Trimming
  keeps the highest counts, so a brand-new address can be evicted before it
  surfaces in the top-ten display — the right trade for a structure that
  answers "who is hitting hardest", and noted in both docstrings.
- **Twelve `open()` calls in the package had no explicit encoding** — in
  `model.py`, `training/train.py`, `training/build_real_dataset.py` and
  `training/generate.py`. Without one, Python falls back to the OS locale
  encoding, so `model.json` and every training artifact round-trip differently
  on a Windows host than on Linux. Latent rather than live, since `json.dump`
  writes ASCII by default, but it is the same defect `parser.py::_open_text`
  was fixed for, and the test suite hit the reading half of it on the Windows
  CI jobs. Found by sweeping with `PYTHONWARNDEFAULTENCODING`, which now
  reports nothing for the package or the suite.
- **`microguard/training/generate.py` wrote outside the repo's data
  directory** — its `__main__` block walked two `dirname`s instead of three, so
  `python -m microguard.training.generate` created
  `microguard/data/training_data.json` inside the package rather than
  `data/training_data.json`. `train.py` does the same walk correctly.
- **`docs/howto-retrain-the-model.md` claimed training takes "seconds, not
  hours"** — measured at 2 to 3 minutes for a full run, about 100x the
  implied figure. Corrected with the measurement.
- **`tests/test_model.py::test_train_step` was a 2%-per-run flake** — it built
  an unseeded `BotDetector`, and on roughly 2% of random inits every hidden
  ReLU sits at zero for both of its input patterns, leaving the output bias as
  the only live gradient. The batch is symmetric (ten targets at +1, ten at
  -1), so that gradient cancels exactly, the model does not move, and the
  assertion fails through no fault of the code. Across a 12-job CI matrix that
  is close to a coin flip per run. Seeded, with the mechanism written down.
- **The dashboard's SPA fallback swallowed `/api` 404s on Windows** — the
  guard read the path StaticFiles hands its handler, which is
  `os.sep`-normalized, so `api\nope` never matched a `"api/"` check and a
  mistyped endpoint returned 200 with the HTML shell instead of a JSON 404.
  The decision now comes from the ASGI scope's request path, extracted as
  `_is_api_path()` and unit-tested on both platforms' shapes.
- **Captured API fixtures could never match on a second run** — the live
  decisions in `gui/src/api/__fixtures__` were scored through a store that
  stamps `time.time()`, so `duration`, every timing feature derived from it,
  and therefore `model_score` changed on every capture. The capture store now
  anchors the session clock to the log's own timestamps, which also makes the
  fixtures realistic (a 34s browser session rather than a 1.7ms artifact).
- **`microguard probe <url> --verbose` crashed with a `TypeError`** — `cli.py`
  called `format_probe_report(results, verbose=True)`, but that function has
  never taken a `verbose` argument. The function that does the verbose
  rendering, `format_probe_verbose()`, sat unused next to it; it is now wired
  in, and `probe --verbose` is covered in `tests/test_cli.py`. This was the
  last remaining `vulture` finding in the package.
- **`watch.py` had the same heuristic/model score-blending asymmetry bug
  already fixed in `cli.py`** — an independent, undiscovered copy of the
  same logic. A confident heuristic 'human' call (e.g. a GraphQL session)
  could still be overridden by the model's score in watch mode. Found
  while writing `TestWatchLogfile`; fixed with the same symmetric cap.
- `scan_logfile()` raised a raw `FileNotFoundError` for a missing log file
  instead of returning its own established `{'error': ...}` dict shape
  (the graceful path only existed in `main()`'s pre-check, not in the
  underlying function documented and exported as part of the Python API).
- CI's CLI smoke test had `continue-on-error: true`, silently swallowing a
  genuine crash (it was added because `microguard scan` correctly exits 1
  when it detects bots — but that setting also ignores real breakage). Now
  checks stdout for a traceback / the expected report header instead of
  relying on exit code, which can't distinguish "detected bots" from
  "crashed" (both exit 1).

## [2.0.0] - 2026-09-06

v2.0 replaces the synthetic-only bot training data with real ground-truth
attack traffic, fixes a real false-positive bug affecting GraphQL/SOAP/RPC/
gRPC APIs, adds a real WebSocket probe, and corrects several claims in the
tool's own output that didn't hold up (a live-probe "ML score" that wasn't
a valid inference, a 95% accuracy number measured on the training set
itself). Beta: see README's Known Limitations before production use.

### Added
- **Real training data.** `training/groundtruth.py` + `training/build_real_dataset.py`
  build the bot class from real, forensically ground-truth-labeled attack
  traffic (`data/zenodo_data/organization-x/`: 213K real Apache log lines,
  39 real attack-pattern rules — SQLi, RCE, directory scanning, brute-force
  login, etc.) instead of `random.uniform()` synthetic data. Combined with
  real Harvard human session data; synthetic data is now a capped top-up
  for underrepresented attack subtypes only, not the bulk of the bot class.
- **Held-out generalization eval.** `training/train.py::train_model` now
  carves out a session-actor-level stratified split *before* training and
  saves it as `data/eval_holdout.json`; `tests/test_training_quality.py::TestHeldOutAccuracy`
  evaluates against it, including a recall check isolated to ground-truth
  (not heuristic) labels specifically.
- **Adversarial eval.** `data/adversarial_eval.json` + `TestAdversarialRobustness`
  measure (don't gate on) recall against a synthetic browser-mimicking
  stealthy-bot generator — an honest measurement of a known blind spot.
- **WebSocket probe.** `microguard probe wss://...` — hand-rolled RFC 6455
  handshake over stdlib `socket`/`ssl` (no new dependency), with its own
  heuristic scorer, terminal/HTML formatters, and 15 tests against an
  in-process echo server.
- **Webhook / RPC-client allowlist.** Recognized senders (Stripe,
  GitHub-Hookshot, Shopify, grpc-go/java/python/..., etc.) are labeled
  `automated-integration` — automated by definition, not scored as a
  security threat, excluded from bot-rate counts.
- **`--output nginx` / `--output cloudflare`** on `microguard scan` —
  auto-generate an nginx deny-list or Cloudflare Firewall Rule expression
  for DANGER-scored (0.80-1.00) IPs, deduped and sorted. Scan-only.
- **`status_code_entropy` feature** (replaces the permanently-hardcoded-0
  `field_fill_speed`) — Shannon entropy of a session's HTTP status codes,
  a real signal distinct from `error_rate`.

### Fixed
- **GraphQL false positive:** `/graphql` was in `API_KEY_SCAN_PATTERNS`,
  branding every legitimate GraphQL client a credential-scanning bot at
  0.75 confidence. Removed.
- **Single-endpoint API false positives:** GraphQL/SOAP/RPC paths are now
  exempt from the "same endpoint = scraper" heuristics, at *both* the
  heuristic-label layer and the score-blending layer in `cli.py` (a
  heuristic fix alone didn't change the final classification — the model's
  independent score could still override it; added a symmetric cap
  mirroring the existing bot-confidence floor).
- **gRPC uniform-timing false positive:** HTTP/2 multiplexing produces
  near-uniform request timing for legitimate clients; the "uniform timing
  = bot" rule now skips sessions with ≥3 distinct `/Service.Method` paths.
- **`probe` no longer feeds live-probe data through the session-trained
  MLP.** `_probe_features_to_vector` mapped unrelated response data into a
  vector shaped for session-log features, then called `model.predict()` on
  it — not a valid inference. Removed; probe scoring is now the heuristic
  alone, and displayed output is relabeled "Automation Fingerprint" instead
  of implying visitor bot/human classification.
- **95% accuracy claim was circular:** it was measured on the model's own
  training set. `TestModelAccuracy` is now explicitly documented as a
  train-set fit sanity check; `TestHeldOutAccuracy` is the real number.
- **Python version claim:** `setup.py`/CI claimed 3.8+ while the codebase
  already used 3.10-only `X | Y` union syntax throughout (pre-existing,
  not introduced this release). Bumped `python_requires` to `>=3.10` and
  dropped the 3.8/3.9 CI legs to match reality.
- Malformed or empty log files rendered as a fake "✅ HEALTHY, 0.0%" report
  in terminal and HTML output instead of surfacing the parse failure — the
  `error` field `scan_logfile()` sets was silently dropped by two of four
  report formatters (`format_json`/`print_report` were unaffected). Also
  fixed the HTML donut chart, which drew a solid danger-red ring for
  zero-session data. Both `format_nginx_denylist`/`format_cloudflare_rule`
  now inherit the same fix.
- `_check_botnet_signatures`'s UA-rotation heuristic false-flagged every
  1-3 request session as a bot — the scaled threshold
  `min(10, request_count * 0.3)` drops below 1 for small sessions, so any
  single-UA session (the normal case) trivially satisfied it.
- `--output-file` to a missing/invalid directory crashed with a raw Python
  traceback instead of a clean CLI error, across all three write sites
  (scan, scan --verbose, probe).
- Cleared all `ruff`/`mypy`/`vulture` findings (270 lint errors, 7 type
  errors, 12 dead-code items) without changing behavior; added `mypy.ini`
  and `microguard/vulture_whitelist.py`.

## [0.1.0] - 2026-09-04

Initial release. Everything built in one session.

### Core Engine
- **Log parser** — Nginx combined and JSON log formats with auto-detection
- **19 feature extractors** — timing (5), behavioral (4), header (3), payload (2), context (1), bonus (4)
- **24 heuristic rules** across 4 confidence tiers for bot/human classification
- **micrograd MLP** — 19→4→1 architecture, 85 parameters, ~1.8KB
- **Score fusion** — 60% ML model + 40% heuristic, capped at heuristic confidence for bots

### CLI Commands
- `microguard scan <logfile>` — scan log files for bot traffic
- `microguard probe <url>` — probe live URLs for bot detection signals
- `microguard scan <logfile> --watch` — continuous log file monitoring
- `microguard info` — show version and feature info
- Auto-sample on first run — bare `microguard` scans bundled sample log

### CLI Flags
- `--verbose` / `-v` — full feature vector breakdown with heuristic rule details
- `--json-pretty` / `-j` — colored JSON output for terminal reading
- `--watch` / `-w` — continuous log monitoring with real-time alerts
- `--output {terminal,json,html}` — multiple output formats
- `--output-file` — save reports to file
- `--threshold` — adjustable bot score threshold (default: 0.7)
- `--user-agent` — custom User-Agent for probe requests

### Output Formats
- **Terminal** — ANSI-colored with score bars, risk labels (SAFE/LOW/WARNING/DANGER), colored recommendations
- **JSON** — machine-readable, indented
- **JSON Pretty** — colored keys, scores, and labels for terminal scanning
- **HTML** — dark theme, donut chart, sortable table, print-friendly
- **Verbose** — per-session feature vectors with bot/human indicators

### Score Interpretation
- SAFE (0.00-0.30) — no bot signals detected
- LOW (0.31-0.59) — minor signals, likely human
- WARNING (0.60-0.79) — suspicious, investigate
- DANGER (0.80-1.00) — high confidence bot traffic

### Heuristic Rules (24 total)

**High Confidence (0.90-0.99):**
- Known bot/monitoring user agents (80+ patterns)
- Vulnerability scanner URL patterns
- Uniform timing patterns
- HTTP/1.0-only clients
- Cloudflare WAF bypass detection
- Attack tool signatures (Nuclei, ffuf, Masscan, etc.)
- Botnet scanning patterns (Mirai, IoT endpoints)

**Medium Confidence (0.70-0.89):**
- High request rates (>100 requests, >50 req/min)
- Same-endpoint scraping
- No referrer on all requests
- High error rate (>50% failed)
- Repeated API endpoint abuse
- API key parameter scanning
- Credential brute-force detection
- Directory brute-force detection
- UA rotation detection

**Low Confidence (0.55-0.69):**
- Unknown user agents
- Short fast sessions
- Night-time activity patterns

**Human Signals (0.55-0.75):**
- Known browsers with normal behavior
- Variable timing patterns
- Multiple endpoints explored
- Natural referrer chains
- Behind Cloudflare with normal browser

### Live Probing
- HTTP/1.1 requests with timing measurement
- Security header detection (CSP, HSTS, X-Frame-Options)
- Body entropy analysis
- Timing consistency analysis (CV calculation)
- Cloudflare CDN detection (CF-Ray, server_bot_score)
- Multi-probe support for timing pattern analysis

### Continuous Monitoring (`--watch`)
- Tails log file every 2 seconds
- Real-time bot detection alerts
- Periodic status updates (every 30s)
- Final summary on Ctrl+C

### Training Pipeline
- Synthetic data generator with realistic bot/human patterns
- Training script with MSE loss on micrograd
- Feature normalization (min-max scaling)
- Combined real + synthetic training data (5,040 samples)
- 99.7% training accuracy

### Testing
- 142 tests across 9 test files
- All tests passing (1 skipped — network-dependent)
- Coverage: parser, features, labeler, model, scanner, report, watch

### CI/CD
- GitHub Actions workflow (`.github/workflows/test.yml`)
- Matrix: 3 OS × 6 Python versions (3.8–3.13)
- Auto-runs on push and PR

### Documentation
- README.md — quick start, CLI reference, architecture diagrams, feature table
- CONTRIBUTING.md — setup, testing, PR process
- LICENSE — MIT
- CLAUDE.md — project context for AI assistants

### Files Created
```
microguard/cli.py          — CLI entry point
microguard/parser.py       — Nginx + JSON parsers
microguard/features.py     — 19 feature extractors
microguard/labeler.py      — 24 heuristic rules
microguard/model.py        — micrograd MLP wrapper
microguard/scanner.py      — HTTP scanner
microguard/watch.py        — Continuous monitoring
microguard/report.py       — Output formatters
microguard/training/       — Training pipeline
tests/test_parser.py       — 16 tests
tests/test_features.py     — 21 tests
tests/test_labeler.py      — 7 tests
tests/test_labeler_rules.py — 18 tests
tests/test_model.py        — 7 tests
tests/test_scanner.py      — 16 tests
tests/test_scanner_extended.py — 16 tests
tests/test_report.py       — 27 tests
tests/test_watch.py        — 8 tests
data/model.json            — Trained model (1.8KB)
data/normalization.json    — Feature normalization
data/sample_access.log     — Demo log file
.github/workflows/test.yml — CI config
README.md                  — Documentation
CONTRIBUTING.md            — Contributor guide
CHANGELOG.md               — This file
LICENSE                    — MIT License
CLAUDE.md                  — AI assistant context
```
