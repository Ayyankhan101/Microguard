# Microguard

Bot Traffic Audit Tool powered by micrograd. Detects malicious bot traffic in API logs and live endpoints.

## Project Structure

- `microguard/` — Python package
  - `cli.py` — CLI entry point (scan, probe, info)
  - `parser.py` — Nginx + JSON log parsers
  - `features.py` — 19 feature extractors
  - `labeler.py` — Heuristic bot/human labeling
  - `model.py` — micrograd MLP wrapper
  - `scanner.py` — HTTP scanner for live probing
  - `report.py` — Terminal + JSON + HTML output
  - `events.py` — DecisionRecorder protocol + in-memory recorder (no Redis
    needed, unlike everything under `live/`)
  - `live/` — Real-time blocking: check server, ASGI/WSGI middleware, Redis
    session store, decision recording, runtime config
  - `dashboard/` — FastAPI app serving the API and the built SPA
  - `training/` — Training pipeline
- `gui/` — TypeScript dashboard (Vite + React). `npm run build` writes
  `microguard/dashboard/static/`, which ships in the wheel
- `docs/` — Diataxis documentation, indexed by `docs/README.md`
  (3 tutorials / 12 how-tos / 5 references / 4 explanations)
- `tests/` — pytest tests (1172 passing, 2 skipped); `gui/src/**/*.test.*` — vitest
  (144 passing)
- `data/` — Model weights, sample logs

## Commands

```bash
python -m pytest tests/              # Run tests
microguard scan <logfile>            # Scan log file
microguard probe <url>               # Probe live URL
microguard dashboard                 # Web UI on 127.0.0.1:8500

cd gui && npm test                   # Frontend tests
cd gui && npm run build              # Build the SPA into the Python package
python gui/scripts/capture_fixtures.py   # Recapture API fixtures after a shape change
```

## Health Stack

- typecheck: mypy microguard (CI gates it in the `typecheck (mypy)` job, on
  Python 3.10)
- lint: ruff check .
- test: pytest
- coverage: pytest --cov=microguard --cov-report=term-missing (100%; CI
  gates at 98% via --cov-fail-under, against `.coveragerc-matrix`, which
  omits only what that job cannot execute — see the CI-parity lanes)
- frontend: cd gui && npx tsc -b && npm test
- browser: pytest tests/browser/ (needs `pip install playwright && playwright
  install chromium`; skips cleanly without it, and CI fails the job if it does)
- deadcode: vulture microguard microguard/vulture_whitelist.py
- shell: shellcheck scripts/*.sh

### CI-parity lanes

Local green is not CI green. A full local run passed while CI failed 13 of 15
jobs, because two things CI checks cannot be observed from a machine that has
Redis and a stable clock. Run these on a **clean tree** before pushing:

- fixtures: `python gui/scripts/capture_fixtures.py && git diff --exit-code -- gui/src/api/__fixtures__`

  CI recaptures the fixtures and diffs them, so ANY non-deterministic field in
  an API payload makes that job permanently red — it can never match the
  committed file. `_stabilize()` in the capture script pins the known ones
  (wall-clock stamps, the uuid4 decision id). Adding a random or time-derived
  field to a decision means adding it there in the same change. This has bitten
  twice: once for `time.time()`, once for `uuid4()`.

- matrix coverage: `pytest --cov=microguard --cov-config=.coveragerc-matrix --cov-report=term --cov-fail-under=98 --deselect tests/live`

  The cross-platform matrix has no Redis, so every `tests/live/` test skips and
  `microguard/live` cannot execute there. It is omitted via
  `.coveragerc-matrix` and gated instead in the `live (Redis-backed)` job. A
  plain local run measures code those runners never touch, so it cannot detect
  a drop in the number they actually compute — it read 100% locally while CI
  read 93%.

  Watch the **precise** number, not the rounded one:
  `coverage report --rcfile=.coveragerc-matrix --precision=2`. coverage.py
  rounds to the display precision before comparing against `--cov-fail-under`,
  so 97.74% renders as "98%" and passes — while sitting eight uncovered
  statements from red, with the cause several files away.

- matrix deps: run the suite with the packages that job does **not** install
  blocked, rather than with whatever happens to be in your environment:

  ```bash
  python -c "
  import sys
  sys.modules['numpy'] = None; sys.modules['mlflow'] = None
  import pytest; raise SystemExit(pytest.main(
      ['tests/','-q','--deselect','tests/live','--deselect','tests/browser']))"
  ```

  The matrix installs `.[live,fastapi,flask,dashboard]` plus
  `pytest pytest-cov httpx httpx2` — nothing more. No package code imports
  numpy, pandas, or mlflow any more (the Databricks/MLflow surface was removed),
  so these two blocks are kept as a standing guard, not because a current
  dependency needs them: a test that imports a package outside the matrix
  install passes on a dev machine that happens to have it and fails all 12
  matrix jobs. That is how `tests/test_tracking.py::TestPyFunc::test_predict`
  once shipped (`import numpy as np`, green locally, `ModuleNotFoundError` on
  every runner). Guard any such test with `pytest.importorskip`, and add any
  newly optional dependency to the blocked list above.

### Platform parity — a review check, not a lane

The `matrix deps` lane above catches tests that depend on a package the runner
lacks. It does NOT catch tests that depend on OS *behaviour*, and no local lane
can short of running the suite on Windows. Both failures this project has had
were the same shape — a test passing here because this machine has a property
the runner does not:

- `import numpy` in a test, with numpy present locally from an unrelated
  environment and absent on the matrix. All 12 jobs red.
- `path.chmod(0o500)` to provoke an `OSError`. POSIX removes write permission;
  Windows does not, so no error was raised, nothing was logged, and the four
  Windows jobs failed on an empty assertion while every other platform passed.

So when reviewing a new test, ask: **does this depend on the machine rather
than the code?** Provoking an error through the filesystem, the clock, the
locale, or an installed package is the tell. Inject the condition instead
(`monkeypatch` the call that should fail), which tests the same contract on
every platform.

## Test suite conventions

- Shared `LogEntry`/`Session`/temp-log-file builders live in `tests/conftest.py`
  (`make_entry`, `make_session`, `nginx_log_file` fixtures) — use them
  instead of writing a new local `_make_entry`-style helper.
  `tests/test_groundtruth.py`'s `_entry()` is a deliberate exception (it
  auto-synthesizes a realistic `raw_line`, which the shared fixture
  doesn't need for other tests).
- `cli.py` and `watch.py` are tested end-to-end (`tests/test_cli.py`,
  `TestWatchLogfile` in `tests/test_watch.py`), not just their helpers —
  keep new CLI/watch behavior covered there, not only at the unit level.
- `watch_logfile()` takes a test-only `_max_iterations` param to terminate
  its otherwise-infinite loop; don't use it from product code. The dashboard's
  `decision_stream()` has the same seam, named `_max_ticks`.
- Tests that read a file the product wrote must pass `encoding='utf-8'` to
  `read_text()`. Windows defaults to the locale codepage (cp1252) and every
  report format contains emoji, so an encoding-less read passes on
  Linux/macOS and fails only on the Windows matrix jobs.
- The zod schemas in `gui/src/api/schemas.ts` are checked against real API
  payloads captured in `gui/src/api/__fixtures__/`. Change a Python response
  shape and you must rerun `gui/scripts/capture_fixtures.py` — CI fails on
  stale fixtures.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
- Author a backlog-ready spec/issue → invoke /spec
