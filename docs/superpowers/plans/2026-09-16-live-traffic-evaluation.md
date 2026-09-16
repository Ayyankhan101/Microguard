# Live Traffic Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure how well microguard's verdicts hold up on real internet traffic: how many real bots it catches, and how many real humans it would have blocked.

**Architecture:** Run the existing observe-only EC2 collector (`--block-threshold 1.0`, nothing is ever blocked) for 72 hours. Ground truth comes from how the site is built, not from people labeling rows afterwards: a hidden honeypot link and exploit-probe paths mark bots; a private invite link plus a fingerprint POST marks humans. One small stdlib module joins the nginx access log with the collected decisions per client IP and prints a markdown report.

**Tech Stack:** Python 3.10+ stdlib, existing `microguard.parser`, `microguard.collect`, `microguard.scoring`; nginx, Redis, EC2 `t3.micro` via `scripts/provision-collector.sh`.

**Spec:** None separate. The design rationale is the "Approach" section below; executors read it before Task 1.

## Global Constraints

- No new runtime or test dependencies. `microguard/evaluate.py` is stdlib-only, like `microguard/collect.py`.
- The collector stays observe-only for the whole run: `--block-threshold 1.0`. No real visitor is ever blocked.
- AWS: all resources in the project's selected Region, `ap-southeast-2` per `docs/howto-collect-real-sessions.md`. Confirm it in AWS Settings > View all projects > Overview > Additional Info > Region before provisioning.
- CI gates that must stay green: matrix coverage `--cov-fail-under=98` against `.coveragerc-matrix`; matrix-deps lane (numpy and mlflow blocked); `ruff check .`; `mypy microguard`.
- Tests that read product-written files pass `encoding='utf-8'`. Tests use the shared `nginx_log_file` fixture from `tests/conftest.py`.
- New CLI behavior is tested end to end in `tests/test_cli.py`.
- The actor ID is the client IP, the same key the check server uses for sessions.

---

## Approach

### What we need to know

Two numbers decide whether blocking can be turned on, and at what threshold:

1. **Humans flagged:** of the real people who visited, how many would have been blocked at least once.
2. **Bots caught:** of the real bots that visited, how many would have been blocked.

Everything else in the report exists to make those two numbers trustworthy.

### Ground truth by construction

A collected row records what microguard *guessed* (`microguard/collect.py` says so explicitly). Labeling thousands of IPs by hand is slow and can't be reproduced. So the site is built so that some behavior can only come from one class:

| Label | Evidence | Why it is sound |
|---|---|---|
| **bot** | Requested `/_hp/...`, a link hidden with `display:none`, `aria-hidden`, `tabindex=-1`, and disallowed in `robots.txt` | A person can't see or tab to it, and polite crawlers skip it |
| **bot** | Requested an exploit probe (`/.env`, `/wp-login.php`, ...) on a static site that has none of those | No invited person asks a static page for WordPress |
| **human** | Arrived via a private `?ref=<token>` link **and** POSTed `/microguard/fp` | The link alone is not enough: chat apps fetch links to build previews, but they don't run the page's JavaScript |
| **conflict** | Both | Shared NAT. Counted, excluded |
| **unlabeled** | Neither | Counted. The flagged ones are listed so they can be read in the access log |

### Known limits of this ground truth, stated up front

- **Probe-labeled bots are circular.** The heuristic scanner rule matches the same kind of paths, so it catches them by definition. The report shows a separate **honeypot-only** column, covering bots that never requested a probe path. That column is the honest recall number.
- **The labeled bots skew easy.** A careful headless browser that never touches the honeypot stays unlabeled. So recall is an upper bound.
- **Humans labeled through the fingerprint have JavaScript on.** People who block scripts aren't in the human set, so the human false-positive rate is a lower bound.
- **One IP is one actor.** A campus NAT merges people, and IPv6 rotation splits one person. The conflict count shows how often the merging happens.

### Decision rules, fixed before any data is seen

Written down now so the results can't be explained away afterwards:

1. **Sample floor.** With fewer than 30 labeled humans **or** fewer than 30 labeled bots, the result is *inconclusive*. Report counts only; no rates, no threshold change. The report prints this itself.
2. **Blocking may be enabled at threshold T only if humans flagged at T is 0/N.** A single real person blocked is a failure at that threshold. Pick the lowest threshold with 0 humans flagged, then read honeypot-only recall at that threshold.
3. **The model earns its place only if** some score threshold with 0 humans flagged catches more honeypot-only bots than the `heuristic label is bot` row. If it doesn't, the finding is that the heuristics alone do the work, and that is written up plainly.
4. **Heuristic rules that never fire on real traffic** (from the report's rules table) are listed as removal candidates in the results. That is how this run also answers whether the codebase is carrying code it doesn't need.

### What this plan deliberately does not build

No dashboard panel, no request-ID join between nginx and the check server, no confidence-interval library, no AWS automation, no labeling UI. Counts reported as `k/n` are exact and small enough to reason about directly. Per-IP joining needs no timestamps. The existing SSH-tunnelled dashboard already covers watching traffic live.

### Bug this plan fixes first

`scripts/provision-collector.sh` (#11) routes `location = /fp`, but `microguard/live/static/fingerprint.js` posts to `/microguard/fp`. On the collector, every fingerprint POST falls through to `location /` and the static root, and is lost. Separately, the `/fp` block never forwards `X-Real-IP`, so even a POST that reached it would bind the hash to `127.0.0.1`. As shipped, no visitor could ever be labeled human. Task 1 fixes both and adds a test that keeps the script and the nginx routes in agreement.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `scripts/provision-collector.sh` | Modify | Route `/microguard/` exactly as `docs/howto-deploy-behind-nginx.md` documents it |
| `tests/test_provision_collector.py` | Create | Contract: the collector's nginx routes what `fingerprint.js` calls |
| `docs/howto-collect-real-sessions.md` | Modify | Script tag path |
| `microguard/evaluate.py` | Create | Ground truth, per-actor verdicts, report rendering |
| `tests/test_evaluate.py` | Create | Unit tests for the above |
| `microguard/cli.py` | Modify | `microguard evaluate` subcommand |
| `tests/test_cli.py` | Modify | End-to-end test of the subcommand |
| `docs/reference-cli.md` | Modify | `microguard evaluate` reference section |
| `docs/howto-evaluate-on-live-traffic.md` | Create | The runbook for Task 5 |
| `docs/README.md`, `CLAUDE.md` | Modify | Index the new how-to; how-to count 11 → 12 |
| `docs/results/2026-09-live-evaluation.md` | Create in Task 5 | The report plus the written decision |

---

### Task 1: Route the fingerprint endpoint on the collector

**Files:**
- Modify: `scripts/provision-collector.sh` (the `/fp` and `/fingerprint.js` lines inside the `microguard.conf` heredoc, around lines 119-122, and the script-tag hint around line 145)
- Modify: `docs/howto-collect-real-sessions.md:76`
- Test: `tests/test_provision_collector.py`

**Interfaces:**
- Consumes: `var ENDPOINT = '/microguard/fp';` in `microguard/live/static/fingerprint.js`
- Produces: a collector whose nginx proxies `/microguard/*` to `127.0.0.1:8400/*` with `X-Real-IP`. Tasks 2 and 5 rely on `POST /microguard/fp` lines appearing in the access log.

- [ ] **Step 1: Write the failing test**

Create `tests/test_provision_collector.py`:

```python
"""The collector's nginx config must route what fingerprint.js calls.

scripts/provision-collector.sh shipped routing `location = /fp` while the
script posts to /microguard/fp, so every fingerprint was lost on the collector
and no visitor could ever be labeled human. This pins the two together.
"""

import re
from pathlib import Path

SCRIPT = Path("scripts/provision-collector.sh").read_text(encoding="utf-8")
FINGERPRINT_JS = Path("microguard/live/static/fingerprint.js").read_text(encoding="utf-8")


def _fingerprint_block() -> str:
    start = SCRIPT.index("location /microguard/ {")
    return SCRIPT[start:SCRIPT.index("}", start)]


def test_the_endpoint_the_script_posts_to_is_routed():
    endpoint = re.search(r"var ENDPOINT = '([^']+)'", FINGERPRINT_JS).group(1)
    prefix = endpoint.rsplit("/", 1)[0] + "/"

    assert f"location {prefix} {{" in SCRIPT


def test_the_route_binds_the_hash_to_the_visitor_not_to_nginx():
    assert "X-Real-IP" in _fingerprint_block()


def test_the_public_route_is_rate_limited_by_a_defined_zone():
    assert "limit_req zone=microguard_fp" in _fingerprint_block()
    assert "zone=microguard_fp:" in SCRIPT
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_provision_collector.py -v`
Expected: 3 FAILED, each with `ValueError: substring not found` or `AssertionError`.

- [ ] **Step 3: Fix the nginx config in the script**

In `scripts/provision-collector.sh`, inside the `cat >/etc/nginx/conf.d/microguard.conf <<NGINX` heredoc, add this line immediately before `server {` (conf.d files are included inside nginx's `http {}` block, which is where a zone has to be defined):

```nginx
# One page load submits one fingerprint; this is generous for a visitor.
limit_req_zone \$binary_remote_addr zone=microguard_fp:10m rate=30r/m;

```

Replace these two lines:

```nginx
    # The fingerprint endpoints are public by design and answer 200 with
    # identical bytes for every outcome, so they cannot be used as an oracle.
    location = /fp              { proxy_pass http://127.0.0.1:8400/fp; }
    location = /fingerprint.js  { proxy_pass http://127.0.0.1:8400/fingerprint.js; }
```

with:

```nginx
    # The fingerprint routes: public by design, answering 200 with identical
    # bytes for every outcome, so they cannot be used as an oracle. Same block
    # as docs/howto-deploy-behind-nginx.md. fingerprint.js posts to
    # /microguard/fp, so this prefix is the one that has to match, and
    # X-Real-IP binds the hash to the visitor rather than to 127.0.0.1.
    location /microguard/ {
        proxy_pass http://127.0.0.1:8400/;
        client_max_body_size  2k;
        client_body_timeout   5s;
        send_timeout          5s;
        proxy_read_timeout    5s;
        limit_req zone=microguard_fp burst=5 nodelay;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For "";
    }
```

The `\$` escapes are required: the heredoc is unquoted, so an unescaped `$remote_addr` would be expanded by bash to an empty string.

In the `DONE` message near the end of the script, change `<script src="/fingerprint.js" defer></script>` to `<script src="/microguard/fingerprint.js" defer></script>`. The exact `/fingerprint.js` location no longer exists, so the old tag would 404.

- [ ] **Step 4: Fix the runbook's script tag**

In `docs/howto-collect-real-sessions.md`, change line 76 from `<script src="/fingerprint.js" defer></script>` to `<script src="/microguard/fingerprint.js" defer></script>`.

- [ ] **Step 5: Run the tests and the shell lint**

Run: `python -m pytest tests/test_provision_collector.py -v && shellcheck scripts/*.sh`
Expected: 3 passed; shellcheck prints nothing.

- [ ] **Step 6: Commit**

```bash
git add scripts/provision-collector.sh tests/test_provision_collector.py docs/howto-collect-real-sessions.md
git commit -m "fix(collector): route /microguard/ so fingerprints reach the check server"
```

---

### Task 2: The evaluation module

**Files:**
- Create: `microguard/evaluate.py`
- Test: `tests/test_evaluate.py`

**Interfaces:**
- Consumes: `microguard.parser.parse_file(filepath: str, fmt: str) -> Iterator[LogEntry]` (`LogEntry.ip`, `.method`, `.url` including the query string); `microguard.collect.load_collected(path, report_skipped=True) -> tuple[list[dict], int]` (row keys `ip`, `score`, `heuristic_label`, `heuristic_reason`); `microguard.collect.DecisionCollector(path).record(decision: dict) -> bool`; `microguard.scoring.BLOCK_THRESHOLD_DEFAULT = 0.85`.
- Produces: `build_actors(log_paths: Iterable[str], collected_path: str, invite_tokens: Iterable[str]) -> tuple[dict[str, Actor], int]` and `render_report(actors: dict[str, Actor], skipped_rows: int = 0) -> str`. Task 3 calls exactly these two.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_evaluate.py`:

```python
"""Tests for microguard.evaluate: ground truth by construction, and the report."""

from microguard.collect import NUM_FEATURES, DecisionCollector
from microguard.evaluate import (
    BOT,
    CONFLICT,
    HUMAN,
    UNLABELED,
    Actor,
    build_actors,
    render_report,
    rule_name,
)

UA = "Mozilla/5.0 (X11; Linux x86_64)"


def _line(ip, method, url, second=0):
    return (
        f'{ip} - - [16/Sep/2026:10:00:{second:02d} +0000] '
        f'"{method} {url} HTTP/1.1" 200 512 "-" "{UA}"'
    )


def _collect(tmp_path, *decisions):
    """Write decisions with the real collector, so the rows match production."""
    path = tmp_path / "collected.jsonl"
    sink = DecisionCollector(path)
    for i, (ip, score, label, reason) in enumerate(decisions):
        assert sink.record({
            "id": f"d{i}", "features": [0.0] * NUM_FEATURES, "score": score,
            "heuristic_label": label, "heuristic_reason": reason,
            "ip": ip, "blocked": False,
        })
    return str(path)


class TestTruth:
    def test_the_honeypot_marks_a_bot(self):
        assert Actor(hit_honeypot=True).truth == BOT

    def test_an_exploit_probe_marks_a_bot(self):
        assert Actor(hit_probe=True).truth == BOT

    def test_an_invite_link_alone_is_not_a_human(self):
        """Chat apps fetch a shared link to build its preview."""
        assert Actor(invited=True).truth == UNLABELED

    def test_an_invite_link_plus_the_fingerprint_is_a_human(self):
        assert Actor(invited=True, ran_fingerprint=True).truth == HUMAN

    def test_evidence_for_both_is_a_conflict(self):
        assert Actor(hit_honeypot=True, invited=True, ran_fingerprint=True).truth == CONFLICT


class TestBuildActors:
    def test_reads_the_evidence_from_the_access_log(self, nginx_log_file, tmp_path):
        log = nginx_log_file([
            _line("198.51.100.1", "GET", "/_hp/archive"),
            _line("198.51.100.2", "GET", "/.env"),
            _line("198.51.100.3", "GET", "/?ref=k7q2"),
            _line("198.51.100.3", "POST", "/microguard/fp", second=1),
            _line("198.51.100.4", "GET", "/?ref=guessed"),
            _line("198.51.100.4", "POST", "/microguard/fp", second=1),
            _line("127.0.0.1", "GET", "/_hp/x"),
        ])

        actors, skipped = build_actors([log], _collect(tmp_path), ["k7q2"])

        assert actors["198.51.100.1"].truth == BOT
        assert actors["198.51.100.2"].truth == BOT
        assert actors["198.51.100.3"].truth == HUMAN
        assert actors["198.51.100.4"].truth == UNLABELED
        assert "127.0.0.1" not in actors
        assert skipped == 0

    def test_the_verdict_is_the_highest_score_any_request_got(self, nginx_log_file, tmp_path):
        log = nginx_log_file([_line("198.51.100.9", "GET", "/")])
        collected = _collect(
            tmp_path,
            ("198.51.100.9", 0.2, "human", "normal browsing"),
            ("198.51.100.9", 0.91, "bot", "uniform timing (avg 0.101s, near-zero variance)"),
            ("127.0.0.1", 0.99, "bot", "load test"),
        )

        actors, _ = build_actors([log], collected, [])

        actor = actors["198.51.100.9"]
        assert actor.max_score == 0.91
        assert actor.heuristic_bot
        assert actor.reasons == {"normal browsing", "uniform timing"}
        assert "127.0.0.1" not in actors

    def test_rotated_logs_are_read_together(self, nginx_log_file, tmp_path):
        first = nginx_log_file([_line("198.51.100.5", "GET", "/")], name="access.log.1")
        second = nginx_log_file([_line("198.51.100.5", "GET", "/_hp/a")], name="access.log")

        actors, _ = build_actors([first, second], _collect(tmp_path), [])

        assert actors["198.51.100.5"].requests == 2
        assert actors["198.51.100.5"].truth == BOT

    def test_unreadable_collected_rows_are_counted(self, nginx_log_file, tmp_path):
        collected = _collect(tmp_path, ("198.51.100.6", 0.4, "human", "normal browsing"))
        with open(collected, "a", encoding="utf-8") as handle:
            handle.write("not json\n")

        _, skipped = build_actors([nginx_log_file([])], collected, [])

        assert skipped == 1


class TestRuleName:
    def test_strips_the_per_session_detail(self):
        assert rule_name("attack tool UA: sqlmap/1.7") == "attack tool UA"
        assert rule_name("UA rotation (5 variants in 9 requests)") == "UA rotation"

    def test_leaves_a_fixed_reason_alone(self):
        assert rule_name("vulnerability scanner pattern detected") == (
            "vulnerability scanner pattern detected"
        )


class TestReport:
    def test_the_threshold_comparison_is_strict_like_the_scorer(self):
        report = render_report({
            "h": Actor(invited=True, ran_fingerprint=True, max_score=0.85),
            "b": Actor(hit_honeypot=True, max_score=0.86),
        })

        assert "| score > 0.85 (default) | 1/1 | 1/1 | 0/1 |" in report
        assert "| score > 0.80 | 1/1 | 1/1 | 1/1 |" in report

    def test_probe_bots_are_kept_out_of_the_honeypot_only_column(self):
        report = render_report({
            "h": Actor(invited=True, ran_fingerprint=True, max_score=0.1),
            "b": Actor(hit_honeypot=True, max_score=0.86),
            "p": Actor(hit_probe=True, max_score=0.99),
        })

        assert "| score > 0.85 (default) | 2/2 | 1/1 | 0/1 |" in report

    def test_the_heuristic_baseline_has_its_own_row(self):
        report = render_report({"b": Actor(hit_honeypot=True, max_score=0.3, heuristic_bot=True)})

        assert "| heuristic label is bot | 1/1 | 1/1 | 0/0 |" in report

    def test_small_samples_are_marked_inconclusive(self):
        report = render_report({"b": Actor(hit_honeypot=True, max_score=0.9)})

        assert "**Inconclusive:**" in report

    def test_reports_how_many_invited_visitors_ran_the_fingerprint(self):
        report = render_report({
            "a": Actor(invited=True, ran_fingerprint=True, max_score=0.1),
            "b": Actor(invited=True, max_score=0.1),
        })

        assert "Invited actors that ran the fingerprint script: 1/2." in report

    def test_actors_with_no_scored_request_are_left_out(self):
        report = render_report({"b": Actor(hit_honeypot=True)})

        assert "| bot | 0 |" in report

    def test_lists_unlabeled_actors_the_default_threshold_would_block(self):
        report = render_report({
            "198.51.100.7": Actor(max_score=0.97, requests=4),
            "198.51.100.8": Actor(max_score=0.5, requests=2),
        })

        assert "flagged at the default threshold (1)" in report
        assert "| 198.51.100.7 | 0.97 | 4 |" in report
        assert "198.51.100.8" not in report

    def test_shows_which_heuristic_rules_fired_on_which_class(self):
        report = render_report({
            "b": Actor(hit_honeypot=True, max_score=0.9, reasons={"uniform timing"}),
        })

        assert "| uniform timing | 1 | 0 | 0 |" in report
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_evaluate.py -v`
Expected: collection ERROR, `ModuleNotFoundError: No module named 'microguard.evaluate'`.

- [ ] **Step 3: Write the module**

Create `microguard/evaluate.py`:

```python
"""Measure live verdicts against ground truth established by construction.

A collected decision records what microguard guessed, never what was true (see
collect.py). Labeling thousands of actors by hand afterwards does not scale and
cannot be reproduced, so the truth comes from how the evaluation site is built:

- BOT: requested a path no person reaches. Either the honeypot link, hidden
  from people and disallowed in robots.txt, or a well-known exploit probe on a
  static site that has no such software.
- HUMAN: arrived through a private invite link AND ran the fingerprint script.
  The link alone is not enough, because chat apps fetch it to build a preview.
- Everything else is UNLABELED: counted, and kept out of the rates.

An actor is one client IP, the key the check server uses for sessions. Its
verdict is the highest score any of its requests got, because one request over
the threshold is one blocked page for a real visitor.

Stdlib only, like collect.py, so it runs wherever the archive is copied to.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from .collect import load_collected
from .parser import parse_file
from .scoring import BLOCK_THRESHOLD_DEFAULT

HONEYPOT_PREFIX = "/_hp/"
# Probes for software a static site does not run. Kept short on purpose: each
# entry has to be a path no invited person could request by accident.
PROBE_PREFIXES = (
    "/.env", "/.git", "/.aws", "/wp-login.php", "/wp-admin", "/xmlrpc.php",
    "/phpmyadmin", "/vendor/phpunit", "/cgi-bin/", "/boaform",
)
FINGERPRINT_PATH = "/microguard/fp"
INVITE_PARAM = "ref"
# Traffic from the instance itself: the latency run and health checks.
LOOPBACK = frozenset({"127.0.0.1", "::1"})
THRESHOLDS = (0.5, 0.6, 0.7, 0.8, BLOCK_THRESHOLD_DEFAULT, 0.9, 0.95)
MIN_PER_CLASS = 30
UNLABELED_LISTED = 20

BOT, HUMAN, CONFLICT, UNLABELED = "bot", "human", "conflict", "unlabeled"


@dataclass
class Actor:
    requests: int = 0
    hit_honeypot: bool = False
    hit_probe: bool = False
    invited: bool = False
    ran_fingerprint: bool = False
    max_score: float | None = None
    heuristic_bot: bool = False
    reasons: set[str] = field(default_factory=set)

    @property
    def truth(self) -> str:
        bot = self.hit_honeypot or self.hit_probe
        human = self.invited and self.ran_fingerprint
        if bot and human:
            return CONFLICT
        if bot:
            return BOT
        if human:
            return HUMAN
        return UNLABELED


def rule_name(reason: str) -> str:
    """'uniform timing (avg 0.101s, ...)' -> 'uniform timing'.

    Reasons embed per-session numbers, so the raw strings never group.
    """
    return re.split(r"[(:]", reason, maxsplit=1)[0].strip()


def build_actors(
    log_paths: Iterable[str],
    collected_path: str,
    invite_tokens: Iterable[str],
) -> tuple[dict[str, Actor], int]:
    """Join the access log (evidence) with collected decisions (verdicts).

    Returns the actors by IP and the number of unreadable collected rows.
    """
    tokens = frozenset(invite_tokens)
    actors: dict[str, Actor] = {}

    for log_path in log_paths:
        for entry in parse_file(log_path, fmt="nginx"):
            if entry.ip in LOOPBACK:
                continue
            actor = actors.setdefault(entry.ip, Actor())
            actor.requests += 1
            parts = urlsplit(entry.url)
            if parts.path.startswith(HONEYPOT_PREFIX):
                actor.hit_honeypot = True
            if parts.path.startswith(PROBE_PREFIXES):
                actor.hit_probe = True
            if tokens.intersection(parse_qs(parts.query).get(INVITE_PARAM, [])):
                actor.invited = True
            if entry.method == "POST" and parts.path == FINGERPRINT_PATH:
                actor.ran_fingerprint = True

    rows, skipped = load_collected(collected_path, report_skipped=True)
    for row in rows:
        ip, score = row.get("ip"), row.get("score")
        if not isinstance(ip, str) or ip in LOOPBACK or not isinstance(score, (int, float)):
            continue
        actor = actors.setdefault(ip, Actor())
        actor.max_score = score if actor.max_score is None else max(actor.max_score, score)
        if row.get("heuristic_label") == "bot":
            actor.heuristic_bot = True
        reason = row.get("heuristic_reason")
        if isinstance(reason, str) and reason:
            actor.reasons.add(rule_name(reason))

    return actors, skipped


def _above(threshold: float) -> Callable[[Actor], bool]:
    """Flag rule matching the scorer, which blocks on score > threshold."""
    return lambda actor: actor.max_score is not None and actor.max_score > threshold


def _ratio(actors: Iterable[Actor], truth: str, flagged: Callable[[Actor], bool]) -> str:
    members = [a for a in actors if a.truth == truth]
    return f"{sum(flagged(a) for a in members)}/{len(members)}"


def render_report(actors: dict[str, Actor], skipped_rows: int = 0) -> str:
    scored = {ip: a for ip, a in actors.items() if a.max_score is not None}
    truths = Counter(a.truth for a in scored.values())
    honeypot_only = [a for a in scored.values() if not a.hit_probe]
    invited = [a for a in scored.values() if a.invited]

    lines = [
        "# Live evaluation",
        "",
        "## Actors (client IPs with at least one scored request)",
        "",
        "| truth | actors |",
        "|---|---|",
        *(f"| {t} | {truths[t]} |" for t in (BOT, HUMAN, CONFLICT, UNLABELED)),
        "",
        (
            "Invited actors that ran the fingerprint script: "
            f"{sum(a.ran_fingerprint for a in invited)}/{len(invited)}. "
            "Near zero means TLS or the /microguard/ route is broken, "
            "and nobody can be labeled human."
        ),
        "",
        f"Collected rows skipped as unreadable: {skipped_rows}.",
        "",
    ]
    if truths[BOT] < MIN_PER_CLASS or truths[HUMAN] < MIN_PER_CLASS:
        lines += [
            (
                f"**Inconclusive:** fewer than {MIN_PER_CLASS} labeled actors in a "
                "class. Read the counts, not the rates, and change no threshold."
            ),
            "",
        ]

    rules: list[tuple[str, Callable[[Actor], bool]]] = [
        ("heuristic label is bot", lambda a: a.heuristic_bot),
    ]
    for t in THRESHOLDS:
        default = " (default)" if t == BLOCK_THRESHOLD_DEFAULT else ""
        rules.append((f"score > {t:.2f}{default}", _above(t)))

    lines += [
        "## Verdicts on labeled actors",
        "",
        (
            "Flagged means at least one request scored above the threshold. "
            "Honeypot-only bots never requested a probe path, so the scanner rule "
            "cannot have caught them by matching the path that labeled them."
        ),
        "",
        "| flag rule | bots caught | honeypot-only bots caught | humans flagged |",
        "|---|---|---|---|",
    ]
    for name, flagged in rules:
        lines.append(
            f"| {name} | {_ratio(scored.values(), BOT, flagged)} "
            f"| {_ratio(honeypot_only, BOT, flagged)} "
            f"| {_ratio(scored.values(), HUMAN, flagged)} |"
        )

    fired: dict[str, Counter[str]] = {}
    for actor in scored.values():
        for reason in actor.reasons:
            fired.setdefault(reason, Counter())[actor.truth] += 1
    lines += [
        "",
        "## Heuristic reasons, by actor truth",
        "",
        "| reason | bot | human | unlabeled |",
        "|---|---|---|---|",
    ]
    for reason in sorted(fired, key=lambda r: (-sum(fired[r].values()), r)):
        counts = fired[reason]
        lines.append(f"| {reason} | {counts[BOT]} | {counts[HUMAN]} | {counts[UNLABELED]} |")

    at_default = _above(BLOCK_THRESHOLD_DEFAULT)
    grey = sorted(
        ((ip, a) for ip, a in scored.items() if a.truth == UNLABELED and at_default(a)),
        key=lambda pair: -(pair[1].max_score or 0.0),
    )
    lines += [
        "",
        f"## Unlabeled actors flagged at the default threshold ({len(grey)})",
        "",
        "Read these in the access log. Each is a block nobody can yet call right or wrong.",
        "",
        "| ip | max score | requests |",
        "|---|---|---|",
    ]
    for ip, actor in grey[:UNLABELED_LISTED]:
        lines.append(f"| {ip} | {actor.max_score:.2f} | {actor.requests} |")

    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_evaluate.py -v`
Expected: 19 passed.

- [ ] **Step 5: Check types, lint, and the matrix-deps lane**

Run: `mypy microguard && ruff check microguard/evaluate.py tests/test_evaluate.py`
Expected: `Success: no issues found`, `All checks passed!`

Run:
```bash
python -c "
import sys
sys.modules['numpy'] = None; sys.modules['mlflow'] = None
import pytest; raise SystemExit(pytest.main(['tests/test_evaluate.py','-q']))"
```
Expected: 19 passed. This proves the module is stdlib-only, as the matrix requires.

- [ ] **Step 6: Commit**

```bash
git add microguard/evaluate.py tests/test_evaluate.py
git commit -m "feat(evaluate): score live verdicts against honeypot and invite-link ground truth"
```

---

### Task 3: `microguard evaluate` command

**Files:**
- Modify: `microguard/cli.py`. Add the parser immediately before the line `    # dashboard command — API + built SPA on one port`, and the dispatch branch immediately before `    elif args.command == 'dashboard':`
- Modify: `tests/test_cli.py`
- Modify: `docs/reference-cli.md`. Add a section after `## \`microguard explain\``

**Interfaces:**
- Consumes: `build_actors(log_paths, collected_path, invite_tokens) -> tuple[dict[str, Actor], int]`, `render_report(actors, skipped_rows) -> str` from Task 2.
- Produces: `microguard evaluate --access-log PATH [--access-log PATH ...] --collected PATH --invite-token TOKEN [--invite-token TOKEN ...]`, printing the report to stdout and exiting 0. Task 5 runs exactly this.

- [ ] **Step 1: Write the failing tests**

In `tests/test_cli.py`, add this import directly below `from microguard.cli import DEFAULT_MODEL_PATH, scan_logfile` (ruff's isort order):

```python
from microguard.collect import NUM_FEATURES, DecisionCollector
```

Append this class to the end of the file:

```python
class TestEvaluateCommand:
    """`microguard evaluate` end to end via main()."""

    def test_prints_the_report(self, monkeypatch, capsys, tmp_path, nginx_log_file):
        log = nginx_log_file([
            (
                '198.51.100.1 - - [16/Sep/2026:10:00:00 +0000] '
                '"GET /_hp/a HTTP/1.1" 404 0 "-" "curl/8.0"'
            ),
        ])
        collected = tmp_path / "collected.jsonl"
        DecisionCollector(collected).record({
            "id": "d1", "features": [0.0] * NUM_FEATURES, "score": 0.9,
            "heuristic_label": "bot", "heuristic_reason": "attack tool UA: curl/8.0",
            "ip": "198.51.100.1", "blocked": False,
        })
        monkeypatch.setattr(sys, "argv", [
            "microguard", "evaluate", "--access-log", log,
            "--collected", str(collected), "--invite-token", "k7q2",
        ])

        cli_module.main()

        out = capsys.readouterr().out
        assert "| bot | 1 |" in out
        assert "| score > 0.85 (default) | 1/1 | 1/1 | 0/0 |" in out
        assert "| attack tool UA | 1 | 0 | 0 |" in out

    def test_an_access_log_is_required(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "argv", [
            "microguard", "evaluate", "--collected", str(tmp_path / "c.jsonl"),
            "--invite-token", "k7q2",
        ])

        with pytest.raises(SystemExit) as exc:
            cli_module.main()

        assert exc.value.code == 2
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_cli.py::TestEvaluateCommand -v`
Expected: `test_prints_the_report` FAILS with `SystemExit: 2` (argparse: `invalid choice: 'evaluate'`). `test_an_access_log_is_required` passes already, for the wrong reason (the whole subcommand is unknown). It has to still pass after Step 3, where it passes for the right reason.

- [ ] **Step 3: Add the subcommand**

In `microguard/cli.py`, immediately before `    # dashboard command — API + built SPA on one port`, insert:

```python
    # evaluate command — how verdicts held up against constructed ground truth
    evaluate_parser = subparsers.add_parser(
        'evaluate',
        help='Score collected verdicts against honeypot and invite-link ground truth'
    )
    evaluate_parser.add_argument(
        '--access-log', action='append', required=True,
        help='nginx access log; repeat for rotated files (.gz is fine)'
    )
    evaluate_parser.add_argument(
        '--collected', required=True,
        help='JSONL archive written by serve --collect-to'
    )
    evaluate_parser.add_argument(
        '--invite-token', action='append', required=True,
        help='A ?ref= value you shared privately; repeat once per channel'
    )

```

Immediately before `    elif args.command == 'dashboard':`, insert:

```python
    elif args.command == 'evaluate':
        from .evaluate import build_actors, render_report
        actors, skipped = build_actors(args.access_log, args.collected, args.invite_token)
        print(render_report(actors, skipped_rows=skipped))

```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_cli.py::TestEvaluateCommand tests/test_evaluate.py -v`
Expected: 21 passed.

- [ ] **Step 5: Document the command**

In `docs/reference-cli.md`, after the `## \`microguard explain\`` section (before `## \`microguard retrain\``), insert:

~~~markdown
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

An actor is a client IP. It is a **bot** if it requested `/_hp/` or an exploit
probe, a **human** if it arrived with an invite token and posted
`/microguard/fp`, and **unlabeled** otherwise. Its verdict is its highest
score. Prints markdown: actor counts, a fingerprint health line, caught and
flagged counts per threshold (with a honeypot-only column that the scanner rule
cannot inflate), the heuristic reasons by class, and the unlabeled actors the
default threshold would block. Fewer than 30 labeled actors in either class is
reported as inconclusive. See
[howto-evaluate-on-live-traffic.md](howto-evaluate-on-live-traffic.md).
~~~

- [ ] **Step 6: Run the matrix coverage lane**

Run: `python -m pytest tests/ -q --cov=microguard --cov-config=.coveragerc-matrix --cov-report= --cov-fail-under=98 --deselect tests/live && coverage report --rcfile=.coveragerc-matrix --precision=2 | tail -1`
Expected: `Required test coverage of 98% reached`; `microguard/evaluate.py` at 100%.

- [ ] **Step 7: Commit**

```bash
git add microguard/cli.py tests/test_cli.py docs/reference-cli.md
git commit -m "feat(cli): microguard evaluate"
```

---

### Task 4: The runbook

**Files:**
- Create: `docs/howto-evaluate-on-live-traffic.md`
- Modify: `docs/README.md` (the "Operating and developing" list, after the "Collect real sessions on EC2" entry)
- Modify: `CLAUDE.md` (`(3 tutorials / 11 how-tos / ...)` becomes `12 how-tos`)

**Interfaces:**
- Consumes: the collector from Task 1, `microguard evaluate` from Task 3.
- Produces: the exact procedure Task 5 follows.

- [ ] **Step 1: Write the how-to**

Create `docs/howto-evaluate-on-live-traffic.md`:

~~~markdown
# Evaluate on live traffic

How to find out how many real bots microguard catches and how many real people
it would block, without blocking anyone. It builds on
[howto-collect-real-sessions.md](howto-collect-real-sessions.md): do sections
1-3 there first (provision, bootstrap, TLS).

## Decide before you look

Fixed before any data exists, so the result cannot be argued with afterwards:

1. Fewer than 30 labeled humans or 30 labeled bots: **inconclusive**. Report
   counts, change nothing.
2. Blocking can be enabled at threshold T only if **humans flagged at T is 0/N**.
3. The model earns its place only if some threshold with 0 humans flagged
   catches more **honeypot-only** bots than the `heuristic label is bot` row.
4. Heuristic reasons that never appear are listed as removal candidates.

## 1. Build the page

Ground truth comes from the page, so its three parts are not optional. On the
instance:

```bash
sudo tee /usr/share/nginx/html/index.html >/dev/null <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microguard: end-semester project</title></head>
<body>
<h1>Microguard</h1>
<p>Bot detection built on micrograd. Read about <a href="/how.html">how it works</a>.</p>
<a href="/_hp/archive" style="display:none" tabindex="-1" aria-hidden="true" rel="nofollow">archive</a>
<script src="/microguard/fingerprint.js" defer></script>
</body></html>
HTML
sudo tee /usr/share/nginx/html/robots.txt >/dev/null <<'TXT'
User-agent: *
Disallow: /_hp/
TXT
```

Add a second page, `how.html`, with real content and the same `<script>` tag. A
visitor who clicks through produces a longer session, and the features need one.

## 2. Verify the three claims before sharing anything

**Fingerprints bind.** Open `https://<domain>/?ref=self` in a real browser, then:

```bash
sudo tail -n 5 /var/log/nginx/access.log | grep 'POST /microguard/fp'
redis6-cli --scan --pattern 'mg:v1:fp:*' | head
```

Both must show your IP. If the POST is missing, check TLS (`crypto.subtle`
needs HTTPS) and the `/microguard/` location. Stop here until it works: without
it nobody can be labeled human.

**Latency.** The check runs on every page request:

```bash
sudo dnf -y install httpd-tools
ab -n 2000 -c 10 -H 'X-Real-IP: 127.0.0.1' -H 'X-Original-URI: /' \
   http://127.0.0.1:8400/check | grep -E '^ +(50|99)%'
```

Write down p50 and p99. The target is p99 under 20 ms on a `t3.micro`; a miss is
a finding, not a blocker. Loopback traffic is excluded from the evaluation.

**Fail-open.**

```bash
sudo systemctl stop redis6
curl -sS -o /dev/null -w '%{http_code}\n' https://<domain>/   # must be 200
sudo systemctl start redis6
```

## 3. Share private invite links, one token per channel

Make a short random token for each place you share, and keep a list:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(4))"
```

Share `https://<domain>/?ref=<token>` in private channels only: class group,
friends, family. A link posted publicly gets followed by crawlers, and a
crawler that runs JavaScript would be labeled human. Use `?ref=self` for your
own devices.

## 4. Run for 72 hours, and check at 24

Bot traffic is diurnal, and 72 hours covers three cycles. At 24 hours, pull the
files and run the evaluation once, only to catch a broken setup:

Both files are root-owned on the instance, so copy them through `sudo tar`
rather than `scp`:

```bash
mkdir -p eval
ssh ec2-user@<ip> 'sudo tar -C / -czf - var/log/nginx var/lib/microguard/collected.jsonl' \
  | tar -C eval -xzf -
microguard evaluate --collected eval/var/lib/microguard/collected.jsonl \
  $(for f in eval/var/log/nginx/access.log*; do printf -- '--access-log %s ' "$f"; done) \
  --invite-token self --invite-token <token1> --invite-token <token2>
```

If `Invited actors that ran the fingerprint script` is near zero, fix the setup
now. Don't read the rates at 24 hours, and don't change anything because of them.

To watch live, use the dashboard over the tunnel described in
[howto-collect-real-sessions.md](howto-collect-real-sessions.md#watching-it-while-it-runs).

## 5. Final report

After 72 hours, pull the files again and run the same command, saving the
output:

```bash
microguard evaluate ... > docs/results/<yyyy-mm>-live-evaluation.md
```

Below the generated report, write the decision under each rule from "Decide
before you look", quoting the row it rests on. Then read at least ten of the
listed unlabeled-but-flagged IPs in the access log
(`zgrep -h '^<ip> ' eval/var/log/nginx/access.log*`) and note what each looked like.

## 6. Clean up

Terminate the instance once the files are copied off. It costs money while it
runs, and it is an internet-facing box you are no longer watching.

## What this cannot tell you

- **Recall is an upper bound.** Labeled bots are the ones that touched a trap.
  A careful headless browser does not, and stays unlabeled.
- **The human flag rate is a lower bound.** People who block JavaScript cannot
  be labeled human.
- **One IP is one actor.** A campus NAT merges people; the conflict count shows
  how often.
~~~

- [ ] **Step 2: Index it**

In `docs/README.md`, after the line starting `- [Collect real sessions on EC2]`, add:

```markdown
- [Evaluate on live traffic](howto-evaluate-on-live-traffic.md) — honeypot and invite-link ground truth, decision rules fixed in advance
```

In `CLAUDE.md`, change `(3 tutorials / 11 how-tos / 5 references / 4 explanations)` to `(3 tutorials / 12 how-tos / 5 references / 4 explanations)`.

- [ ] **Step 3: Check the links resolve**

Run: `python -c "import pathlib,re; d=pathlib.Path('docs'); t=(d/'howto-evaluate-on-live-traffic.md').read_text(encoding='utf-8'); [print('MISSING', l) for l in re.findall(r'\]\(([^)#]+)', t) if not (d/l).exists()]"`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add docs/howto-evaluate-on-live-traffic.md docs/README.md CLAUDE.md
git commit -m "docs: how to evaluate on live traffic"
```

---

### Task 5: Run the evaluation

Operational, not code. Follow `docs/howto-evaluate-on-live-traffic.md` exactly. The steps below are the checkpoints; each has a pass condition.

**Files:**
- Create: `docs/results/<yyyy-mm>-live-evaluation.md`

- [ ] **Step 1: Ship Tasks 1-4 first.** `provision-collector.sh` installs `microguard[live] @ git+https://github.com/Ayyankhan101/microguard.git`, which is `main`, so the route fix has to be merged before provisioning. Pass: PR merged, CI green.
- [ ] **Step 2: Confirm the Region and spend limit.** AWS Settings > View all projects > Overview > Additional Info > Region shows `ap-southeast-2`; AWS Settings > Billing shows a spend limit you accept. Pass: both confirmed by the project owner.
- [ ] **Step 3: Provision, add TLS, and build the page** (`howto-collect-real-sessions.md` sections 1-3, then this runbook's section 1). Pass: `curl -sS -o /dev/null -w '%{http_code}\n' https://<domain>/` prints `200`.
- [ ] **Step 4: Verify the three claims** (runbook section 2). Pass: your own POST `/microguard/fp` line in the access log and your IP under `mg:v1:fp:*`; p50/p99 recorded; `200` with Redis stopped.
- [ ] **Step 5: Share the invite links and record the start time.** Pass: token list saved alongside the start time in UTC.
- [ ] **Step 6: 24-hour checkpoint.** Pass: `Invited actors that ran the fingerprint script` is above 0. If it is 0, fix the setup and restart the 72-hour clock.
- [ ] **Step 7: 72-hour final run.** Pass: the report is saved to `docs/results/`, with a written decision under each of the four pre-set rules and notes on at least ten unlabeled-but-flagged IPs.
- [ ] **Step 8: Commit the results.**

```bash
git add docs/results/
git commit -m "docs: live evaluation results"
```

- [ ] **Step 9: Clean up.** Ask the project owner whether to terminate the instance now or keep it for a second run. Terminate only on a yes: `aws ec2 terminate-instances --region ap-southeast-2 --instance-ids <id>`.
