"""Every detector the benchmark scores, behind one shape.

A detector reads one actor's evidence and returns a Verdict. Parameters are
the ones fixed in PREREGISTRATION.md; changing one here without recording a
deviation in the report invalidates the comparison.

Two kinds of evidence, because the product has two paths:

- `requests`: the actor's access-log lines. What an operator's nginx wrote,
  and all that a log-reading baseline (or `microguard scan`) ever sees.
- `decisions`: the actor's archived live decisions from `serve --collect-to`,
  in arrival order. What the real scorer said at each request, as it said it.
"""

from __future__ import annotations

import contextlib
import io
import math
import re
from collections import deque
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from microguard.collect import load_collected
from microguard.evaluate import PROBE_PREFIXES
from microguard.parser import LogEntry, parse_file
from microguard.scoring import BLOCK_THRESHOLD_DEFAULT, compute_combined_score

MODEL_THRESHOLD = 0.5
SCAN_THRESHOLD = 0.7  # microguard.cli.DEFAULT_THRESHOLD, restated so a change there is visible here

UA_REGEX = re.compile(
    r"bot|crawl|spider|slurp|curl|wget|python|go-http|java/|libwww|perl|ruby|php/"
    r"|scrapy|httpclient|okhttp|axios|node-fetch|headless|phantom|selenium|nmap"
    r"|sqlmap|nikto|nuclei|ffuf|gobuster|dirbuster|wfuzz|masscan|zgrab|hydra",
    re.IGNORECASE,
)
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_S = 60.0
EXTRA_BLOCKED_PREFIXES = ("/server-status", "/actuator", "/.ds_store")
PAYLOAD_MARKERS = (
    "../", "/etc/passwd", "union select", "<script", "' or ", "sleep(", "${jndi:",
    "waitfor delay",
)

# Every confidence labeler.py can return, per label. A live archive row stores
# the blend and the model score but not the heuristic confidence, and the
# blend cannot be inverted uniquely for a 'human' verdict. The true confidence
# is always one of these, which settles it. benchmarks/tests/test_detectors.py
# re-reads labeler.py so a new confidence there fails loudly instead of
# mis-resolving here.
RULE_CONFIDENCES = {
    "bot": (0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.88, 0.9, 0.95),
    "human": (0.5, 0.6, 0.65, 0.7, 0.75),
}
# A 'bot' blend is strictly increasing in the confidence, so it inverts
# uniquely. A 'human' blend rises then falls, so two confidences can land on
# one score (0.6 and 0.7 at model 0.1, for one). The archived reason names the
# rule, and the rule fixes the confidence.
HUMAN_REASON_CONFIDENCE = (
    ("empty session", 0.5),
    ("known browser, reasonable session", 0.75),
    ("variable timing", 0.7),
    ("exploring", 0.65),
    ("natural navigation", 0.6),
    ("Cloudflare-protected site", 0.65),
    ("no strong signals", 0.5),
)


@dataclass(frozen=True)
class Decision:
    score: float
    model_score: float
    heuristic_label: str
    heuristic_reason: str
    features: tuple[float, ...] | None


@dataclass
class Actor:
    ip: str
    requests: list[LogEntry] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)


@dataclass(frozen=True)
class Verdict:
    """flagged, where (1-based, into the evidence the detector read), and a
    score for ranking metrics when the detector has one."""

    flagged: bool
    first_flag: int | None = None
    score: float | None = None


Detector = Callable[[Actor], Verdict]


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


def load_actors(
    access_logs: Iterable[str],
    archive: str | None = None,
    ips: Collection[str] | None = None,
) -> dict[str, Actor]:
    """Join access logs and a live archive by client IP.

    `ips` restricts to the actors under evaluation; stray loopback and
    setup traffic never becomes an actor.
    """
    actors: dict[str, Actor] = {}

    def actor_for(ip: str) -> Actor | None:
        if ips is not None and ip not in ips:
            return None
        return actors.setdefault(ip, Actor(ip))

    for path in access_logs:
        for entry in parse_file(path, fmt="nginx"):
            actor = actor_for(entry.ip)
            if actor is not None:
                actor.requests.append(entry)
    for actor in actors.values():
        actor.requests.sort(key=lambda e: e.timestamp)  # stable: log order within a second

    if archive is not None:
        for row in load_collected(archive):
            ip = row.get("ip")
            if not isinstance(ip, str) or not isinstance(row.get("score"), (int, float)):
                continue
            actor = actor_for(ip)
            if actor is None:
                continue
            actor.decisions.append(
                Decision(
                    score=float(row["score"]),
                    model_score=float(row.get("model_score") or 0.0),
                    heuristic_label=str(row.get("heuristic_label") or ""),
                    heuristic_reason=str(row.get("heuristic_reason") or ""),
                    features=tuple(row["features"]),
                )
            )
    return actors


def rewrite_user_agent(raw_line: str, old: str, new: str) -> str:
    """Replace the quoted UA field of a combined-format line.

    The last occurrence, because nginx appends fields after the UA
    (Zanbil logs carry a trailing "$http_x_forwarded_for").
    """
    quoted = f'"{old}"'
    at = raw_line.rfind(quoted)
    if at < 0:
        raise ValueError("user agent not found in line")
    return raw_line[:at] + f'"{new}"' + raw_line[at + len(quoted):]


# --------------------------------------------------------------------------
# Baselines: what an operator could deploy in ten minutes instead
# --------------------------------------------------------------------------


def ua_regex(actor: Actor) -> Verdict:
    for i, entry in enumerate(actor.requests, 1):
        ua = entry.user_agent.strip()
        if not ua or ua == "-" or UA_REGEX.search(ua):
            return Verdict(True, i)
    return Verdict(False)


def rate_limit(
    limit: int = RATE_LIMIT_REQUESTS, window_s: float = RATE_LIMIT_WINDOW_S
) -> Detector:
    """More than `limit` requests inside any `window_s`-second window."""

    def detect(actor: Actor) -> Verdict:
        recent: deque[float] = deque()
        for i, entry in enumerate(actor.requests, 1):
            now = entry.timestamp.timestamp()
            recent.append(now)
            while now - recent[0] >= window_s:
                recent.popleft()
            if len(recent) > limit:
                return Verdict(True, i)
        return Verdict(False)

    detect.__name__ = f"rate_limit_{limit}"
    return detect


def is_blocked_request(url: str) -> bool:
    path = urlsplit(url).path.lower()
    if path.startswith(tuple(p.lower() for p in PROBE_PREFIXES) + EXTRA_BLOCKED_PREFIXES):
        return True
    decoded = unquote(unquote(url)).replace("+", " ").lower()
    return any(marker in decoded for marker in PAYLOAD_MARKERS)


def path_blocklist(actor: Actor) -> Verdict:
    for i, entry in enumerate(actor.requests, 1):
        if is_blocked_request(entry.url):
            return Verdict(True, i)
    return Verdict(False)


def ip_set(flagged_ips: Collection[str]) -> Detector:
    """A detector whose verdicts were computed elsewhere (CrowdSec, a scan)."""

    def detect(actor: Actor) -> Verdict:
        return Verdict(actor.ip in flagged_ips)

    return detect


# --------------------------------------------------------------------------
# microguard, live path: read the archived decisions
# --------------------------------------------------------------------------


def _first_over(values: Iterable[float], threshold: float) -> Verdict:
    best: float | None = None
    first: int | None = None
    for i, value in enumerate(values, 1):
        best = value if best is None else max(best, value)
        if first is None and value > threshold:
            first = i
    return Verdict(first is not None, first, best)


def mg_heuristic(actor: Actor) -> Verdict:
    for i, d in enumerate(actor.decisions, 1):
        if d.heuristic_label == "bot":
            return Verdict(True, i)
    return Verdict(False)


def mg_blend(threshold: float = BLOCK_THRESHOLD_DEFAULT) -> Detector:
    def detect(actor: Actor) -> Verdict:
        return _first_over((d.score for d in actor.decisions), threshold)

    return detect


def mg_model(threshold: float = MODEL_THRESHOLD) -> Detector:
    def detect(actor: Actor) -> Verdict:
        return _first_over((d.model_score for d in actor.decisions), threshold)

    return detect


def recover_heuristic_confidence(
    label: str, score: float, model_score: float, reason: str = ""
) -> float:
    """The heuristic confidence behind an archived blend.

    Raises ValueError unless exactly one rule confidence reproduces the row
    (after the reason breaks a tie): none means the row did not come from
    `compute_combined_score` as this code knows it.
    """
    matches = {
        conf
        for conf in RULE_CONFIDENCES.get(label, ())
        if math.isclose(compute_combined_score(label, conf, model_score), score, abs_tol=1e-9)
    }
    if len(matches) > 1 and label == "human":
        named = {conf for prefix, conf in HUMAN_REASON_CONFIDENCE if reason.startswith(prefix)}
        matches &= named
    if len(matches) != 1:
        raise ValueError(
            f"{len(matches)} rule confidences reproduce {label} score={score} model={model_score}"
        )
    return matches.pop()


def rescored(predict: Callable[[list[float]], float], threshold: float, blend: bool) -> Detector:
    """Re-score the archived feature vectors with a different model.

    The session state, rules, and heuristic verdict at each request are
    exactly what the live run produced; only the model is swapped. That is
    the paired comparison Suite D needs: same actors, same requests.
    """

    def detect(actor: Actor) -> Verdict:
        values = []
        for d in actor.decisions:
            if d.features is None:
                continue
            m = predict(list(d.features))
            if not blend:
                values.append(m)
            elif d.heuristic_label == "automated-integration":
                values.append(0.0)
            else:
                conf = recover_heuristic_confidence(
                    d.heuristic_label, d.score, d.model_score, d.heuristic_reason
                )
                values.append(compute_combined_score(d.heuristic_label, conf, m))
        return _first_over(values, threshold)

    return detect


# --------------------------------------------------------------------------
# microguard, offline path: the real `microguard scan`
# --------------------------------------------------------------------------


def scan_verdicts(log_path: str, model_path: str | None = None) -> dict[str, Verdict]:
    """Run `scan_logfile` exactly as the CLI does; one verdict per IP.

    An IP with several sessions is flagged if any session is.
    """
    from microguard.cli import scan_logfile
    from microguard.model import DEFAULT_MODEL_PATH

    with contextlib.redirect_stderr(io.StringIO()):
        results = scan_logfile(
            log_path, fmt="nginx", threshold=SCAN_THRESHOLD,
            model_path=model_path or DEFAULT_MODEL_PATH,
        )
    if results.get("error"):
        raise RuntimeError(results["error"])
    verdicts: dict[str, Verdict] = {}
    for session in results["sessions"]:
        ip = session["ip"]
        prior = verdicts.get(ip, Verdict(False, None, None))
        best = session["score"] if prior.score is None else max(prior.score, session["score"])
        verdicts[ip] = Verdict(prior.flagged or session["label"] == "bot", None, best)
    return verdicts


def offline_scan(verdicts: dict[str, Verdict]) -> Detector:
    def detect(actor: Actor) -> Verdict:
        return verdicts.get(actor.ip, Verdict(False))

    return detect
