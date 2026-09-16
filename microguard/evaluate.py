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

import ipaddress
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
    max_model_score: float | None = None
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
            if (
                entry.method == "POST"
                and parts.path == FINGERPRINT_PATH
                and entry.status == 200
            ):
                actor.ran_fingerprint = True

    rows, skipped = load_collected(collected_path, report_skipped=True)
    for row in rows:
        ip, score = row.get("ip"), row.get("score")
        if not isinstance(ip, str) or ip in LOOPBACK or not isinstance(score, (int, float)):
            continue
        actor = actors.setdefault(ip, Actor())
        actor.max_score = score if actor.max_score is None else max(actor.max_score, score)
        model = row.get("model_score")
        if isinstance(model, (int, float)):
            actor.max_model_score = (
                model if actor.max_model_score is None
                else max(actor.max_model_score, model)
            )
        if row.get("heuristic_label") == "bot":
            actor.heuristic_bot = True
        reason = row.get("heuristic_reason")
        if isinstance(reason, str) and reason:
            actor.reasons.add(rule_name(reason))

    return actors, skipped


def _above(threshold: float) -> Callable[[Actor], bool]:
    """Flag rule matching the scorer, which blocks on score > threshold."""
    return lambda actor: actor.max_score is not None and actor.max_score > threshold


def _model_above(threshold: float) -> Callable[[Actor], bool]:
    """The model's own verdict, before the heuristic is blended in."""
    return lambda actor: (
        actor.max_model_score is not None and actor.max_model_score > threshold
    )


def _ratio(actors: Iterable[Actor], truth: str, flagged: Callable[[Actor], bool]) -> str:
    members = [a for a in actors if a.truth == truth]
    return f"{sum(flagged(a) for a in members)}/{len(members)}"


def mask_ip(ip: str) -> str:
    """Mask a client IP so a report can be committed without publishing it.

    IPv4: last octet -> x. IPv6: everything past the first three groups -> x.
    Anything that doesn't parse as an IP is masked entirely.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "x"
    if addr.version == 4:
        a, b, c, _ = str(addr).split(".")
        return f"{a}.{b}.{c}.x"
    groups = addr.exploded.split(":")
    return ":".join(groups[:3]) + ":x"


def render_report(
    actors: dict[str, Actor], skipped_rows: int = 0, redact_ips: bool = False
) -> str:
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
    has_model = any(a.max_model_score is not None for a in scored.values())
    if has_model:
        rules += [(f"model score > {t:.2f}", _model_above(t)) for t in THRESHOLDS]

    lines += [
        "## Verdicts on labeled actors",
        "",
        (
            "Flagged means at least one request scored above the threshold. "
            "Honeypot-only bots never requested a path in the probe list, which "
            "narrows (does not eliminate) overlap with the scanner rule, whose "
            "patterns are wider."
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
    if not has_model:
        lines += [
            "",
            (
                "Model-only rows omitted: this archive predates model_score, so the "
                "model cannot be separated from the blend."
            ),
        ]

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
        shown_ip = mask_ip(ip) if redact_ips else ip
        lines.append(f"| {shown_ip} | {actor.max_score:.2f} | {actor.requests} |")

    return "\n".join(lines) + "\n"
