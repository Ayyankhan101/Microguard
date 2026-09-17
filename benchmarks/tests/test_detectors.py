"""Detectors must do exactly what PREREGISTRATION.md says, and nothing kinder."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from benchmarks.detectors import (
    HUMAN_REASON_CONFIDENCE,
    RULE_CONFIDENCES,
    Actor,
    Decision,
    is_blocked_request,
    load_actors,
    mg_blend,
    mg_heuristic,
    mg_model,
    path_blocklist,
    rate_limit,
    recover_heuristic_confidence,
    rescored,
    rewrite_user_agent,
    scan_verdicts,
    ua_regex,
)
from microguard.parser import LogEntry
from microguard.scoring import compute_combined_score

CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
T0 = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)


def entry(ip="10.0.0.1", seconds=0.0, url="/", ua=CHROME, method="GET", status=200):
    return LogEntry(ip, T0 + timedelta(seconds=seconds), method, url, status, 100, "-", ua)


def decision(score=0.2, model=0.731, label="human", reason="", features=(0.0,) * 19):
    return Decision(score, model, label, reason, features)


class TestUaRegex:
    def test_flags_at_the_first_telling_request(self):
        actor = Actor("a", [entry(ua=CHROME), entry(ua="python-requests/2.31.0")])
        assert ua_regex(actor).first_flag == 2

    @pytest.mark.parametrize("ua", ["", "-", "Googlebot/2.1", "HeadlessChrome/125", "sqlmap/1.8"])
    def test_catches(self, ua):
        assert ua_regex(Actor("a", [entry(ua=ua)])).flagged

    def test_a_spoofed_browser_walks_through(self):
        assert not ua_regex(Actor("a", [entry(ua=CHROME)] * 50)).flagged


class TestRateLimit:
    def test_sixty_one_inside_a_minute(self):
        actor = Actor("a", [entry(seconds=i * 0.5) for i in range(61)])
        assert rate_limit()(actor).first_flag == 61

    def test_exactly_one_per_second_never_trips(self):
        actor = Actor("a", [entry(seconds=float(i)) for i in range(200)])
        assert not rate_limit()(actor).flagged


class TestPathBlocklist:
    @pytest.mark.parametrize(
        "url",
        [
            "/.env",
            "/wp-login.php",
            "/Server-Status",
            "/search?q=1%27%20OR%201=1",
            "/search?q=1+UNION+SELECT+null",
            "/x?f=..%2F..%2Fetc%2Fpasswd",
            "/?q=%24%7Bjndi:ldap://x%7D",
        ],
    )
    def test_blocks(self, url):
        assert is_blocked_request(url)

    @pytest.mark.parametrize("url", ["/catalog/p001.html", "/search?q=blue+shoes", "/login"])
    def test_passes(self, url):
        assert not is_blocked_request(url)

    def test_verdict_points_at_the_request(self):
        actor = Actor("a", [entry(url="/"), entry(url="/.git/config")])
        assert path_blocklist(actor).first_flag == 2


class TestLiveDetectors:
    def test_blend_is_strictly_above_like_the_scorer(self):
        actor = Actor("a", decisions=[decision(score=0.85), decision(score=0.851)])
        v = mg_blend()(actor)
        assert v.first_flag == 2
        assert v.score == 0.851

    def test_model_and_heuristic(self):
        actor = Actor("a", decisions=[decision(model=0.4), decision(label="bot", model=0.6)])
        assert mg_model()(actor).first_flag == 2
        assert mg_heuristic(actor).first_flag == 2

    def test_no_decisions_is_not_caught(self):
        assert not mg_blend()(Actor("a")).flagged


class TestConfidenceRecovery:
    def test_table_matches_every_confidence_labeler_can_return(self):
        source = Path("microguard/labeler.py").read_text(encoding="utf-8")
        found: dict[str, set[float]] = {"bot": set(), "human": set()}
        for label, conf in re.findall(r"return '(bot|human)', ([0-9.]+)", source):
            found[label].add(float(conf))
        # Helper verdicts returned as (True, conf, reason) and folded into 'bot'.
        found["bot"].update(float(c) for c in re.findall(r"True,\s*([0-9.]+),", source))
        # _check_api_key_patterns and _check_botnet_signatures are applied at
        # fixed confidences in the chain, which the first regex already reads.
        assert found["bot"] == set(RULE_CONFIDENCES["bot"])
        assert found["human"] == set(RULE_CONFIDENCES["human"])

    def test_human_reasons_name_the_confidence_labeler_returns(self):
        source = Path("microguard/labeler.py").read_text(encoding="utf-8")
        returned = re.findall(r"return 'human', ([0-9.]+), f?'([^'{]+)", source)
        assert returned, "labeler.py no longer matches this parser"
        for conf, reason in returned:
            named = [c for prefix, c in HUMAN_REASON_CONFIDENCE if reason.startswith(prefix)]
            assert named and named[0] == float(conf), reason

    @pytest.mark.parametrize("model", [0.0, 0.1, 0.4, 0.7309067755517084, 0.93, 1.0])
    def test_round_trips_every_rule_at_many_model_scores(self, model):
        reasons = {c: prefix for prefix, c in reversed(HUMAN_REASON_CONFIDENCE)}
        for label, confs in RULE_CONFIDENCES.items():
            for conf in confs:
                score = compute_combined_score(label, conf, model)
                reason = reasons.get(conf, "") if label == "human" else ""
                assert recover_heuristic_confidence(label, score, model, reason) == conf

    def test_refuses_a_row_no_rule_produces(self):
        with pytest.raises(ValueError):
            recover_heuristic_confidence("bot", 0.123456, 0.2)


class TestRescored:
    def test_swapping_in_the_same_model_reproduces_the_live_run(self):
        model = 0.7309067755517084
        rows = [
            decision(compute_combined_score("human", 0.5, model), model, "human"),
            decision(compute_combined_score("bot", 0.75, model), model, "bot"),
            decision(compute_combined_score("bot", 0.95, model), model, "bot"),
        ]
        actor = Actor("a", decisions=rows)
        live = mg_blend()(actor)
        again = rescored(lambda _f: model, threshold=0.85, blend=True)(actor)
        assert (again.flagged, again.first_flag, again.score) == (
            live.flagged, live.first_flag, live.score
        )

    def test_a_better_model_changes_only_the_model_half(self):
        human = decision(compute_combined_score("human", 0.5, 0.731), 0.731, "human")
        actor = Actor("a", decisions=[human])
        # A confident model cannot push a capped 0.5 human past 0.85.
        assert not rescored(lambda _f: 1.0, threshold=0.85, blend=True)(actor).flagged
        assert rescored(lambda _f: 1.0, threshold=0.5, blend=False)(actor).flagged


class TestEvidence:
    def test_joins_log_and_archive_and_drops_strangers(self, tmp_path):
        log = tmp_path / "access.log"
        log.write_text(
            '10.66.1.1 - - [17/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.7.1"\n'
            '127.0.0.1 - - [17/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 5 "-" "ab"\n',
            encoding="utf-8",
        )
        archive = tmp_path / "collected.jsonl"
        row = {"ip": "10.66.1.1", "score": 0.95, "model_score": 0.73,
               "heuristic_label": "bot", "heuristic_reason": "x", "features": [0.0] * 19}
        archive.write_text(json.dumps(row) + "\n", encoding="utf-8")
        actors = load_actors([str(log)], str(archive), ips={"10.66.1.1"})
        assert list(actors) == ["10.66.1.1"]
        assert len(actors["10.66.1.1"].requests) == 1
        assert actors["10.66.1.1"].decisions[0].score == 0.95

    def test_rewrite_ua_keeps_trailing_fields(self):
        line = '1.2.3.4 - - [22/Jan/2019:03:56:14 +0330] "GET / HTTP/1.1" 200 5 "-" "Googlebot/2.1" "-"'
        out = rewrite_user_agent(line, "Googlebot/2.1", CHROME)
        assert out.endswith(f'"{CHROME}" "-"')

    def test_scan_verdicts_run_the_real_scan(self, tmp_path):
        log = tmp_path / "access.log"
        lines = [
            f'10.66.1.1 - - [17/Sep/2026:12:00:{i:02d} +0000] "GET /.env HTTP/1.1" 404 5 "-" "curl/8.7.1"'
            for i in range(3)
        ]
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verdicts = scan_verdicts(str(log))
        assert verdicts["10.66.1.1"].flagged
