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
