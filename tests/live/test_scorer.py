"""Tests for LiveScorer — in-memory store, no Redis needed."""

import logging
from datetime import datetime, timezone

import pytest

from microguard.live.scorer import LiveScorer, _load_model
from microguard.parser import LogEntry
from microguard.signals import Signals


def _make_entry(ip="1.2.3.4", status=200, url="/api/test", ua="Mozilla/5.0", **kwargs):
    return LogEntry(
        ip=ip,
        timestamp=datetime.now(timezone.utc),
        method="GET",
        url=url,
        status=status,
        size=100,
        referer="",
        user_agent=ua,
        **kwargs,
    )


@pytest.fixture()
def scorer(store):
    return LiveScorer(store, block_threshold=0.85)


# --- Basic scoring ---


def test_first_request_always_human(scorer):
    entry = _make_entry()
    result = scorer.score_request(entry)
    assert result["label"] == "human"
    assert result["request_count"] == 1


def test_session_accumulates_requests(scorer):
    for i in range(5):
        scorer.score_request(_make_entry(url=f"/page/{i}"))
    session = scorer._store.peek("1.2.3.4")
    assert session is not None
    assert session.request_count == 5


def test_result_contains_score_and_reason(scorer):
    result = scorer.score_request(_make_entry())
    assert "score" in result
    assert "reason" in result
    assert isinstance(result["score"], float)


# --- Automated integration short-circuit ---


def test_automated_integration_not_blocked(scorer):
    entry = _make_entry(ua="Stripe/2.0")
    result = scorer.score_request(entry)
    assert result["label"] == "human"
    assert "automated-integration" in result["reason"]


def test_webhook_not_blocked(scorer):
    entry = _make_entry(ua="GitHub-Hookshot/1.0")
    result = scorer.score_request(entry)
    assert result["label"] == "human"


# --- Bot detection ---


def test_known_bot_ua_detected(scorer):
    entry = _make_entry(ua="python-requests/2.28.0")
    # Single request with known bot UA — heuristic labels it bot,
    # but score depends on confidence and model.
    result = scorer.score_request(entry)
    # Just verify it ran without error; actual classification
    # depends on model availability
    assert "label" in result
    assert result["label"] in ("bot", "human")


def test_scanner_patterns_detected(scorer):
    entry = _make_entry(url="/wp-admin/install.php", ua="Mozilla/5.0")
    result = scorer.score_request(entry)
    assert "label" in result


# --- Multiple IPs isolated ---


def test_different_ips_are_isolated(store):
    s1 = LiveScorer(store, block_threshold=0.85)
    s2 = LiveScorer(store, block_threshold=0.85)

    s1.score_request(_make_entry(ip="1.1.1.1"))
    s2.score_request(_make_entry(ip="2.2.2.2"))

    session1 = store.peek("1.1.1.1")
    session2 = store.peek("2.2.2.2")
    assert session1 is not None
    assert session2 is not None
    assert session1.request_count == 1
    assert session2.request_count == 1


# --- Edge cases ---


def test_empty_user_agent(scorer):
    entry = _make_entry(ua="")
    result = scorer.score_request(entry)
    assert result["label"] in ("bot", "human")


def test_model_load_failure_graceful(store):
    scorer = LiveScorer(store, model_path="/nonexistent/path.pkl")
    entry = _make_entry()
    result = scorer.score_request(entry)
    # Should still work, just without model score
    assert result["label"] in ("bot", "human")
    assert result["score"] >= 0.0


def test_custom_threshold(store):
    scorer = LiveScorer(store, block_threshold=0.1)
    entry = _make_entry(ua="python-requests/2.28.0")
    result = scorer.score_request(entry)
    # Even a single bot request should exceed 0.1 threshold
    assert result["label"] == "bot"


def test_custom_short_circuit_label(store):
    """Short circuit matches when label_session returns the short_circuit_label string."""
    scorer = LiveScorer(store, short_circuit_label="automated-integration")
    entry = _make_entry(ua="Stripe/2.0")
    result = scorer.score_request(entry)
    assert result["label"] == "human"
    assert "automated-integration" in result["reason"]


def test_session_preserved_across_requests(store):
    scorer = LiveScorer(store, block_threshold=0.85)
    for i in range(3):
        scorer.score_request(_make_entry(ip="10.0.0.1", url=f"/api/{i}"))
    session = store.peek("10.0.0.1")
    assert session is not None
    assert session.request_count == 3


# --- _load_model edge cases ---


def test_packaged_model_resolves():
    """The default path must find the model the repo actually ships.

    This is the regression test for a bug that hid for five commits:
    _load_model searched for data/bot_model.pkl, which has never existed here,
    returned None, and the scorer silently fell back to model_score = 0.0. Every
    live blocking decision ran on heuristics alone with nothing reporting it.
    A test that tolerates a missing model cannot catch that, so this one does
    not tolerate it.
    """
    assert _load_model(None) is not None


def test_scorer_reports_the_model_is_in_play(store):
    assert LiveScorer(store).model_loaded is True


def test_result_reports_model_loaded(scorer):
    assert scorer.score_request(_make_entry())["model_loaded"] is True


def test_load_model_nonexistent_path(caplog):
    """A missing model degrades to heuristics, but never quietly."""
    with caplog.at_level(logging.WARNING):
        assert _load_model("/nonexistent/model.json") is None
    assert "heuristics only" in caplog.text


def test_scorer_without_a_model_says_so(store):
    scorer = LiveScorer(store, model_path="/nonexistent/model.json")
    assert scorer.model_loaded is False
    assert scorer.score_request(_make_entry())["model_loaded"] is False


def test_load_model_corrupt_file(tmp_path, caplog):
    """A corrupt model degrades to heuristics, and logs why."""
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("not valid json {{{", encoding='utf-8')
    with caplog.at_level(logging.WARNING):
        assert _load_model(str(corrupt)) is None
    assert "failed to load" in caplog.text


# --- Block boundary ---


class TestBlockBoundary:
    """The threshold is a bar to exceed, not to reach.

    A first-time visitor gets the neutral heuristic verdict
    ('human', 0.5, 'no strong signals either way'), which caps the combined
    score at exactly 0.5. Blocking at `>=` meant any operator running a 0.5
    threshold blocked every new visitor on arrival, contradicting spec AC#7:
    no session yet means no evidence of bot behavior, so allow by default.
    """

    def test_score_exactly_at_the_threshold_is_allowed(self, store):
        scorer = LiveScorer(store, block_threshold=0.5)
        result = scorer.score_request(_make_entry())
        assert result["score"] <= 0.5
        assert result["label"] == "human"

    def test_unknown_visitor_is_allowed_at_an_aggressive_threshold(self, store):
        """Spec AC#7: never-seen IP + UA, first request, no evidence -> allow."""
        scorer = LiveScorer(store, block_threshold=0.5)
        assert scorer.score_request(_make_entry(ip="203.0.113.77"))["label"] == "human"

    def test_threshold_of_one_never_blocks(self, store):
        scorer = LiveScorer(store, block_threshold=1.0)
        for i in range(6):
            result = scorer.score_request(
                _make_entry(ip="10.0.0.9", ua="curl/7.68", url=f"/wp-admin/{i}.php")
            )
        assert result["label"] == "human"

    def test_a_score_above_the_threshold_still_blocks(self, store):
        scorer = LiveScorer(store, block_threshold=0.5)
        result = scorer.score_request(
            _make_entry(ip="10.0.0.8", url="/wp-admin/setup-config.php")
        )
        assert result["score"] > 0.5
        assert result["label"] == "bot"


# --- Decision payload ---


EXPECTED_KEYS = {
    "ip", "label", "score", "model_score", "heuristic_label",
    "heuristic_confidence", "heuristic_reason", "request_count",
    "duration", "model_loaded", "model_refused", "reason", "block_threshold",
    # What the external signals said, and which of them were allowed to decide.
    # An unpromoted signal changes no verdict but is still recorded, which is
    # the only way an operator can see what enforcing it would cost.
    "signals",
    # What a later correction points at, and what it trains on. The live
    # session expires long before anyone reviews a block, so the vector has to
    # travel with the decision rather than be recomputed.
    "id",
    "features",
}


class TestDecisionPayload:
    """The response carries why, not just what.

    A single blended float says a customer was blocked but not whether the
    rules or the model drove it, which is what you need to tune a threshold or
    explain the block. It is also how a dead model stays visible: model_score
    pinned at 0.0 across every response is a symptom you can see.
    """

    def test_scored_path_returns_the_full_shape(self, scorer):
        assert set(scorer.score_request(_make_entry())) == EXPECTED_KEYS

    def test_short_circuit_path_returns_the_same_shape(self, store):
        """The automated-integration branch must not report a different shape."""
        scorer = LiveScorer(store)
        result = scorer.score_request(_make_entry(ua="Slackbot 1.0 (+https://api.slack.com/robots)"))
        assert set(result) == EXPECTED_KEYS

    def test_breakdown_explains_the_score(self, store):
        scorer = LiveScorer(store, block_threshold=0.85)
        result = scorer.score_request(
            _make_entry(ip="10.5.5.5", url="/wp-admin/setup-config.php")
        )
        assert result["label"] == "bot"
        assert result["heuristic_label"] == "bot"
        assert result["heuristic_confidence"] == pytest.approx(0.95)
        assert "scanner" in result["heuristic_reason"]
        # the model still reported a number of its own
        assert 0.0 <= result["model_score"] <= 1.0

    def test_model_score_is_zero_when_no_model_is_loaded(self, store):
        scorer = LiveScorer(store, model_path="/nonexistent/model.json")
        result = scorer.score_request(_make_entry())
        assert result["model_score"] == 0.0
        assert result["model_loaded"] is False

    def test_ip_and_duration_are_reported(self, store):
        scorer = LiveScorer(store)
        for _ in range(3):
            result = scorer.score_request(_make_entry(ip="10.6.6.6"))
        assert result["ip"] == "10.6.6.6"
        assert result["request_count"] == 3
        assert isinstance(result["duration"], float)


def test_threshold_default_is_shared(store):
    """Scorer, server, middleware and CLI must not drift apart."""
    from microguard.scoring import BLOCK_THRESHOLD_DEFAULT

    assert LiveScorer(store)._block_threshold == BLOCK_THRESHOLD_DEFAULT


class TestDecisionRecording:
    """The scorer optionally tees every decision to a recorder.

    Recording exists for the dashboard; blocking exists for the site. The
    second must never depend on the first, which is what most of these pin.
    """

    def test_scored_decisions_reach_the_recorder(self, store):
        from microguard.events import InMemoryDecisionRecorder

        recorder = InMemoryDecisionRecorder()
        scorer = LiveScorer(store, recorder=recorder)

        result = scorer.score_request(_make_entry(ua="python-requests/2.31"))

        assert recorder.recent()[0]["ip"] == result["ip"]
        assert recorder.stats()["total"] == 1

    def test_short_circuited_integrations_are_recorded_too(self, store):
        from microguard.events import InMemoryDecisionRecorder

        recorder = InMemoryDecisionRecorder()
        scorer = LiveScorer(store, recorder=recorder)

        scorer.score_request(_make_entry(url="/webhooks/stripe", ua="Stripe/1.0"))

        assert recorder.stats()["total"] == 1

    def test_a_recorder_that_raises_does_not_change_the_verdict(self, store):
        class ExplodingRecorder:
            def record(self, result):
                raise RuntimeError("redis is down")

        entry = _make_entry(ua="curl/8.0")
        expected = LiveScorer(store, block_threshold=0.5).score_request(entry)
        store.delete(entry.ip)

        scorer = LiveScorer(store, block_threshold=0.5, recorder=ExplodingRecorder())
        result = scorer.score_request(entry)

        assert result["label"] == expected["label"]
        assert result["score"] == expected["score"]

    def test_a_recorder_that_raises_is_logged_not_swallowed_silently(self, store, caplog):
        class ExplodingRecorder:
            def record(self, result):
                raise RuntimeError("redis is down")

        scorer = LiveScorer(store, recorder=ExplodingRecorder())

        with caplog.at_level(logging.ERROR):
            scorer.score_request(_make_entry())

        assert "redis is down" in caplog.text

    def test_no_recorder_is_the_default(self, store):
        scorer = LiveScorer(store)

        assert scorer.score_request(_make_entry())["label"] == "human"


class TestRuntimeThreshold:
    """The block threshold can be moved without restarting the scorer.

    Tuning a live threshold today means editing a flag and restarting, which
    drops every in-flight session. A source lets an operator move it from the
    dashboard; the constructor value stays the default when there is none.
    """

    def test_the_source_overrides_the_constructor_threshold(self, store):
        scorer = LiveScorer(store, block_threshold=1.0, threshold_source=lambda: 0.0)

        result = scorer.score_request(_make_entry(ua="curl/8.0"))

        assert result["label"] == "bot"

    def test_the_constructor_value_is_used_when_the_source_returns_none(self, store):
        scorer = LiveScorer(store, block_threshold=1.0, threshold_source=lambda: None)

        assert scorer.score_request(_make_entry(ua="curl/8.0"))["label"] == "human"

    def test_the_threshold_is_read_per_request_not_cached_by_the_scorer(self, store):
        thresholds = iter([1.0, 0.0])
        scorer = LiveScorer(
            store, block_threshold=1.0, threshold_source=lambda: next(thresholds)
        )

        first = scorer.score_request(_make_entry(ua="curl/8.0"))
        second = scorer.score_request(_make_entry(ua="curl/8.0"))

        assert first["label"] == "human"
        assert second["label"] == "bot"

    def test_a_source_that_raises_falls_back_to_the_constructor_threshold(self, store):
        def exploding():
            raise RuntimeError("redis is down")

        scorer = LiveScorer(store, block_threshold=1.0, threshold_source=exploding)

        assert scorer.score_request(_make_entry(ua="curl/8.0"))["label"] == "human"

    def test_the_threshold_used_is_reported_in_the_decision(self, store):
        scorer = LiveScorer(store, block_threshold=1.0, threshold_source=lambda: 0.25)

        assert scorer.score_request(_make_entry())["block_threshold"] == 0.25


def test_fail_open_payloads_match_the_real_decision_shape(store):
    """Both entrypoints hand back a canned payload when scoring blows up.

    It only avoids downstream special-casing if that payload has the same keys
    as a real decision, so this pins the two together rather than trusting the
    comment above it. Both entrypoints now build it from one function, which is
    what keeps a key added to the real decision from being added to only one of
    them -- so this asserts the builder, and that both callers use it.
    """
    from microguard.live import middleware, server
    from microguard.live.scorer import fail_open_result

    real = LiveScorer(store).score_request(_make_entry())

    assert set(fail_open_result("1.2.3.4")) == set(real)
    assert middleware.fail_open_result is fail_open_result
    assert server.fail_open_result is fail_open_result


class TestSignalPromotion:
    """Decision 10A: a resolved signal is recorded but cannot decide a verdict
    until the deployment promotes its source."""

    def test_an_unpromoted_signal_is_recorded_but_does_not_block(self, store):
        store.set_signals("1.2.3.4", Signals(resolved=True, tor_exit=True))
        result = LiveScorer(store).score_request(_make_entry())

        assert result["label"] == "human"
        assert result["signals"] == {
            "resolved": True,
            "tor_exit": True,
            "hosting_range": False,
            "abuse_score": None,
            "promoted": [],
        }

    def test_a_promoted_signal_decides(self, store):
        store.set_signals("1.2.3.4", Signals(resolved=True, abuse_score=99.0))
        scorer = LiveScorer(store, promoted_source=lambda: frozenset({"abuseipdb"}))

        result = scorer.score_request(_make_entry())

        assert result["label"] == "bot"
        assert "AbuseIPDB" in result["heuristic_reason"]
        assert result["signals"]["promoted"] == ["abuseipdb"]

    def test_unresolved_signals_report_only_that(self, store):
        """No signal data for this actor. The record must say so rather than
        reporting a clean lookup that never happened."""
        result = LiveScorer(store).score_request(_make_entry())
        assert result["signals"] == {"resolved": False}

    def test_a_failing_promotion_source_promotes_nothing(self, store, caplog):
        """An unreachable config store must not start enforcing a signal
        nobody approved. Same fail-safe direction as the threshold source."""
        def boom() -> frozenset[str]:
            raise RuntimeError("config store unreachable")

        store.set_signals("1.2.3.4", Signals(resolved=True, tor_exit=True))
        scorer = LiveScorer(store, promoted_source=boom)

        result = scorer.score_request(_make_entry())

        assert result["label"] == "human"
        assert result["signals"]["promoted"] == []
        assert "promotion source failed" in caplog.text


class TestCollectionSink:
    """Archiving decisions is separate from recording them for the dashboard.

    `mg:v1:events` is capped at 1000 and LTRIMmed, so it cannot be the source
    of a training set. The collector is the durable copy, and it has to run
    alongside the recorder rather than instead of it.
    """

    def test_a_scored_decision_reaches_the_collector(self, store, tmp_path):
        from microguard.collect import DecisionCollector, load_collected

        path = tmp_path / "collected.jsonl"
        scorer = LiveScorer(
            store, block_threshold=0.85, collector=DecisionCollector(path)
        )

        scorer.score_request(_make_entry(ip="9.9.9.9"))

        rows = load_collected(path)
        assert len(rows) == 1
        assert rows[0]["ip"] == "9.9.9.9"
        assert len(rows[0]["features"]) == 19

    def test_the_dashboard_recorder_still_sees_it_too(self, store, tmp_path):
        from microguard.collect import DecisionCollector
        from microguard.events import InMemoryDecisionRecorder

        recorder = InMemoryDecisionRecorder()
        scorer = LiveScorer(
            store,
            block_threshold=0.85,
            recorder=recorder,
            collector=DecisionCollector(tmp_path / "collected.jsonl"),
        )

        scorer.score_request(_make_entry())

        assert recorder.stats()["total"] == 1

    def test_a_collector_failure_never_becomes_an_outage(self, store, tmp_path):
        """nginx turns any non-2xx/401/403 from /check into a 500 for the
        visitor, so a failed archive write must not reach them."""
        class Exploding:
            def record(self, decision):
                raise RuntimeError("disk gone")

        scorer = LiveScorer(store, block_threshold=0.85, collector=Exploding())

        result = scorer.score_request(_make_entry())  # must not raise

        assert "score" in result

    def test_without_a_collector_nothing_is_written(self, store, tmp_path):
        """Collection is opt-in: the rows carry client IPs."""

        scorer = LiveScorer(store, block_threshold=0.85)
        scorer.score_request(_make_entry())

        assert not (tmp_path / "collected.jsonl").exists()
        assert scorer._collector is None


class TestADegenerateModelIsAnnounced:
    """0.6 of the combined score comes from the model.

    When the model answers the same for every input, that 0.6 carries no
    information while reading as independent evidence beside the heuristic.
    Loading one has to say so.

    Scope: total collapse only. The shipped model is a two-valued step
    function that learned a leaked column, and it passes this check -- see
    `_warn_if_degenerate` for why no load-time probe catches that, and
    tests/test_dataset_integrity.py for where it is caught instead.
    """

    def test_loading_a_constant_model_logs_a_warning_naming_the_file(
        self, store, tmp_path, caplog
    ):
        import logging

        from microguard.model import BotDetector

        detector = BotDetector()
        for neuron in detector.model.layers[0].neurons:
            for weight in neuron.w:
                weight.data = 0.0
            neuron.b.data = -1.0
        # Deliberately NOT named "constant.json": model.py already warns
        # about a missing normalization.json and quotes the path, so a
        # filename carrying the word under test would make this pass on the
        # wrong warning. It did, the first time this test was written.
        path = tmp_path / "shipped.json"
        detector.save(str(path))

        with caplog.at_level(logging.WARNING, logger="microguard.live.scorer"):
            LiveScorer(store, model_path=path)

        assert "answers identically" in caplog.text, (
            f"no degeneracy warning; got: {caplog.text!r}"
        )
        assert "shipped.json" in caplog.text

    def test_a_working_model_is_not_flagged(self, store, tmp_path, caplog):
        import logging
        import random

        from microguard.model import BotDetector

        random.seed(42)
        detector = BotDetector()
        features = [[random.uniform(0.0, 1.0) for _ in range(19)] for _ in range(40)]
        labels = [1.0 if row[3] > 0.5 else 0.0 for row in features]
        detector.train(features, labels, epochs=25, learning_rate=0.05, verbose=False)
        path = tmp_path / "trained.json"
        detector.save(str(path))

        with caplog.at_level(logging.WARNING, logger="microguard.live.scorer"):
            LiveScorer(store, model_path=path)

        assert "answers identically" not in caplog.text


class TestTheDegeneracyProbeNeverBreaksLoading:
    def test_a_model_that_raises_on_predict_is_logged_not_propagated(
        self, store, tmp_path, caplog
    ):
        """The probe is diagnostics. It must never be why a model won't load."""
        import logging

        from microguard.live.scorer import _warn_if_degenerate

        class Exploding:
            def predict(self, row):
                raise ValueError("bad weights")

        with caplog.at_level(logging.DEBUG, logger="microguard.live.scorer"):
            _warn_if_degenerate(Exploding(), tmp_path / "m.json")  # must not raise

        assert "degeneracy probe failed" in caplog.text

    def test_no_model_is_not_probed(self, tmp_path):
        from microguard.live.scorer import _warn_if_degenerate

        _warn_if_degenerate(None, tmp_path / "m.json")  # must not raise
