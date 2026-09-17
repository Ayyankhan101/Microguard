"""End-to-end tests for the dashboard HTTP API.

These drive the real FastAPI app through TestClient — no mocking of the
scan/model engine, so a shape change in scan_logfile() or model.json shows up
here rather than in the browser.
"""

import json

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")
TestClient = fastapi_testclient.TestClient


@pytest.fixture
def client():
    from microguard.dashboard.app import create_app
    return TestClient(create_app())


class _FakeConfig:
    """An in-memory stand-in for RedisRuntimeConfig.

    The real one needs redis-py, and these tests are about the HTTP surface --
    validation, the write gate, and what a PUT leaves alone. Redis behavior is
    covered against a real server in tests/live/test_runtime_config.py.
    """

    def __init__(self):
        self._threshold = None
        self._promoted = frozenset()

    def block_threshold(self):
        return self._threshold

    def set_block_threshold(self, value):
        self._threshold = value

    def promoted_signals(self):
        return self._promoted

    def set_promoted_signals(self, sources):
        from microguard.signals import KNOWN_SIGNAL_SOURCES

        unknown = set(sources) - KNOWN_SIGNAL_SOURCES
        if unknown:
            raise ValueError(f"unknown signal source(s): {sorted(unknown)}")
        self._promoted = frozenset(sources)


@pytest.fixture
def writable_client():
    from microguard.dashboard.app import create_app

    app = create_app(allow_config_writes=True)
    app.state.runtime_config = _FakeConfig()
    return TestClient(app)


class TestHealth:
    def test_reports_version_and_model_status(self, client):
        response = client.get("/api/health")

        assert response.status_code == 200
        body = response.json()
        # Against the package, not a literal: setup.py and __init__.py had
        # already drifted two majors apart, and a literal here would have to
        # be chased on every bump.
        from microguard import __version__

        assert body["version"] == __version__
        assert isinstance(body["model_loaded"], bool)
        assert isinstance(body["redis_connected"], bool)


class TestScanSamples:
    def test_lists_bundled_sample_logs(self, client):
        response = client.get("/api/scan/samples")

        assert response.status_code == 200
        names = [s["name"] for s in response.json()["samples"]]
        assert "sample_access.log" in names

    def test_reports_line_count_for_each_sample(self, client):
        samples = client.get("/api/scan/samples").json()["samples"]

        sample = next(s for s in samples if s["name"] == "sample_access.log")
        assert sample["lines"] == 20


class TestScan:
    def test_scanning_a_bundled_sample_returns_the_scan_logfile_dict(self, client):
        from microguard.cli import scan_logfile

        response = client.post("/api/scan", json={"sample": "sample_access.log"})

        assert response.status_code == 200
        expected = scan_logfile("data/sample_access.log")
        assert response.json() == expected

    def test_threshold_is_passed_through_to_the_engine(self, client):
        response = client.post(
            "/api/scan", json={"sample": "sample_access.log", "threshold": 0.99}
        )

        assert response.json()["threshold"] == 0.99

    def test_unknown_sample_is_rejected(self, client):
        response = client.post("/api/scan", json={"sample": "nope.log"})

        assert response.status_code == 404
        assert response.json()["detail"] == "No such sample: nope.log"

    def test_sample_name_cannot_escape_the_data_directory(self, client):
        response = client.post("/api/scan", json={"sample": "../setup.py"})

        assert response.status_code == 404
        assert response.json()["detail"] == "No such sample: ../setup.py"

    def test_unknown_request_key_is_rejected(self, client):
        response = client.post(
            "/api/scan", json={"sample": "sample_access.log", "treshold": 0.5}
        )

        assert response.status_code == 422


class TestScanUpload:
    def test_uploaded_log_is_scanned(self, client):
        with open("data/sample_access.log", "rb") as handle:
            response = client.post(
                "/api/scan/upload", files={"file": ("access.log", handle, "text/plain")}
            )

        assert response.status_code == 200
        assert response.json()["total_sessions"] > 0

    def test_upload_over_the_size_cap_is_rejected(self, client, monkeypatch):
        from microguard.dashboard import api_scan

        monkeypatch.setattr(api_scan, "MAX_UPLOAD_BYTES", 10)

        response = client.post(
            "/api/scan/upload", files={"file": ("big.log", b"x" * 100, "text/plain")}
        )

        assert response.status_code == 413

    def test_upload_leaves_no_temp_file_behind(self, client, tmp_path, monkeypatch):
        import tempfile

        # tempfile caches gettempdir(), so setting TMPDIR here would do nothing.
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

        client.post("/api/scan/upload", files={"file": ("a.log", b"garbage\n", "text/plain")})

        assert list(tmp_path.iterdir()) == []

    def test_rejected_oversize_upload_leaves_no_temp_file_behind(
        self, client, tmp_path, monkeypatch
    ):
        import tempfile

        from microguard.dashboard import api_scan

        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        monkeypatch.setattr(api_scan, "MAX_UPLOAD_BYTES", 10)

        client.post("/api/scan/upload", files={"file": ("big.log", b"x" * 100, "text/plain")})

        assert list(tmp_path.iterdir()) == []


class TestScanExport:
    def test_nginx_export_matches_the_report_formatter(self, client):
        from microguard.report import format_nginx_denylist

        results = client.post("/api/scan", json={"sample": "sample_access.log"}).json()

        response = client.post(
            "/api/scan/export", json={"results": results, "format": "nginx"}
        )

        assert response.status_code == 200
        assert response.text == format_nginx_denylist(results)

    def test_html_export_is_served_as_a_download_not_a_page(self, client):
        results = client.post("/api/scan", json={"sample": "sample_access.log"}).json()

        response = client.post(
            "/api/scan/export", json={"results": results, "format": "html"}
        )

        # format_html() does no escaping (report.py:455), so it must never be
        # served as text/html from the dashboard's own origin.
        assert response.headers["content-type"].startswith("text/plain")
        assert "attachment" in response.headers["content-disposition"]

    def test_unknown_export_format_is_rejected(self, client):
        response = client.post(
            "/api/scan/export", json={"results": {}, "format": "pdf"}
        )

        assert response.status_code == 422


class TestModel:
    def test_exposes_the_trained_network_shape_and_weights(self, client):
        from microguard.features import FEATURE_NAMES

        response = client.get("/api/model")

        assert response.status_code == 200
        body = response.json()
        assert body["num_features"] == 19
        assert body["architecture"] == [4, 1]
        assert body["feature_names"] == FEATURE_NAMES
        assert len(body["weights"]) == 85

    def test_exposes_the_normalization_ranges_predict_applies(self, client):
        body = client.get("/api/model").json()

        assert len(body["normalization"]["mins"]) == 19
        assert len(body["normalization"]["maxs"]) == 19

    def test_evaluates_the_holdout_set(self, client):
        import json

        with open("data/eval_holdout.json", encoding='utf-8') as handle:
            expected_samples = json.load(handle)["n_samples"]

        response = client.post(
            "/api/model/evaluate", json={"dataset": "holdout", "threshold": 0.5}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["n_samples"] == expected_samples
        assert sum(body["confusion"].values()) == expected_samples

    def test_evaluates_the_adversarial_set(self, client):
        response = client.post(
            "/api/model/evaluate", json={"dataset": "adversarial", "threshold": 0.5}
        )

        assert response.json()["n_samples"] == 400

    def test_raising_the_threshold_cannot_increase_the_positives(self, client):
        low = client.post(
            "/api/model/evaluate", json={"dataset": "adversarial", "threshold": 0.2}
        ).json()
        high = client.post(
            "/api/model/evaluate", json={"dataset": "adversarial", "threshold": 0.9}
        ).json()

        assert high["confusion"]["tp"] <= low["confusion"]["tp"]
        assert high["confusion"]["fp"] <= low["confusion"]["fp"]

    def test_unknown_dataset_is_rejected(self, client):
        response = client.post(
            "/api/model/evaluate", json={"dataset": "training", "threshold": 0.5}
        )

        assert response.status_code == 422


class TestStaticSpa:
    """The built SPA is served from the same origin as the API."""

    @pytest.fixture
    def built_client(self, tmp_path):
        from microguard.dashboard.app import create_app

        (tmp_path / "index.html").write_text("<title>Microguard</title>", encoding='utf-8')
        (tmp_path / "app.js").write_text("console.log(1)", encoding='utf-8')
        return TestClient(create_app(static_dir=str(tmp_path)))

    def test_serves_the_index_at_the_root(self, built_client):
        response = built_client.get("/")

        assert response.status_code == 200
        assert "Microguard" in response.text

    def test_serves_built_assets(self, built_client):
        assert built_client.get("/app.js").status_code == 200

    def test_unknown_paths_fall_back_to_the_index_for_client_routing(self, built_client):
        response = built_client.get("/live")

        assert response.status_code == 200
        assert "Microguard" in response.text

    def test_unknown_api_paths_stay_404_rather_than_returning_html(self, built_client):
        response = built_client.get("/api/nope")

        assert response.status_code == 404
        assert "Microguard" not in response.text

    def test_the_api_still_answers_when_the_spa_is_mounted(self, built_client):
        assert built_client.get("/api/health").status_code == 200

    def test_a_missing_build_leaves_the_api_working(self, tmp_path):
        from microguard.dashboard.app import create_app

        client = TestClient(create_app(static_dir=str(tmp_path / "not-built")))

        assert client.get("/api/health").status_code == 200
        assert client.get("/").status_code == 404


class TestSharedSecret:
    """`--token` for the case where loopback binding is not an option."""

    @pytest.fixture
    def guarded(self):
        from microguard.dashboard.app import create_app

        return TestClient(create_app(token="s3cret"))

    def test_requests_without_the_token_are_refused(self, guarded):
        assert guarded.get("/api/health").status_code == 401

    def test_the_token_lets_a_request_through(self, guarded):
        response = guarded.get("/api/health", headers={"X-Microguard-Token": "s3cret"})

        assert response.status_code == 200

    def test_a_wrong_token_is_refused(self, guarded):
        response = guarded.get("/api/health", headers={"X-Microguard-Token": "guess"})

        assert response.status_code == 401

    def test_every_api_route_is_covered_not_just_health(self, guarded):
        assert guarded.get("/api/live/stats").status_code == 401

    def test_no_token_configured_means_no_gate(self, client):
        assert client.get("/api/health").status_code == 200


class TestApiPathGuard:
    """The SPA fallback must not swallow /api 404s.

    StaticFiles hands its handler an os.sep-normalized filesystem path, so a
    guard reading that argument sees "api\\nope" on Windows and misses. The
    decision has to come from the request path.
    """

    def test_recognizes_an_api_request(self):
        from microguard.dashboard.app import _is_api_path

        assert _is_api_path({"path": "/api/live/stats"}) is True

    def test_does_not_treat_a_client_route_as_api(self):
        from microguard.dashboard.app import _is_api_path

        assert _is_api_path({"path": "/live"}) is False

    def test_does_not_match_a_path_that_merely_contains_api(self):
        from microguard.dashboard.app import _is_api_path

        assert _is_api_path({"path": "/rapid/thing"}) is False

    def test_tolerates_a_scope_without_a_path(self):
        from microguard.dashboard.app import _is_api_path

        assert _is_api_path({}) is False


class TestDegradedStates:
    """What the API does when the things it reads are missing."""

    def test_the_model_endpoint_reports_503_without_a_trained_model(self, monkeypatch):
        from microguard.dashboard import api_model
        from microguard.dashboard.app import create_app

        monkeypatch.setattr(api_model.os.path, "exists", lambda _p: False)
        client = TestClient(create_app())

        response = client.get("/api/model")

        assert response.status_code == 503
        assert "No trained model" in response.json()["detail"]

    def test_evaluation_reports_503_without_a_trained_model(self, monkeypatch):
        from microguard.dashboard import api_model
        from microguard.dashboard.app import create_app

        api_model._detector.cache_clear()
        api_model._scores.cache_clear()
        monkeypatch.setattr(api_model.os.path, "exists", lambda _p: False)
        client = TestClient(create_app())

        response = client.post("/api/model/evaluate",
                               json={"dataset": "holdout", "threshold": 0.5})

        assert response.status_code == 503
        api_model._detector.cache_clear()
        api_model._scores.cache_clear()

    def test_samples_are_empty_when_the_data_directory_is_absent(self, monkeypatch):
        from microguard.dashboard import api_scan
        from microguard.dashboard.app import create_app

        monkeypatch.setattr(api_scan, "DATA_DIR", "/nonexistent/data")
        client = TestClient(create_app())

        assert client.get("/api/scan/samples").json() == {"samples": []}


class TestPathResolution:
    def test_the_directory_itself_is_not_a_valid_target(self, tmp_path):
        from microguard.dashboard.paths import resolve_within

        assert resolve_within(str(tmp_path), ".") is None

    def test_a_file_inside_resolves(self, tmp_path):
        from microguard.dashboard.paths import resolve_within

        (tmp_path / "a.log").write_text("x", encoding='utf-8')

        assert resolve_within(str(tmp_path), "a.log") is not None


class TestSpaFallbackEdges:
    def test_a_missing_index_does_not_mask_a_real_404(self, tmp_path):
        """With no index.html there is nothing to fall back to, so the
        StaticFiles 404 must surface unchanged."""
        from microguard.dashboard.app import create_app

        (tmp_path / "app.js").write_text("console.log(1)", encoding='utf-8')
        client = TestClient(create_app(static_dir=str(tmp_path)))

        assert client.get("/some/route").status_code == 404


class TestDashboardServer:
    """run_dashboard's banner and wiring, with uvicorn stubbed out."""

    def test_reports_its_configuration(self, monkeypatch, capsys):
        import uvicorn

        from microguard.dashboard import server

        started = {}
        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: started.update(kw))

        server.run_dashboard(port=8599, redis_url="redis://127.0.0.1:6390")

        output = capsys.readouterr().out
        assert "8599" in output
        assert "redis://127.0.0.1:6390" in output
        assert started["port"] == 8599

    def test_warns_when_bound_off_loopback_without_a_token(self, monkeypatch, capsys):
        import uvicorn

        from microguard.dashboard import server

        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)

        server.run_dashboard(host="0.0.0.0", redis_url="redis://127.0.0.1:6390")

        assert "WARNING" in capsys.readouterr().out

    def test_a_token_silences_the_warning(self, monkeypatch, capsys):
        import uvicorn

        from microguard.dashboard import server

        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)

        server.run_dashboard(host="0.0.0.0", token="s3cret",
                             redis_url="redis://127.0.0.1:6390")

        output = capsys.readouterr().out
        assert "api token: required" in output
        assert "WARNING" not in output

    def test_says_when_the_ui_has_not_been_built(self, monkeypatch, capsys):
        import uvicorn

        from microguard.dashboard import server

        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
        monkeypatch.setattr(server, "STATIC_DIR", "/nonexistent/static")

        server.run_dashboard(redis_url="redis://127.0.0.1:6390")

        assert "NOT BUILT" in capsys.readouterr().out


class TestWithoutTheLiveExtra:
    def test_a_missing_redis_package_degrades_to_an_in_process_recorder(
        self, monkeypatch, caplog
    ):
        """microguard/live/__init__.py raises ImportError without redis-py, so
        the dashboard must survive a base install and say what it lost."""
        import builtins
        import logging

        from microguard.dashboard.app import create_app
        from microguard.events import InMemoryDecisionRecorder

        real_import = builtins.__import__

        def no_redis(name, *args, **kwargs):
            if name == 'redis' or name.startswith('microguard.live'):
                raise ImportError("No module named 'redis'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_redis)

        with caplog.at_level(logging.WARNING):
            app = create_app(redis_url="redis://localhost:6379")

        assert isinstance(app.state.recorder, InMemoryDecisionRecorder)
        assert "redis is not installed" in caplog.text


class TestSignalHealth:
    """The signal panel reports a refresher nobody started.

    Every threat-intel signal degrades to silently absent when the slow tier
    is not running, and a silently absent signal looks exactly like a clean
    actor. This is the only place that difference is visible.
    """

    def test_no_redis_reports_not_running(self):
        from microguard.dashboard.api_health import _signal_health

        assert _signal_health(None) == {
            "running": False, "reason": "no redis", "sources": [],
        }

    def test_a_redis_that_raises_reports_unreachable(self):
        from microguard.dashboard.api_health import _signal_health

        class Broken:
            def get(self, key):
                raise RuntimeError("connection reset")

        assert _signal_health(Broken())["reason"] == "redis unreachable"

    def test_a_redis_with_no_heartbeat_reports_never_ran(self):
        from microguard.dashboard.api_health import _signal_health

        class Empty:
            def get(self, key):
                return None

        assert _signal_health(Empty())["reason"] == "never ran"

    def test_a_recorded_pass_reports_its_age_and_sources(self):
        import json
        import time as _time

        from microguard.dashboard.api_health import _signal_health

        class Beating:
            def get(self, key):
                return json.dumps({
                    "ts": _time.time() - 30,
                    "resolved": 4,
                    "sources": [{"name": "tor", "ok": True, "entries": 2}],
                })

        health = _signal_health(Beating())
        assert health["running"] is True
        assert health["resolved"] == 4
        assert 29 <= health["age_seconds"] <= 40
        assert health["sources"][0]["name"] == "tor"


class TestSignalPromotionEndpoint:
    """Promotion is the moment a signal stops being a measurement.

    Without a way to set it, decision 10A's observe-only posture is permanent
    and every signal built in M1 and M2 can never decide anything.
    """

    def test_reading_reports_the_known_sources(self, client):
        body = client.get("/api/live/config").json()
        assert set(body["known_signals"]) == {"tor", "abuseipdb", "fingerprint"}
        assert body["promoted_signals"] == []

    def test_hosting_is_not_offered_because_no_rule_reads_it(self, client):
        """It is resolved and recorded, but nothing enforces it. Offering it
        would give an operator an 'enforced' badge and zero enforcement."""
        assert "hosting" not in client.get("/api/live/config").json()["known_signals"]

    def test_writing_is_refused_without_the_flag(self, client):
        response = client.put(
            "/api/live/config", json={"block_threshold": 0.9, "promoted_signals": ["tor"]}
        )
        assert response.status_code == 403

    def test_an_unknown_source_is_rejected_with_the_known_list(self, writable_client):
        """A typo must fail loudly. Accepting 'torr' silently would leave the
        operator believing a signal is enforced while it quietly is not."""
        response = writable_client.put(
            "/api/live/config", json={"block_threshold": 0.9, "promoted_signals": ["torr"]}
        )
        assert response.status_code == 400
        assert "torr" in response.json()["detail"]

    def test_a_promotion_round_trips(self, writable_client):
        writable_client.put(
            "/api/live/config",
            json={"block_threshold": 0.9, "promoted_signals": ["tor", "fingerprint"]},
        )
        body = writable_client.get("/api/live/config").json()
        assert body["promoted_signals"] == ["fingerprint", "tor"]

    def test_an_empty_list_returns_everything_to_observe_only(self, writable_client):
        writable_client.put(
            "/api/live/config", json={"block_threshold": 0.9, "promoted_signals": ["tor"]}
        )
        writable_client.put(
            "/api/live/config", json={"block_threshold": 0.9, "promoted_signals": []}
        )
        assert writable_client.get("/api/live/config").json()["promoted_signals"] == []

    def test_omitting_the_field_leaves_promotion_alone(self, writable_client):
        """A threshold change must not silently un-promote a signal."""
        writable_client.put(
            "/api/live/config", json={"block_threshold": 0.9, "promoted_signals": ["tor"]}
        )
        writable_client.put("/api/live/config", json={"block_threshold": 0.7})

        assert writable_client.get("/api/live/config").json()["promoted_signals"] == ["tor"]


class TestFeedbackEndpoint:
    """Recording a correction is open by default; acting on it is not.

    Decision 8A. A recorded correction changes nothing until someone
    deliberately retrains, and the safety rails refuse thin or skewed data at
    that point. Gating the recording instead would mean the button is dark on
    a default install, and min_examples=50 makes thin collection equivalent to
    no feature at all.
    """

    @pytest.fixture()
    def feedback_client(self, tmp_path):
        from microguard.dashboard.app import create_app
        from microguard.events import InMemoryDecisionRecorder

        recorder = InMemoryDecisionRecorder()
        recorder.record({
            "id": "dec-1", "ip": "203.0.113.5", "label": "bot", "score": 0.9,
            "features": [0.5] * 19,
        })
        recorder.record({
            "id": "dec-no-features", "ip": "203.0.113.6", "label": "human",
            "score": 0.1, "features": None,
        })
        app = create_app(recorder=recorder, feedback_dir=str(tmp_path), deployment_id="prod")
        return TestClient(app), tmp_path

    def test_a_correction_is_recorded_without_any_flag(self, feedback_client):
        client, feedback_dir = feedback_client
        response = client.post("/api/live/feedback", json={"decision_id": "dec-1", "label": "human"})

        assert response.status_code == 200
        rows = (feedback_dir / "prod.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert json.loads(rows[0])["label"] == 0.0

    def test_a_bot_correction_records_the_other_label(self, feedback_client):
        client, feedback_dir = feedback_client
        client.post("/api/live/feedback", json={"decision_id": "dec-1", "label": "bot"})

        rows = (feedback_dir / "prod.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert json.loads(rows[0])["label"] == 1.0

    def test_clicking_twice_records_one_example(self, feedback_client):
        client, feedback_dir = feedback_client
        client.post("/api/live/feedback", json={"decision_id": "dec-1", "label": "human"})
        client.post("/api/live/feedback", json={"decision_id": "dec-1", "label": "human"})

        from microguard.training.online_update import load_corrections
        assert len(load_corrections("prod", feedback_dir)) == 1

    def test_an_unknown_decision_is_a_404(self, feedback_client):
        """The decision feed is capped at 1000. A row that scrolled out cannot
        be corrected, and saying so beats recording a correction against
        nothing."""
        client, _ = feedback_client
        response = client.post(
            "/api/live/feedback", json={"decision_id": "gone", "label": "human"}
        )
        assert response.status_code == 404

    def test_a_decision_with_no_features_cannot_be_corrected(self, feedback_client):
        """Fail-open rows carry no vector: nothing was scored, so there is
        nothing to train on. Training on a placeholder would be worse than
        refusing."""
        client, _ = feedback_client
        response = client.post(
            "/api/live/feedback", json={"decision_id": "dec-no-features", "label": "bot"}
        )
        assert response.status_code == 422
        assert "features" in response.json()["detail"].lower()

    def test_an_invalid_label_is_rejected(self, feedback_client):
        client, _ = feedback_client
        response = client.post(
            "/api/live/feedback", json={"decision_id": "dec-1", "label": "maybe"}
        )
        assert response.status_code == 422

    def test_feedback_is_unavailable_without_a_deployment_id(self, tmp_path):
        """Corrections are per-deployment by definition. Without an id there
        is nothing to attribute them to."""
        from microguard.dashboard.app import create_app
        from microguard.events import InMemoryDecisionRecorder

        client = TestClient(create_app(recorder=InMemoryDecisionRecorder()))
        response = client.post(
            "/api/live/feedback", json={"decision_id": "dec-1", "label": "human"}
        )
        assert response.status_code == 503
        assert "--deployment-id" in response.json()["detail"]

    def test_a_write_failure_is_reported_rather_than_swallowed(self, tmp_path, monkeypatch):
        """An operator who clicked and saw nothing happen would click again,
        and the correction would still be lost."""
        from microguard.dashboard.app import create_app
        from microguard.events import InMemoryDecisionRecorder

        recorder = InMemoryDecisionRecorder()
        recorder.record({"id": "dec-1", "ip": "1.1.1.1", "label": "bot",
                         "score": 0.9, "features": [0.5] * 19})

        def boom(**kwargs):
            raise OSError("disk full")

        monkeypatch.setattr("microguard.dashboard.api_live.record_correction", boom)
        client = TestClient(create_app(
            recorder=recorder, feedback_dir=str(tmp_path), deployment_id="prod"
        ))

        response = client.post(
            "/api/live/feedback", json={"decision_id": "dec-1", "label": "human"}
        )
        assert response.status_code == 500
        assert "disk full" in response.json()["detail"]


class TestFeatureVectorsStayServerSide:
    """The browser never needs the stored vector, and it is a third of the row.

    The feedback endpoint reads the features from the same record server-side,
    so nothing is lost by keeping a per-session behavioural vector off the
    wire.
    """

    @pytest.fixture()
    def recorded(self):
        from microguard.dashboard.app import create_app
        from microguard.events import InMemoryDecisionRecorder

        recorder = InMemoryDecisionRecorder()
        recorder.record({"id": "dec-1", "ip": "1.1.1.1", "label": "bot",
                         "score": 0.9, "features": [0.5] * 19})
        return TestClient(create_app(recorder=recorder))

    def test_events_carry_the_id_but_not_the_features(self, recorded):
        event = recorded.get("/api/live/events").json()["events"][0]

        assert event["id"] == "dec-1"
        assert "features" not in event

    def test_the_stream_strips_them_too(self, recorded):
        from microguard.dashboard.api_live import _without_features

        assert "features" not in _without_features({"id": "x", "features": [1.0]})
        assert _without_features({"id": "x", "features": [1.0]})["id"] == "x"

