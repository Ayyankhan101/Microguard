"""Tests for microguard.cli — scan_logfile() and main() end-to-end.

Previously the largest, most-changed file in the package (scan_logfile,
main, all argument parsing, the heuristic/model score-blending logic) had
zero dedicated tests. These exist to catch exactly the kind of regression
that already happened once by hand this session: a heuristic fix that
correctly re-labels a session as human, but whose effect the score-blending
math silently discards.
"""

import json
import sys

import pytest

import microguard.cli as cli_module
from microguard.cli import DEFAULT_MODEL_PATH, scan_logfile
from microguard.collect import NUM_FEATURES, DecisionCollector


def _nginx_line(ip, ts, method, url, status, ua, referer="-"):
    return f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} 512 "{referer}" "{ua}"'


def _graphql_session_lines(ip="10.1.1.1"):
    """25 legitimate GraphQL calls: single endpoint, browser UA, spread timing.

    Regression fixture for the GraphQL false-positive fix — before the
    labeler exemption + score-blending symmetric cap, this scored 'bot'.
    """
    ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    lines = []
    base_day, base_hour = 24, 12
    for i in range(25):
        second = int(i * 2.3) % 60
        minute = base_hour * 60 + int(i * 2.3) // 60
        ts = f"{base_day}/Mar/2024:{minute // 60:02d}:{minute % 60:02d}:{second:02d} +0000"
        lines.append(_nginx_line(
            ip, ts, "POST", "/graphql", 200, ua, referer="https://app.example.com/"
        ))
    return lines


def _bot_session_lines(ip="10.9.9.9"):
    """A blatant bot session: known bot UA, single request — high-confidence."""
    return [_nginx_line(
        ip, "24/Mar/2024:12:00:00 +0000", "GET", "/api/data", 200, "python-requests/2.28.0"
    )]


def _webhook_session_lines(ip="10.3.3.3"):
    """8 Stripe webhook calls — automated, but not a threat."""
    lines = []
    for i in range(8):
        ts = f"24/Mar/2024:12:{i:02d}:00 +0000"
        lines.append(_nginx_line(
            ip, ts, "POST", "/webhooks/payments", 200,
            "Stripe/1.0 (+https://stripe.com/docs/webhooks)",
        ))
    return lines


class TestScanLogfileHappyPath:
    def test_returns_expected_shape(self, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        results = scan_logfile(path, model_path=DEFAULT_MODEL_PATH)
        assert results['total_sessions'] == 1
        assert 'bot_count' in results
        assert 'human_count' in results
        assert 'integration_count' in results
        assert 'sessions' in results
        assert isinstance(results['bot_rate'], float)

    def test_obvious_bot_ua_classified_as_bot(self, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        results = scan_logfile(path, model_path=DEFAULT_MODEL_PATH)
        assert results['bot_count'] == 1
        assert results['sessions'][0]['label'] == 'bot'


class TestScanLogfileErrorHandling:
    def test_missing_file_returns_error_not_traceback(self):
        results = scan_logfile("/nonexistent/path/does-not-exist.log")
        assert results.get('error')
        assert results['total_sessions'] == 0
        assert results['bot_rate'] == 0.0

    def test_empty_file_returns_error(self, nginx_log_file):
        path = nginx_log_file([])
        results = scan_logfile(path, model_path=DEFAULT_MODEL_PATH)
        assert results.get('error')


class TestAutomatedIntegrationExclusion:
    """Regression test for the webhook-allowlist fix — automated-integration
    sessions must not be counted as bot or human, and must not affect bot_rate."""

    def test_webhook_session_excluded_from_bot_and_human_counts(self, nginx_log_file):
        path = nginx_log_file(_webhook_session_lines())
        results = scan_logfile(path, model_path=DEFAULT_MODEL_PATH)
        assert results['bot_count'] == 0
        assert results['human_count'] == 0
        assert results['integration_count'] == 1
        assert results['bot_rate'] == 0.0
        assert results['sessions'][0]['label'] == 'automated-integration'

    def test_webhook_mixed_with_real_bot_does_not_dilute_bot_rate(self, nginx_log_file):
        lines = _webhook_session_lines(ip="10.3.3.3") + _bot_session_lines(ip="10.9.9.9")
        path = nginx_log_file(lines)
        results = scan_logfile(path, model_path=DEFAULT_MODEL_PATH)
        # 1 real bot session, 1 integration session — bot_rate should reflect
        # 1 bot out of 2 total sessions, not be diluted to look "safer" by
        # treating the integration session as human.
        assert results['bot_count'] == 1
        assert results['integration_count'] == 1
        assert results['bot_rate'] == pytest.approx(0.5)


class TestScoreBlendingSymmetry:
    """Regression tests for cli.py's heuristic<->model score blending.

    A heuristic 'bot' call floors the blended score up; a heuristic 'human'
    call must symmetrically cap it down. Before this fix (found and fixed
    by hand this session, previously untested), the GraphQL exemption
    changed the heuristic label but not the final classification, because
    nothing stopped the model's independent score from overriding it.
    """

    def test_graphql_session_classified_as_human(self, nginx_log_file):
        path = nginx_log_file(_graphql_session_lines())
        results = scan_logfile(path, model_path=DEFAULT_MODEL_PATH, threshold=0.5)
        session = results['sessions'][0]
        assert session['heuristic_label'] == 'human', (
            "heuristic layer regressed: single-endpoint API exemption not applied"
        )
        assert session['label'] == 'human', (
            "score-blending regressed: heuristic said human but final label "
            "flipped to bot — the symmetric cap is missing or broken"
        )

    def test_high_confidence_bot_heuristic_still_wins(self, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        results = scan_logfile(path, model_path=DEFAULT_MODEL_PATH, threshold=0.5)
        session = results['sessions'][0]
        assert session['heuristic_label'] == 'bot'
        assert session['label'] == 'bot'
        assert session['score'] >= session['heuristic_confidence']


class TestThreshold:
    def test_threshold_moves_the_boundary(self, nginx_log_file):
        path = nginx_log_file(_graphql_session_lines())
        low = scan_logfile(path, model_path=DEFAULT_MODEL_PATH, threshold=0.01)
        high = scan_logfile(path, model_path=DEFAULT_MODEL_PATH, threshold=0.99)
        # threshold=0.01: almost anything with nonzero score clears it.
        assert low['sessions'][0]['label'] == 'bot'
        # threshold=0.99: nothing but near-certainty clears it.
        assert high['sessions'][0]['label'] == 'human'


class TestMainCLI:
    """End-to-end tests via main(), monkeypatching sys.argv (argparse reads
    from it directly) — the standard dependency-free pattern, no CliRunner
    needed since this project uses argparse, not click."""

    def _run(self, monkeypatch, argv):
        monkeypatch.setattr(sys, 'argv', ['microguard'] + argv)
        with pytest.raises((SystemExit, KeyboardInterrupt)) as exc_info:
            cli_module.main()
        if isinstance(exc_info.value, SystemExit):
            return exc_info.value.code
        return 0

    def test_scan_exits_0_for_clean_traffic(self, monkeypatch, nginx_log_file, capsys):
        path = nginx_log_file(_graphql_session_lines())
        code = self._run(monkeypatch, ['scan', path, '--threshold', '0.99'])
        assert code == 0

    def test_scan_exits_1_for_high_bot_rate(self, monkeypatch, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        code = self._run(monkeypatch, ['scan', path, '--threshold', '0.01'])
        assert code == 1

    def test_scan_missing_file_exits_1_cleanly(self, monkeypatch, capsys):
        code = self._run(monkeypatch, ['scan', '/nonexistent/file.log'])
        assert code == 1
        assert 'not found' in capsys.readouterr().err.lower()

    def test_scan_output_file_writes_content(self, monkeypatch, nginx_log_file, tmp_path):
        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "report.json"
        self._run(monkeypatch, ['scan', path, '--output', 'json', '--output-file', str(out)])
        data = json.loads(out.read_text(encoding='utf-8'))
        assert data['total_sessions'] == 1

    def test_scan_bad_output_file_path_exits_cleanly_not_traceback(self, monkeypatch, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        code = self._run(monkeypatch, ['scan', path, '--output-file', '/nonexistent-dir/report.txt'])
        assert code == 1

    def test_scan_html_output_smoke(self, monkeypatch, nginx_log_file, tmp_path):
        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "report.html"
        self._run(monkeypatch, ['scan', path, '--output', 'html', '--output-file', str(out)])
        assert '<html' in out.read_text(encoding='utf-8').lower()

    def test_info_command_does_not_exit_and_prints_version(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, 'argv', ['microguard', 'info'])
        cli_module.main()  # no SystemExit — info falls through normally
        from microguard import __version__

        assert f'v{__version__}' in capsys.readouterr().out

    def test_bare_invocation_runs_sample_scan(self, monkeypatch, capsys):
        code = self._run(monkeypatch, [])
        assert code == 0
        assert 'sample scan' in capsys.readouterr().out.lower()

    def test_a_failing_mlflow_log_says_so(self, monkeypatch, nginx_log_file, capsys):
        """MLflow is ON by default and points at 'databricks'.

        Without credentials `init()` raises, and the scan used to swallow it
        and exit normally, so a run that recorded nothing looked identical to
        a run that recorded everything.
        """
        from microguard import tracking

        def boom(*args, **kwargs):
            raise RuntimeError("no credentials")

        monkeypatch.setattr(tracking, 'init', boom)
        path = nginx_log_file(_bot_session_lines())
        self._run(monkeypatch, ['scan', path])

        err = capsys.readouterr().err.lower()
        assert 'mlflow logging failed' in err
        assert 'no credentials' in err
        # Naming the URI is the point: "it failed" without "pointing where"
        # sends you looking in the wrong place.
        assert 'databricks' in err

    def test_a_failing_mlflow_log_does_not_change_the_exit_code(
        self, monkeypatch, nginx_log_file
    ):
        """Tracking is observability. It must never decide a scan's verdict."""
        from microguard import tracking

        def boom(*args, **kwargs):
            raise RuntimeError("no credentials")

        path = nginx_log_file(_graphql_session_lines())
        clean = self._run(monkeypatch, ['scan', path, '--threshold', '0.99', '--no-mlflow'])

        monkeypatch.setattr(tracking, 'init', boom)
        with_failure = self._run(monkeypatch, ['scan', path, '--threshold', '0.99'])

        assert with_failure == clean == 0

    def test_mlflow_not_being_installed_is_not_reported_as_a_failure(
        self, monkeypatch, nginx_log_file, capsys
    ):
        """Absent is not broken -- the dependency is genuinely optional."""
        from microguard import tracking

        def not_installed(*args, **kwargs):
            raise ImportError("No module named 'mlflow'")

        monkeypatch.setattr(tracking, 'init', not_installed)
        path = nginx_log_file(_bot_session_lines())
        self._run(monkeypatch, ['scan', path])

        assert 'mlflow logging failed' not in capsys.readouterr().err.lower()

    def test_probe_https_dispatches_to_http_probe(self, monkeypatch):
        calls = {}

        def fake_probe(url, **kwargs):
            calls['http'] = url
            return {
                'url': url, 'label': 'human', 'combined_score': 0.1,
                'heuristic_score': 0.1, 'heuristic_reason': 'ok', 'model_score': 0.0,
                'threshold': 0.7, 'timing': {}, 'status_code': 200, 'headers': {},
                'body_preview': '', 'probes': 1,
            }

        def fake_ws_probe(*args, **kwargs):
            calls['ws'] = True
            raise AssertionError("should not be called for an https:// URL")

        monkeypatch.setattr('microguard.scanner.probe_and_analyze', fake_probe)
        monkeypatch.setattr('microguard.scanner.probe_ws_and_analyze', fake_ws_probe)
        self._run(monkeypatch, ['probe', 'https://example.com'])

        assert calls.get('http') == 'https://example.com'
        assert 'ws' not in calls

    def test_probe_verbose_prints_the_feature_breakdown(self, monkeypatch, capsys):
        """`probe --verbose` crashed: cli.py called format_probe_report() with a
        verbose= kwarg it never accepted, while format_probe_verbose() sat
        unused beside it."""
        def fake_probe(url, **kwargs):
            return {
                'url': url, 'label': 'human', 'combined_score': 0.1,
                'heuristic_score': 0.1, 'heuristic_reason': 'ok', 'model_score': 0.0,
                'threshold': 0.7, 'timing': {'total': 0.1}, 'status_code': 200,
                'headers': {'Server': 'nginx'}, 'body_preview': '', 'probes': 1,
                'features': {'response_time': 0.1, 'header_count': 1},
            }

        monkeypatch.setattr('microguard.scanner.probe_and_analyze', fake_probe)
        code = self._run(monkeypatch, ['probe', 'https://example.com', '--verbose'])

        assert code == 0
        assert 'response_time' in capsys.readouterr().out

    def test_probe_wss_dispatches_to_ws_probe(self, monkeypatch):
        calls = {}

        def fake_probe(*args, **kwargs):
            calls['http'] = True
            raise AssertionError("should not be called for a wss:// URL")

        def fake_ws_probe(url, **kwargs):
            calls['ws'] = url
            return {
                'url': url, 'protocol': 'websocket', 'label': 'human',
                'combined_score': 0.1, 'heuristic_score': 0.1, 'heuristic_reason': 'ok',
                'model_score': 0.0, 'threshold': 0.7, 'probes': 1, 'connected': True,
                'handshake_ok': True, 'status_code': 101, 'headers': {}, 'timing': {},
                'error': None, 'features': {},
            }

        monkeypatch.setattr('microguard.scanner.probe_and_analyze', fake_probe)
        monkeypatch.setattr('microguard.scanner.probe_ws_and_analyze', fake_ws_probe)
        self._run(monkeypatch, ['probe', 'wss://example.com/socket'])

        assert calls.get('ws') == 'wss://example.com/socket'
        assert 'http' not in calls

    def test_watch_flag_dispatches_to_watch_logfile(self, monkeypatch, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        calls = {}

        def fake_watch(**kwargs):
            calls.update(kwargs)

        monkeypatch.setattr('microguard.watch.watch_logfile', fake_watch)
        code = self._run(monkeypatch, ['scan', path, '--watch'])

        assert code == 0
        assert calls.get('filepath') == path

    def test_serve_dispatches_to_run_server(self, monkeypatch):
        calls = {}

        def fake_run_server(**kwargs):
            calls.update(kwargs)
            raise KeyboardInterrupt()

        monkeypatch.setattr('microguard.live.server.run_server', fake_run_server)
        code = self._run(monkeypatch, ['serve'])
        assert code == 0
        assert 'host' in calls

    def test_serve_custom_port(self, monkeypatch):
        calls = {}

        def fake_run_server(**kwargs):
            calls.update(kwargs)
            raise KeyboardInterrupt()

        monkeypatch.setattr('microguard.live.server.run_server', fake_run_server)
        code = self._run(monkeypatch, ['serve', '--port', '9000'])
        assert code == 0
        assert calls['port'] == 9000

    def test_serve_custom_threshold(self, monkeypatch):
        calls = {}

        def fake_run_server(**kwargs):
            calls.update(kwargs)
            raise KeyboardInterrupt()

        monkeypatch.setattr('microguard.live.server.run_server', fake_run_server)
        code = self._run(monkeypatch, ['serve', '--block-threshold', '0.7'])
        assert code == 0
        assert calls['block_threshold'] == 0.7

    def test_serve_custom_session_ttl(self, monkeypatch):
        calls = {}

        def fake_run_server(**kwargs):
            calls.update(kwargs)
            raise KeyboardInterrupt()

        monkeypatch.setattr('microguard.live.server.run_server', fake_run_server)
        code = self._run(monkeypatch, ['serve', '--session-ttl', '600'])
        assert code == 0
        assert calls['session_ttl'] == 600


class TestBaseInstallImports:
    """`pip install microguard` with no extras must keep working.

    Spec AC#11. The live package raises ImportError without redis, so any
    module-level import of microguard.live from cli.py breaks `microguard scan`
    for every user who never asked for real-time mode. That is easy to do by
    accident when reaching for a shared constant, and impossible to notice
    locally with redis installed.
    """

    def test_cli_imports_without_redis(self):
        import subprocess
        import sys

        probe = (
            "import sys, builtins\n"
            "_real = builtins.__import__\n"
            "def blocked(name, *a, **k):\n"
            "    if name == 'redis' or name.startswith('redis.'):\n"
            "        raise ImportError('No module named redis')\n"
            "    return _real(name, *a, **k)\n"
            "builtins.__import__ = blocked\n"
            "import microguard.cli\n"
            "assert microguard.cli.BLOCK_THRESHOLD_DEFAULT\n"
            "print('ok')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            encoding='utf-8',
            check=False,  # the assertion below reports the failure with stderr
        )
        assert result.returncode == 0, (
            "microguard.cli must import without the live extra:\n" + result.stderr
        )

    def test_live_package_still_guards(self):
        """The flip side: importing live/ without redis must say what to install."""
        import subprocess
        import sys

        probe = (
            "import builtins\n"
            "_real = builtins.__import__\n"
            "def blocked(name, *a, **k):\n"
            "    if name == 'redis' or name.startswith('redis.'):\n"
            "        raise ImportError('No module named redis')\n"
            "    return _real(name, *a, **k)\n"
            "builtins.__import__ = blocked\n"
            "try:\n"
            "    import microguard.live\n"
            "except ImportError as e:\n"
            "    assert 'live' in str(e), e\n"
            "    print('ok')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            encoding='utf-8',
            check=False,  # the assertion below reports the failure with stderr
        )
        assert result.returncode == 0, result.stderr


class TestDashboardCommand:
    """`microguard dashboard` — the whole GUI is one command."""

    def _run(self, monkeypatch, argv):
        import sys

        from microguard.cli import main

        monkeypatch.setattr(sys, 'argv', ['microguard'] + argv)
        try:
            main()
        except SystemExit as exc:
            return exc.code
        return 0

    def test_dispatches_to_the_dashboard_server(self, monkeypatch):
        calls = {}

        def fake_run(**kwargs):
            calls.update(kwargs)

        monkeypatch.setattr('microguard.dashboard.server.run_dashboard', fake_run)
        code = self._run(monkeypatch, ['dashboard'])

        assert code == 0
        assert calls['host'] == '127.0.0.1'
        assert calls['port'] == 8500

    def test_passes_through_host_port_and_redis_url(self, monkeypatch):
        calls = {}

        monkeypatch.setattr(
            'microguard.dashboard.server.run_dashboard', lambda **kw: calls.update(kw)
        )
        self._run(
            monkeypatch,
            [
                'dashboard',
                '--host', '0.0.0.0',
                '--port', '9100',
                '--redis-url', 'redis://elsewhere:6380',
            ],
        )

        assert calls['host'] == '0.0.0.0'
        assert calls['port'] == 9100
        assert calls['redis_url'] == 'redis://elsewhere:6380'

    def test_config_writes_are_off_unless_asked_for(self, monkeypatch):
        calls = {}

        monkeypatch.setattr(
            'microguard.dashboard.server.run_dashboard', lambda **kw: calls.update(kw)
        )
        self._run(monkeypatch, ['dashboard'])

        assert calls['allow_config_writes'] is False

    def test_config_writes_can_be_enabled(self, monkeypatch):
        calls = {}

        monkeypatch.setattr(
            'microguard.dashboard.server.run_dashboard', lambda **kw: calls.update(kw)
        )
        self._run(monkeypatch, ['dashboard', '--allow-config-writes'])

        assert calls['allow_config_writes'] is True


class TestScanOutputDispatch:
    """Flag precedence: --watch > --verbose > --json-pretty > --output-file.

    Each earlier flag silently wins, which is worth pinning because it is
    surprising — `--verbose --output html` prints the verbose terminal dump.
    """

    def _run(self, monkeypatch, argv):
        import sys

        from microguard.cli import main

        monkeypatch.setattr(sys, 'argv', ['microguard'] + argv)
        try:
            main()
        except SystemExit as exc:
            return exc.code
        return 0

    def test_verbose_prints_the_feature_breakdown(self, monkeypatch, capsys, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())

        self._run(monkeypatch, ['scan', path, '--verbose'])

        assert 'Verbose' in capsys.readouterr().out

    def test_verbose_can_write_to_a_file(self, monkeypatch, tmp_path, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "verbose.txt"

        self._run(monkeypatch, ['scan', path, '--verbose', '--output-file', str(out)])

        assert out.exists()
        assert 'Verbose' in out.read_text(encoding='utf-8')

    def test_verbose_wins_over_output_format(self, monkeypatch, capsys, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())

        self._run(monkeypatch, ['scan', path, '--verbose', '--output', 'html'])

        assert '<!DOCTYPE html>' not in capsys.readouterr().out

    def test_json_pretty_prints_coloured_output(self, monkeypatch, capsys, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())

        self._run(monkeypatch, ['scan', path, '--json-pretty'])

        assert '\033[' in capsys.readouterr().out

    def test_output_file_writes_nginx_rules(self, monkeypatch, tmp_path, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "deny.conf"

        self._run(monkeypatch, ['scan', path, '--output', 'nginx', '--output-file', str(out)])

        assert 'deny ' in out.read_text(encoding='utf-8')

    def test_output_file_writes_a_cloudflare_rule(self, monkeypatch, tmp_path, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "rule.txt"

        self._run(monkeypatch, ['scan', path, '--output', 'cloudflare', '--output-file', str(out)])

        assert 'ip.src' in out.read_text(encoding='utf-8')

    def test_output_file_writes_html(self, monkeypatch, tmp_path, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "report.html"

        self._run(monkeypatch, ['scan', path, '--output', 'html', '--output-file', str(out)])

        assert '<!DOCTYPE html>' in out.read_text(encoding='utf-8')

    def test_output_file_writes_json(self, monkeypatch, tmp_path, nginx_log_file):
        import json as json_module

        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "report.json"

        self._run(monkeypatch, ['scan', path, '--output', 'json', '--output-file', str(out)])

        assert json_module.loads(out.read_text(encoding='utf-8'))['total_sessions'] >= 1

    def test_output_file_writes_the_terminal_report(self, monkeypatch, tmp_path, nginx_log_file):
        path = nginx_log_file(_bot_session_lines())
        out = tmp_path / "report.txt"

        self._run(monkeypatch, ['scan', path, '--output-file', str(out)])

        assert 'Microguard Bot Traffic Report' in out.read_text(encoding='utf-8')


class TestProbeOutputDispatch:
    def _run(self, monkeypatch, argv):
        import sys

        from microguard.cli import main

        monkeypatch.setattr(sys, 'argv', ['microguard'] + argv)
        try:
            main()
        except SystemExit as exc:
            return exc.code
        return 0

    def _fake_probe(self, url, **kwargs):
        return {
            'url': url, 'label': 'human', 'combined_score': 0.1,
            'heuristic_score': 0.1, 'heuristic_reason': 'ok', 'model_score': 0.0,
            'threshold': 0.7, 'timing': {'total': 0.1}, 'status_code': 200,
            'headers': {'Server': 'nginx'}, 'body_preview': '', 'probes': 1,
            'features': {'response_time': 0.1},
        }

    def _fake_ws_probe(self, url, **kwargs):
        result = self._fake_probe(url)
        result.update({'protocol': 'websocket', 'connected': True,
                       'handshake_ok': True, 'error': None})
        return result

    def test_probe_verbose_prints_the_feature_breakdown(self, monkeypatch, capsys):
        monkeypatch.setattr('microguard.scanner.probe_and_analyze', self._fake_probe)

        self._run(monkeypatch, ['probe', 'https://example.com', '--verbose'])

        assert 'response_time' in capsys.readouterr().out

    def test_probe_json_pretty(self, monkeypatch, capsys):
        monkeypatch.setattr('microguard.scanner.probe_and_analyze', self._fake_probe)

        self._run(monkeypatch, ['probe', 'https://example.com', '--json-pretty'])

        assert '\033[' in capsys.readouterr().out

    def test_probe_html_to_a_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr('microguard.scanner.probe_and_analyze', self._fake_probe)
        out = tmp_path / "probe.html"

        self._run(monkeypatch, ['probe', 'https://example.com',
                                '--output', 'html', '--output-file', str(out)])

        assert '<!DOCTYPE html>' in out.read_text(encoding='utf-8')

    def test_probe_json_output(self, monkeypatch, capsys):
        monkeypatch.setattr('microguard.scanner.probe_and_analyze', self._fake_probe)

        self._run(monkeypatch, ['probe', 'https://example.com', '--output', 'json'])

        assert '"url"' in capsys.readouterr().out

    def test_websocket_json_pretty(self, monkeypatch, capsys):
        monkeypatch.setattr('microguard.scanner.probe_ws_and_analyze', self._fake_ws_probe)

        self._run(monkeypatch, ['probe', 'wss://example.com/s', '--json-pretty'])

        assert '\033[' in capsys.readouterr().out

    def test_websocket_json_output(self, monkeypatch, capsys):
        monkeypatch.setattr('microguard.scanner.probe_ws_and_analyze', self._fake_ws_probe)

        self._run(monkeypatch, ['probe', 'wss://example.com/s', '--output', 'json'])

        assert '"url"' in capsys.readouterr().out

    def test_websocket_html_to_a_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr('microguard.scanner.probe_ws_and_analyze', self._fake_ws_probe)
        out = tmp_path / "ws.html"

        self._run(monkeypatch, ['probe', 'wss://example.com/s',
                                '--output', 'html', '--output-file', str(out)])

        assert '<!DOCTYPE html>' in out.read_text(encoding='utf-8')


class TestScanModelFallbacks:
    def test_a_corrupt_model_falls_back_to_heuristics(self, tmp_path, capsys, nginx_log_file):
        from microguard.cli import scan_logfile

        path = nginx_log_file(_bot_session_lines())
        bad_model = tmp_path / "model.json"
        bad_model.write_text('{"weights": [0.1]}', encoding='utf-8')

        results = scan_logfile(path, model_path=str(bad_model))

        assert results['model_used'] is False
        assert 'Could not load model' in capsys.readouterr().err

    def test_a_missing_model_scores_on_rules_alone(self, tmp_path, nginx_log_file):
        from microguard.cli import scan_logfile

        path = nginx_log_file(_bot_session_lines())

        results = scan_logfile(path, model_path=str(tmp_path / "absent.json"))

        assert results['model_used'] is False
        assert all(s['model_score'] == 0.0 for s in results['sessions'])


class TestProbeExitCodes:
    def _run(self, monkeypatch, argv):
        import sys

        from microguard.cli import main

        monkeypatch.setattr(sys, 'argv', ['microguard'] + argv)
        try:
            main()
        except SystemExit as exc:
            return exc.code
        return 0

    def test_a_bot_verdict_exits_one(self, monkeypatch):
        def fake_probe(url, **kwargs):
            return {
                'url': url, 'label': 'bot', 'combined_score': 0.9,
                'heuristic_score': 0.9, 'heuristic_reason': 'rate limited',
                'model_score': 0.0, 'threshold': 0.7, 'timing': {'total': 0.1},
                'status_code': 429, 'headers': {}, 'body_preview': '', 'probes': 1,
                'features': {},
            }

        monkeypatch.setattr('microguard.scanner.probe_and_analyze', fake_probe)

        assert self._run(monkeypatch, ['probe', 'https://example.com']) == 1


class TestBareInvocationFallback:
    def test_help_is_shown_when_the_sample_log_is_missing(self, monkeypatch, capsys):
        """The zero-argument path scans a bundled sample; without it, show help
        rather than a traceback."""
        import os
        import sys

        import microguard.cli as cli_module

        real_exists = os.path.exists
        monkeypatch.setattr(
            cli_module.os.path, 'exists',
            lambda p: False if p.endswith('sample_access.log') else real_exists(p),
        )
        monkeypatch.setattr(sys, 'argv', ['microguard'])

        try:
            cli_module.main()
        except SystemExit as exc:
            assert exc.code == 0

        assert 'usage:' in capsys.readouterr().out


class TestSignalCommands:
    """End-to-end coverage for `signals` and `explain` via main().

    Redis is injected rather than required: these assert the CLI wiring —
    argument parsing, dispatch, and the failure message an operator actually
    sees — not the Redis behavior, which tests/live/ covers against a real
    server.
    """

    def _run(self, monkeypatch, argv):
        monkeypatch.setattr(sys, "argv", ["microguard", *argv])
        return cli_module.main()

    def test_explain_reports_a_redis_it_cannot_reach(self, monkeypatch, capsys):
        """The common first failure. A traceback here tells an operator
        nothing; the URL it tried tells them everything."""
        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, ["explain", "1.2.3.4", "--redis-url", "redis://127.0.0.1:1"])

        assert exc.value.code == 1
        assert "cannot reach Redis" in capsys.readouterr().err

    def test_explain_prints_the_explanation(self, monkeypatch, capsys):
        calls = {}

        def fake_explain(client, ip, promoted=frozenset()):
            calls["ip"] = ip
            calls["promoted"] = promoted
            return "EXPLANATION BODY"

        monkeypatch.setattr("microguard.live.explain.explain_actor", fake_explain)
        monkeypatch.setattr(
            "redis.Redis.from_url", lambda *a, **k: type("C", (), {"ping": lambda s: True})()
        )

        self._run(monkeypatch, ["explain", "9.9.9.9", "--promote", "tor, abuseipdb"])

        assert calls["ip"] == "9.9.9.9"
        assert calls["promoted"] == frozenset({"tor", "abuseipdb"})
        assert "EXPLANATION BODY" in capsys.readouterr().out

    def test_signals_passes_its_flags_through(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            "microguard.live.signals_runner.main",
            lambda **kwargs: seen.update(kwargs),
        )

        self._run(monkeypatch, ["signals", "--interval", "45", "--session-ttl", "90"])

        assert seen == {
            "redis_url": "redis://localhost:6379",
            "interval": 45,
            "session_ttl": 90,
        }


class TestRetrainCommand:
    """`microguard retrain` end to end via main().

    Both safety rails are refusals, not crashes: an operator who ran a retrain
    needs to know it did not happen and what would change that, rather than
    reading a traceback.
    """

    def _run(self, monkeypatch, argv):
        monkeypatch.setattr(sys, "argv", ["microguard", *argv])
        return cli_module.main()

    def test_it_reports_success_and_the_rollback(self, monkeypatch, capsys, tmp_path):
        written = tmp_path / "prod_model.json"
        monkeypatch.setattr(
            "microguard.training.online_update.retrain_deployment_model",
            lambda **kwargs: written,
        )

        self._run(monkeypatch, ["retrain", "--deployment-id", "prod"])

        out = capsys.readouterr().out
        assert str(written) in out
        assert "baseline was not modified" in out
        assert "deleting that file" in out

    def test_too_few_corrections_exits_1_with_the_reason(self, monkeypatch, capsys):
        from microguard.training.online_update import InsufficientFeedbackError

        def refuse(**kwargs):
            raise InsufficientFeedbackError("has 3 correction(s), need at least 50")

        monkeypatch.setattr(
            "microguard.training.online_update.retrain_deployment_model", refuse
        )

        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, ["retrain", "--deployment-id", "prod"])

        assert exc.value.code == 1
        assert "need at least 50" in capsys.readouterr().err

    def test_a_skewed_set_exits_1_with_the_reason(self, monkeypatch, capsys):
        from microguard.training.online_update import ClassImbalanceError

        def refuse(**kwargs):
            raise ClassImbalanceError("corrections are 100% one class")

        monkeypatch.setattr(
            "microguard.training.online_update.retrain_deployment_model", refuse
        )

        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, ["retrain", "--deployment-id", "prod"])

        assert exc.value.code == 1
        assert "one class" in capsys.readouterr().err

    def test_the_flags_reach_the_trainer(self, monkeypatch, tmp_path):
        seen = {}
        monkeypatch.setattr(
            "microguard.training.online_update.retrain_deployment_model",
            lambda **kwargs: seen.update(kwargs) or tmp_path / "m.json",
        )

        self._run(monkeypatch, [
            "retrain", "--deployment-id", "prod",
            "--feedback-dir", str(tmp_path), "--min-examples", "7", "--epochs", "3",
        ])

        assert seen == {
            "deployment_id": "prod",
            "feedback_dir": str(tmp_path),
            "min_examples": 7,
            "epochs": 3,
        }


class TestScanModelSourceRegistry:
    """`scan --model-source registry` loads from the Databricks Registry.

    Every failure falls back to the local model and says so. A scan must not
    depend on a reachable tracking backend, and without credentials the
    Registry is unreachable by default (it resolves to "databricks").
    """

    def _run(self, monkeypatch, argv):
        monkeypatch.setattr(sys, 'argv', ['microguard'] + argv)
        with pytest.raises(SystemExit) as exc:
            cli_module.main()
        return exc.value.code

    def test_an_unreachable_registry_falls_back_and_says_so(
        self, monkeypatch, nginx_log_file, capsys
    ):
        from microguard import tracking

        def boom(*args, **kwargs):
            raise RuntimeError("no credentials")

        monkeypatch.setattr(tracking, 'load_model', boom)
        path = nginx_log_file(_bot_session_lines())

        self._run(monkeypatch, ['scan', path, '--model-source', 'registry', '--no-mlflow'])

        err = capsys.readouterr().err
        assert 'Registry load failed' in err
        assert 'no credentials' in err
        assert 'falling back to local model' in err

    def test_mlflow_missing_falls_back_and_says_so(
        self, monkeypatch, nginx_log_file, capsys
    ):
        from microguard import tracking

        def not_installed(*args, **kwargs):
            raise ImportError("No module named 'mlflow'")

        monkeypatch.setattr(tracking, 'load_model', not_installed)
        path = nginx_log_file(_bot_session_lines())

        self._run(monkeypatch, ['scan', path, '--model-source', 'registry', '--no-mlflow'])

        assert 'MLflow not installed' in capsys.readouterr().err

    def test_a_working_registry_is_used_for_scoring(
        self, monkeypatch, nginx_log_file, capsys
    ):
        import types

        from microguard import tracking
        from microguard.model import BotDetector

        detector = BotDetector(DEFAULT_MODEL_PATH)
        pyfunc = types.SimpleNamespace(
            _model_impl=types.SimpleNamespace(
                python_model=types.SimpleNamespace(detector=detector)
            )
        )
        monkeypatch.setattr(tracking, 'load_model', lambda *a, **k: pyfunc)
        path = nginx_log_file(_bot_session_lines())

        self._run(monkeypatch, ['scan', path, '--model-source', 'registry', '--no-mlflow'])

        err = capsys.readouterr().err
        assert 'Loading model from Databricks Registry' in err
        assert 'Loaded model from Databricks Registry' in err

    def test_mlflow_not_installed_during_scan_logging_stays_quiet(
        self, monkeypatch, nginx_log_file, capsys
    ):
        """Absent is not broken: the extra is optional, so nothing is logged."""
        from microguard import tracking

        def not_installed(*args, **kwargs):
            raise ImportError("No module named 'mlflow'")

        monkeypatch.setattr(tracking, 'init', not_installed)
        path = nginx_log_file(_bot_session_lines())

        self._run(monkeypatch, ['scan', path])

        assert 'MLflow logging failed' not in capsys.readouterr().err


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
