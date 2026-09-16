"""CLI entry point for microguard bot detection tool.

Usage:
    microguard scan <logfile> [--format terminal|json] [--threshold 0.7]
    microguard scan --help
"""

import argparse
import json
import os
import sys
from typing import Any

from . import __version__
from .features import FEATURE_NAMES, extract_features, group_into_sessions
from .labeler import label_session
from .model import DEFAULT_MODEL_PATH, BotDetector
from .parser import LogEntry, parse_file
from .report import print_report
from .scoring import BLOCK_THRESHOLD_DEFAULT, compute_combined_score

# Default threshold for bot classification
DEFAULT_THRESHOLD = 0.7



def _write_report(output_file: str, content: str) -> None:
    """Write report content to a file, exiting cleanly (not a traceback) on failure."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
    except OSError as e:
        print(f"❌ Error: could not write to {output_file}: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"📄 Report saved to {output_file}", file=sys.stderr)


def scan_logfile(
    filepath: str,
    fmt: str = 'auto',
    threshold: float = DEFAULT_THRESHOLD,
    model_path: str = DEFAULT_MODEL_PATH,
    timeout_minutes: int = 30,
) -> dict[str, Any]:
    """Scan a log file for bot traffic.
    
    Args:
        filepath: Path to the log file
        fmt: Log format ('auto', 'nginx', 'json')
        threshold: Bot score threshold (above this = bot)
        model_path: Path to pre-trained model, or '__registry__' for Databricks Registry
        timeout_minutes: Session timeout in minutes
    
    Returns:
        Dictionary with scan results
    """
    from collections import Counter
    
    # Parse log file
    print(f"📂 Parsing {filepath}...", file=sys.stderr)

    if not os.path.exists(filepath):
        return {
            'total_sessions': 0,
            'bot_count': 0,
            'human_count': 0,
            'bot_rate': 0.0,
            'sessions': [],
            'error': f'Log file not found: {filepath}',
        }

    entries: list[LogEntry] = list(parse_file(filepath, fmt))

    if not entries:
        return {
            'total_sessions': 0,
            'bot_count': 0,
            'human_count': 0,
            'bot_rate': 0.0,
            'sessions': [],
            'error': 'No valid log entries found',
        }
    
    print(f"📊 Found {len(entries)} log entries", file=sys.stderr)
    
    # Group into sessions
    sessions = group_into_sessions(entries, timeout_minutes)
    print(f"👥 Grouped into {len(sessions)} sessions", file=sys.stderr)
    
    # Load model (if available)
    model = None
    
    if model_path == '__registry__':
        # Load from Databricks Registry
        try:
            from .tracking import load_model as load_registry_model
            pyfunc = load_registry_model()
            model = pyfunc._model_impl.python_model.detector
            print("🧠 Loaded model from Databricks Registry", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — registry load is best-effort, falls back to heuristics
            print(f"⚠️  Registry load failed: {e}", file=sys.stderr)
            print("   Falling back to heuristic rules only", file=sys.stderr)
    else:
        model_available = os.path.exists(model_path)
        
        if model_available:
            try:
                model = BotDetector(model_path)
                print("🧠 Loaded pre-trained model", file=sys.stderr)
            except Exception as e:  # noqa: BLE001 — model load is best-effort, falls back to heuristics
                print(f"⚠️  Could not load model: {e}", file=sys.stderr)
                print("   Falling back to heuristic rules only", file=sys.stderr)
        else:
            print("📋 No pre-trained model found, using heuristic rules", file=sys.stderr)
    
    # Analyze each session
    session_results = []
    bot_count = 0
    human_count = 0
    integration_count = 0

    for session in sessions:
        # Extract features
        features = extract_features(session)

        # Get label from heuristic rules
        heuristic_label, heuristic_conf, heuristic_reason = label_session(session)

        # Recognized webhook/integration traffic is automated by definition
        # but not a security threat — don't run it through bot scoring at
        # all, and don't count it toward bot or human tallies.
        if heuristic_label == 'automated-integration':
            model_score = 0.0
            combined_score = 0.0
            label = 'automated-integration'
            integration_count += 1
        else:
            # Get model prediction (if available)
            if model is not None:
                model_score = model.predict(features)
            else:
                model_score = 0.0
            combined_score = compute_combined_score(heuristic_label, heuristic_conf, model_score)

            # Classify
            is_bot = combined_score >= threshold
            label = 'bot' if is_bot else 'human'

            if is_bot:
                bot_count += 1
            else:
                human_count += 1

        # Get top endpoint
        urls = [e.url.split('?')[0] for e in session.requests]
        top_endpoint = Counter(urls).most_common(1)[0][0] if urls else '?'
        
        session_results.append({
            'ip': session.ip,
            'score': combined_score,
            'model_score': model_score,
            'heuristic_label': heuristic_label,
            'heuristic_confidence': heuristic_conf,
            'heuristic_reason': heuristic_reason,
            'label': label,
            'request_count': session.request_count,
            'duration': session.duration,
            'top_endpoint': top_endpoint,
            'user_agent': session.user_agent[:100],
            'features': {name: val for name, val in zip(FEATURE_NAMES, features)},
        })
    
    total = len(sessions)
    bot_rate = bot_count / total if total > 0 else 0.0

    return {
        'total_sessions': total,
        'bot_count': bot_count,
        'human_count': human_count,
        'integration_count': integration_count,
        'bot_rate': bot_rate,
        'threshold': threshold,
        'model_used': model is not None,
        'sessions': session_results,
        'summary': {
            'total_entries': len(entries),
            'total_sessions': total,
            'bot_sessions': bot_count,
            'human_sessions': human_count,
            'integration_sessions': integration_count,
            'bot_rate': bot_rate,
        },
    }


def main():
    """CLI entry point."""
    if sys.platform == 'win32':  # pragma: no cover - exercised only on Windows
        # Windows consoles default stdout/stderr to the OS locale codepage
        # (commonly cp1252), which can't encode the emoji used throughout
        # terminal/report output — every `microguard scan` would crash on
        # its own default output. Force UTF-8 regardless of console codepage.
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')

    parser = argparse.ArgumentParser(
        prog='microguard',
        description='🔍 Microguard — Bot Traffic Audit Tool',
        epilog='Powered by micrograd. Detect malicious bot traffic in your API logs.',
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan a log file for bot traffic'
    )
    scan_parser.add_argument(
        'logfile',
        help='Path to the log file to analyze'
    )
    scan_parser.add_argument(
        '--format', '-f',
        choices=['auto', 'nginx', 'json'],
        default='auto',
        help='Log file format (default: auto-detect)'
    )
    scan_parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f'Bot score threshold (default: {DEFAULT_THRESHOLD})'
    )
    scan_parser.add_argument(
        '--model', '-m',
        default=DEFAULT_MODEL_PATH,
        help='Path to pre-trained model file'
    )
    scan_parser.add_argument(
        '--output', '-o',
        choices=['terminal', 'json', 'html', 'nginx', 'cloudflare'],
        default='terminal',
        help='Output format (default: terminal). nginx/cloudflare emit a '
             'deny-list/firewall-rule expression for DANGER-scored IPs.'
    )
    scan_parser.add_argument(
        '--output-file', '-O',
        default=None,
        help='Write report to file instead of stdout (useful for HTML output)'
    )
    scan_parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Session timeout in minutes (default: 30)'
    )
    scan_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed feature vectors and heuristic rule breakdown'
    )
    scan_parser.add_argument(
        '--json-pretty', '-j',
        action='store_true',
        help='Output colored JSON for terminal reading (human-friendly)'
    )
    scan_parser.add_argument(
        '--watch', '-w',
        action='store_true',
        help='Continuously monitor log file for new bot traffic (tails the file)'
    )
    scan_parser.add_argument(
        '--no-mlflow',
        action='store_true',
        help='Disable MLflow logging for this scan (enabled by default)'
    )
    scan_parser.add_argument(
        '--model-source',
        choices=['local', 'registry'],
        default='local',
        help='Load model from local file or Databricks Registry (default: local)'
    )
    
    # serve command — live check server for nginx auth_request
    serve_parser = subparsers.add_parser(
        'serve',
        help='Start live check server for nginx auth_request'
    )
    serve_parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Bind address (default: 127.0.0.1)'
    )
    serve_parser.add_argument(
        '--port',
        type=int,
        default=8400,
        help='Listen port (default: 8400)'
    )
    serve_parser.add_argument(
        '--redis-url',
        default='redis://localhost:6379',
        help='Redis connection URL (default: redis://localhost:6379)'
    )
    serve_parser.add_argument(
        '--block-threshold',
        type=float,
        default=BLOCK_THRESHOLD_DEFAULT,
        help='Score above which requests are blocked (default: 0.85)'
    )
    serve_parser.add_argument(
        '--session-ttl',
        type=int,
        default=1800,
        help='Session expiry in seconds (default: 1800)'
    )
    serve_parser.add_argument(
        '--deployment-id',
        default=None,
        help='Use this deployment\'s retrained model when one exists. Without '
             'it the shipped baseline is always used.'
    )
    serve_parser.add_argument(
        '--collect-to',
        default=None,
        help='Append every scored decision to this JSONL file, for building a '
             'training set. Off by default: the live event list in Redis is '
             'capped at 1000 and cannot be that source, but every row here '
             'carries a client IP, so this is opt-in.'
    )
    serve_parser.add_argument(
        '--trust-forwarded-for',
        action='store_true',
        help='Honor X-Forwarded-For for client IP. Only enable behind a proxy '
             'that overwrites it — the header is client-supplied, and a '
             'spoofable session key defeats detection.'
    )

    # retrain command — fine-tune on one deployment's own corrections
    retrain_parser = subparsers.add_parser(
        'retrain',
        help="Fine-tune the model on one deployment's confirmed corrections"
    )
    retrain_parser.add_argument(
        '--deployment-id',
        required=True,
        help='Which deployment to retrain. Corrections never mix across ids.'
    )
    retrain_parser.add_argument(
        '--feedback-dir',
        default=None,
        help='Where corrections live (default: a user data directory)'
    )
    retrain_parser.add_argument(
        '--min-examples',
        type=int,
        default=50,
        help='Refuse to train below this many corrections (default: 50)'
    )
    retrain_parser.add_argument(
        '--epochs',
        type=int,
        default=20,
        help='Fine-tuning epochs (default: 20 — this is adaptation, not training)'
    )

    # signals command — the slow tier, out of the request path
    signals_parser = subparsers.add_parser(
        'signals',
        help='Resolve threat-intel signals out of band (needs Redis)'
    )
    signals_parser.add_argument(
        '--redis-url',
        default='redis://localhost:6379',
        help='Redis connection URL (default: redis://localhost:6379)'
    )
    signals_parser.add_argument(
        '--interval',
        type=int,
        default=300,
        help='Seconds between refresh passes (default: 300)'
    )
    signals_parser.add_argument(
        '--session-ttl',
        type=int,
        default=1800,
        help='Expiry for each written signal record (default: 1800)'
    )

    # explain command — why one actor got the verdict it did
    explain_parser = subparsers.add_parser(
        'explain',
        help='Explain the current verdict for one IP (needs Redis)'
    )
    explain_parser.add_argument('ip', help='Client IP to explain')
    explain_parser.add_argument(
        '--redis-url',
        default='redis://localhost:6379',
        help='Redis connection URL (default: redis://localhost:6379)'
    )
    explain_parser.add_argument(
        '--promote',
        default='',
        help='Comma-separated signal sources to treat as enforced, e.g. '
             '"tor,abuseipdb". Default: none, so every signal reads as '
             'observe-only.'
    )

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
    evaluate_parser.add_argument(
        '--redact-ips', action='store_true',
        help='Mask IPs in the unlabeled-flagged table, for a report you commit'
    )

    # dashboard command — API + built SPA on one port
    dashboard_parser = subparsers.add_parser(
        'dashboard',
        help='Start the web dashboard (live traffic, scans, model)'
    )
    dashboard_parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Bind address (default: 127.0.0.1). The dashboard has no auth — '
             'binding off loopback exposes every decision, and with '
             '--allow-config-writes the blocking threshold itself.'
    )
    dashboard_parser.add_argument(
        '--port',
        type=int,
        default=8500,
        help='Listen port (default: 8500)'
    )
    dashboard_parser.add_argument(
        '--redis-url',
        default='redis://localhost:6379',
        help='Redis the live path writes to (default: redis://localhost:6379). '
             'Unreachable means the live tab is empty; scan and model still work.'
    )
    dashboard_parser.add_argument(
        '--token',
        default=None,
        help='Require this shared secret in an X-Microguard-Token header on every '
             '/api request. For when loopback binding is not an option.'
    )
    dashboard_parser.add_argument(
        '--allow-config-writes',
        action='store_true',
        help='Let the dashboard change the live block threshold. Off by default '
             'because it decides who gets blocked on a running site.'
    )

    dashboard_parser.add_argument(
        '--deployment-id',
        default=None,
        help='Enable the feedback control, recording corrections against this '
             'deployment. Without it corrections have nothing to attribute to.'
    )
    dashboard_parser.add_argument(
        '--feedback-dir',
        default=None,
        help='Where corrections are written (default: a user data directory)'
    )

    # probe command
    probe_parser = subparsers.add_parser(
        'probe',
        help="Fingerprint how automated/hardened a live URL looks (not visitor classification — use 'scan' for that)"
    )
    probe_parser.add_argument(
        'url',
        help='URL to probe — http(s):// or ws(s):// (e.g., https://example.com, wss://example.com/socket)'
    )
    probe_parser.add_argument(
        '--count', '-n',
        type=int,
        default=3,
        help='Number of probes to send (default: 3, more = better timing analysis)'
    )
    probe_parser.add_argument(
        '--delay', '-d',
        type=float,
        default=0.5,
        help='Delay between probes in seconds (default: 0.5)'
    )
    probe_parser.add_argument(
        '--method',
        choices=['GET', 'POST', 'HEAD', 'OPTIONS'],
        default='GET',
        help='HTTP method (default: GET)'
    )
    probe_parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f'Bot score threshold (default: {DEFAULT_THRESHOLD})'
    )
    probe_parser.add_argument(
        '--model', '-m',
        default=DEFAULT_MODEL_PATH,
        help='Path to pre-trained model file'
    )
    probe_parser.add_argument(
        '--output', '-o',
        choices=['terminal', 'json', 'html'],
        default='terminal',
        help='Output format (default: terminal)'
    )
    probe_parser.add_argument(
        '--output-file', '-O',
        default=None,
        help='Write report to file instead of stdout'
    )
    probe_parser.add_argument(
        '--timeout',
        type=float,
        default=10.0,
        help='Request timeout in seconds (default: 10)'
    )
    probe_parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    probe_parser.add_argument(
        '--user-agent',
        default=None,
        help='Custom User-Agent header (default: Chrome)'
    )
    probe_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed feature vectors and heuristic rule breakdown'
    )
    probe_parser.add_argument(
        '--json-pretty', '-j',
        action='store_true',
        help='Output colored JSON for terminal reading (human-friendly)'
    )
    
    # info command
    subparsers.add_parser(
        'info',
        help='Show information about microguard'
    )
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        # Watch mode: continuous monitoring
        if args.watch:
            from .watch import watch_logfile
            watch_logfile(
                filepath=args.logfile,
                fmt=args.format,
                threshold=args.threshold,
                model_path=args.model,
            )
            sys.exit(0)
        
        # Validate file exists
        if not os.path.exists(args.logfile):
            print(f"❌ Error: Log file not found: {args.logfile}", file=sys.stderr)
            sys.exit(1)
        
        # Determine model path based on source
        model_path = args.model
        if args.model_source == 'registry':
            try:
                from .tracking import load_model as load_registry_model
                load_registry_model()
                model_path = '__registry__'
                print("🧠 Loading model from Databricks Registry...", file=sys.stderr)
            except ImportError:
                print("⚠️  MLflow not installed — falling back to local model", file=sys.stderr)
            except Exception as e:  # noqa: BLE001 — registry load is best-effort, falls back to the local model
                print(f"⚠️  Registry load failed: {e} — falling back to local model", file=sys.stderr)
        
        # Run scan
        results = scan_logfile(
            filepath=args.logfile,
            fmt=args.format,
            threshold=args.threshold,
            model_path=model_path,
            timeout_minutes=args.timeout,
        )
        
        # Print report
        if args.verbose:
            from .report import format_verbose
            content = format_verbose(results)
            if args.output_file:
                _write_report(args.output_file, content)
            else:
                print(content)
        elif args.json_pretty:
            from .report import format_json_pretty
            print(format_json_pretty(results))
        elif args.output_file:
            from .report import (
                format_cloudflare_rule,
                format_html,
                format_json,
                format_nginx_denylist,
                format_terminal,
            )
            if args.output == 'html':
                content = format_html(results)
            elif args.output == 'json':
                content = format_json(results)
            elif args.output == 'nginx':
                content = format_nginx_denylist(results)
            elif args.output == 'cloudflare':
                content = format_cloudflare_rule(results)
            else:
                content = format_terminal(results)

            _write_report(args.output_file, content)
        else:
            print_report(results, fmt=args.output)
        
        # Log to MLflow (unless disabled)
        if not args.no_mlflow:
            try:
                from .tracking import init, log_metrics, start_run
                init()
                with start_run(run_name=f"scan-{os.path.basename(args.logfile)}"):
                    log_metrics({
                        "sessions": results['total_sessions'],
                        "bots": results['bot_count'],
                        "humans": results['human_count'],
                        "bot_rate": results['bot_rate'],
                    })
            except ImportError:
                pass  # MLflow is an optional extra — absent is not broken.
            except Exception as e:  # noqa: BLE001 — tracking never decides a scan's verdict
                # Loud, but not fatal. Without credentials init() raises and
                # the scan used to exit normally having recorded nothing, so a
                # run that tracked nothing looked exactly like one that did.
                # Name the URI: "it failed" without "pointing where" sends you
                # looking in the wrong place.
                from .tracking import resolved_tracking_uri
                print(
                    f"⚠️  MLflow logging failed (tracking URI: "
                    f"{resolved_tracking_uri()}): {e}",
                    file=sys.stderr,
                )
                print("   The scan itself is unaffected.", file=sys.stderr)
        
        # Exit code: 1 if bots detected above threshold
        if results['bot_rate'] > 0.1:
            sys.exit(1)
        else:
            sys.exit(0)
    
    elif args.command == 'probe':
        is_websocket = args.url.startswith(('ws://', 'wss://'))

        if is_websocket:
            from .scanner import (
                format_ws_probe_html,
                format_ws_probe_report,
                probe_ws_and_analyze,
            )

            # No model to load — the session-trained MLP has no valid
            # input for probe data of any kind (HTTP or WebSocket).
            results = probe_ws_and_analyze(
                url=args.url,
                count=args.count,
                delay=args.delay,
                threshold=args.threshold,
                verbose=True,
            )

            if args.json_pretty:
                from .report import format_json_pretty
                content = format_json_pretty(results)
            elif args.output == 'json':
                content = json.dumps(results, indent=2, default=str)
            elif args.output == 'html':
                content = format_ws_probe_html(results)
            else:
                content = format_ws_probe_report(results)

            if args.output_file:
                _write_report(args.output_file, content)
            else:
                print(content)

            sys.exit(1 if results['label'] == 'bot' else 0)

        from .scanner import format_probe_report, probe_and_analyze

        # Run probe analysis
        results = probe_and_analyze(
            url=args.url,
            count=args.count,
            delay=args.delay,
            threshold=args.threshold,
            verbose=True,
        )

        # Format and output
        if args.verbose:
            from .scanner import format_probe_verbose
            content = format_probe_verbose(results)
        elif args.json_pretty:
            from .report import format_json_pretty
            content = format_json_pretty(results)
        elif args.output == 'json':
            content = json.dumps(results, indent=2, default=str)
        elif args.output == 'html':
            from .scanner import format_probe_html
            content = format_probe_html(results)
        else:
            content = format_probe_report(results)

        if args.output_file:
            _write_report(args.output_file, content)
        else:
            print(content)

        # Exit code: 1 if bot detected
        if results['label'] == 'bot':
            sys.exit(1)
        else:
            sys.exit(0)
    
    elif args.command == 'serve':
        from .live.server import run_server
        run_server(
            host=args.host,
            port=args.port,
            redis_url=args.redis_url,
            block_threshold=args.block_threshold,
            session_ttl=args.session_ttl,
            trust_forwarded_for=args.trust_forwarded_for,
            deployment_id=args.deployment_id,
            collect_to=args.collect_to,
        )

    elif args.command == 'retrain':
        from .training.online_update import (
            ClassImbalanceError,
            InsufficientFeedbackError,
            retrain_deployment_model,
        )
        try:
            written = retrain_deployment_model(
                deployment_id=args.deployment_id,
                feedback_dir=args.feedback_dir,
                min_examples=args.min_examples,
                epochs=args.epochs,
            )
        except (InsufficientFeedbackError, ClassImbalanceError) as exc:
            # Both rails are refusals, not crashes. Say what happened and what
            # would change it, rather than printing a traceback at someone who
            # just wanted a better model.
            print(f"❌ Not retraining: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"✅ Retrained {args.deployment_id} -> {written}")
        print("   The shipped baseline was not modified.")
        print(f"   Restart is not needed: `microguard serve --deployment-id {args.deployment_id}`")
        print("   picks it up within a few seconds. Roll back by deleting that file.")

    elif args.command == 'signals':
        from .live.signals_runner import main as run_signals
        run_signals(
            redis_url=args.redis_url,
            interval=args.interval,
            session_ttl=args.session_ttl,
        )

    elif args.command == 'explain':
        import redis as _redis

        from .live.explain import explain_actor
        promoted = frozenset(p.strip() for p in args.promote.split(',') if p.strip())
        try:
            client = _redis.Redis.from_url(args.redis_url, decode_responses=True)
            client.ping()
        except _redis.RedisError as exc:
            print(f"❌ Error: cannot reach Redis at {args.redis_url}: {exc}", file=sys.stderr)
            sys.exit(1)
        print(explain_actor(client, args.ip, promoted=promoted))

    elif args.command == 'evaluate':
        from .evaluate import build_actors, render_report
        try:
            actors, skipped = build_actors(args.access_log, args.collected, args.invite_token)
        except OSError as e:
            print(f"❌ Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(render_report(actors, skipped_rows=skipped, redact_ips=args.redact_ips))

    elif args.command == 'dashboard':
        from .dashboard.server import run_dashboard
        run_dashboard(
            host=args.host,
            port=args.port,
            redis_url=args.redis_url,
            allow_config_writes=args.allow_config_writes,
            token=args.token,
            deployment_id=args.deployment_id,
            feedback_dir=args.feedback_dir,
        )

    elif args.command == 'info':
        print(f"🔍 Microguard v{__version__}")
        print("   Bot Traffic Audit Tool powered by micrograd")
        print()
        print("   Usage:")
        print("     microguard scan <logfile>    Scan a log file for bot traffic")
        print("     microguard probe <url>       Probe a live URL for bot signals")
        print("   Docs:  https://github.com/yourusername/microguard")
        print()
        print("   Features:")
        print("   • 19 HTTP-level features for bot detection")
        print("   • micrograd neural network (85 parameters, ~1.8KB)")
        print("   • Heuristic rules + ML model combined scoring")
        print("   • Live URL probing with timing analysis")
        print("   • Streaming log processing (handles large files)")
        print("   • HTML report output for sharing with your team")
        print("   • Zero external dependencies (beyond micrograd)")
    
    else:
        # T2: Auto-sample on first run — scan bundled sample log
        sample_path = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'sample_access.log'
        )
        if os.path.exists(sample_path):
            print("🔍 Microguard — Bot Traffic Audit Tool")
            print("   Powered by micrograd")
            print()
            print("   No command specified. Running sample scan...")
            print("   (Scan your own logs with: microguard scan <logfile>)")
            print()
            
            results = scan_logfile(
                filepath=sample_path,
                fmt='auto',
                threshold=DEFAULT_THRESHOLD,
                model_path=DEFAULT_MODEL_PATH,
            )
            print_report(results, fmt='terminal')
            
            print("\n─── What just happened? ───")
            print("   Microguard analyzed a sample log file for bot traffic.")
            print("   The model scored each session 0.0 (human) to 1.0 (bot).")
            print()
            print("   Next steps:")
            print("   • Scan your own logs:  microguard scan access.log")
            print("   • Probe a live URL:    microguard probe https://yourapi.com")
            print("   • See all options:     microguard --help")
            print()
        else:
            parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    main()
