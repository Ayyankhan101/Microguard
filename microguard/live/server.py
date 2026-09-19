"""nginx auth_request microservice — standalone HTTP server.

Handles /check requests from nginx auth_request module.
Returns 200 (allow) or 403 (block) based on live scoring.

nginx config example:
    location /api/ {
        auth_request /_microguard_check;
        auth_request_set $microguard_label $upstream_http_x_microguard_label;
        proxy_set_header X-Microguard-Label $microguard_label;
        proxy_pass http://backend;
    }

    location = /_microguard_check {
        internal;
        proxy_pass http://127.0.0.1:8400/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header User-Agent $http_user_agent;
        # Drop any client-supplied X-Forwarded-For. Microguard keys sessions
        # on this IP, so a spoofable value means a bot gets a fresh session
        # per request and never accumulates a detectable history.
        proxy_set_header X-Forwarded-For "";
    }
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

import redis

from ..collect import DecisionCollector
from ..parser import LogEntry
from .fp_routes import (
    FP_PATHS,
    MAX_FP_BODY_BYTES,
    SCRIPT_PATHS,
    fingerprint_script,
    handle_fp_post,
)
from .redis_events import RedisDecisionRecorder
from .redis_store import RedisSessionStateStore
from .runtime_config import RedisRuntimeConfig
from .scorer import BLOCK_THRESHOLD_DEFAULT, LiveScorer, fail_open_result

logger = logging.getLogger(__name__)


class CheckHandler(BaseHTTPRequestHandler):
    """Handle /check requests from nginx auth_request."""

    scorer: LiveScorer
    # Set alongside the scorer. The fingerprint routes write actor state
    # directly rather than through the session store, which only records
    # requests.
    redis_client: redis.Redis | None = None
    # X-Forwarded-For is client-supplied. Only honor it when the operator
    # confirms a trusted proxy rewrites it (see --trust-forwarded-for).
    trust_forwarded_for: bool = False

    def do_POST(self):
        """The only writable route, and the only public one that takes a body.

        Answers 200 whatever happens -- see fp_routes for why a public,
        unauthenticated, non-critical route must not report its own failures.
        """
        if self.path.split("?")[0] not in FP_PATHS:
            self._send_not_here()
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        # Read at most the cap, never the declared length. A client that
        # announces a large body gets its announcement ignored rather than
        # this process allocating for it.
        body = self.rfile.read(min(max(length, 0), MAX_FP_BODY_BYTES + 1))

        status, payload = handle_fp_post(self.redis_client, self._get_client_ip(), body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in SCRIPT_PATHS:
            self._send_script()
            return
        if path != "/check":
            self._send_not_here()
            return

        # Extract client IP from X-Real-IP or X-Forwarded-For
        ip = self._get_client_ip()
        ua = self.headers.get("User-Agent", "")
        method = self.headers.get("X-Original-Method", "GET")
        url = self.headers.get("X-Original-URI", "/")
        referer = self.headers.get("Referer", "")

        entry = LogEntry(
            ip=ip,
            timestamp=datetime.now(timezone.utc),
            method=method,
            url=url,
            status=0,
            size=0,
            referer=referer,
            user_agent=ua,
        )

        try:
            result = self.scorer.score_request(entry)
        except Exception:
            # Fail open. nginx auth_request turns any non-2xx/401/403 into a
            # 500 for the visitor, so a Redis blip here would take the whole
            # site down. An unscored request beats an outage.
            logger.exception("scoring failed, allowing request")
            failed = fail_open_result(ip)
            self.send_response(200)
            self._send_score_headers(failed)
            self.end_headers()
            self.wfile.write(json.dumps(failed).encode())
            return

        self.send_response(403 if result["label"] == "bot" else 200)
        self._send_score_headers(result)
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def _send_script(self) -> None:
        """Serve the client probe.

        Cached rather than no-store: the script changes only on deploy, and a
        revalidation per page load on every visitor is real traffic through
        the process nginx is waiting on.
        """
        body, content_type = fingerprint_script()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def _send_not_here(self) -> None:
        """Answer any path other than /check with an explanation.

        The status stays exactly 404. nginx turns any auth_request response
        outside 2xx/401/403 into a 500 for the visitor, so a misconfigured
        proxy_pass pointing at the wrong path must keep producing that 500 —
        only the body a human reads changes.

        It changes because a bare stdlib 404 is a useless answer to someone who
        opened this in a browser expecting the dashboard. This server knows
        exactly what they did wrong and can say so.
        """
        # The real bound address, not a constant: a hardcoded port hands the
        # reader a command that fails whenever this is not on 8400.
        #
        # server_address is typed as a union because a socketserver can bind a
        # Unix socket, where it is a path string. run_server always binds
        # (host, port) over TCP, so narrowing to that is safe here.
        host, port = cast("tuple[str, int]", self.server.server_address)

        body = (
            "microguard check server\n"
            "\n"
            "This is the nginx auth_request endpoint, not the web UI.\n"
            "The only route here is /check, and it is meant to be called by\n"
            "nginx rather than opened in a browser.\n"
            "\n"
            "Public routes, if you have wired the nginx location for them:\n"
            "    GET  /fingerprint.js\n"
            "    POST /fp\n"
            "\n"
            "Looking for the dashboard?\n"
            "    microguard dashboard        # http://127.0.0.1:8500\n"
            "\n"
            "Want to exercise this endpoint directly?\n"
            f"    curl -s http://{host}:{port}/check \\\n"
            "      -H 'X-Real-IP: 203.0.113.9' \\\n"
            "      -H 'User-Agent: curl/8.0' \\\n"
            "      -H 'X-Original-URI: /wp-admin/setup-config.php'\n"
            "\n"
            "Wiring it up: docs/howto-deploy-behind-nginx.md\n"
        ).encode()

        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_score_headers(self, result: dict) -> None:
        """Emit the decision as headers so nginx can forward it upstream.

        nginx's auth_request_set can only read response headers, so anything
        the backend should know has to travel this way, not just in the body.
        """
        self.send_header("X-Microguard-Label", result["label"])
        self.send_header("X-Microguard-Score", str(result["score"]))
        self.send_header("X-Microguard-Model-Score", str(result["model_score"]))
        self.send_header("X-Microguard-Heuristic", result["heuristic_label"])
        self.send_header("X-Microguard-Reason", result["heuristic_reason"])
        self.send_header("Content-Type", "application/json")

    def _get_client_ip(self) -> str:
        """Resolve the client IP, preferring values only a proxy can set.

        X-Real-IP is set by nginx from $remote_addr and cannot be forged by
        the client. X-Forwarded-For can, so it is used only when the operator
        opts in via --trust-forwarded-for.
        """
        xri = self.headers.get("X-Real-IP", "")
        if xri:
            return xri.strip()
        if self.trust_forwarded_for:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, format, *args):
        """Suppress default logging — let the caller decide."""


def run_server(
    host: str = "127.0.0.1",
    port: int = 8400,
    redis_url: str = "redis://localhost:6379",
    block_threshold: float = BLOCK_THRESHOLD_DEFAULT,
    session_ttl: int = 1800,
    trust_forwarded_for: bool = False,
    deployment_id: str | None = None,
    collect_to: str | None = None,
):
    """Start the check server."""
    r = redis.Redis.from_url(redis_url, decode_responses=True)
    r.ping()
    store = RedisSessionStateStore(r, default_ttl=session_ttl)
    # Recording every decision is what gives `microguard dashboard` something
    # to show. It shares this Redis and cannot fail the request: LiveScorer
    # swallows recorder errors.
    recorder = RedisDecisionRecorder(r)
    # The flag is the default; an operator can move the live threshold from the
    # dashboard without a restart, which would otherwise drop every in-flight
    # session. No override set means the flag stands.
    config = RedisRuntimeConfig(r)
    # Off unless asked for. The archive is the only route to a real training
    # set -- the Redis event list is capped at 1000 and LTRIMmed -- but every
    # row carries a client IP, so writing one per request to disk is a
    # decision an operator makes on purpose.
    collector = DecisionCollector(collect_to) if collect_to else None
    scorer = LiveScorer(
        store,
        block_threshold=block_threshold,
        recorder=recorder,
        collector=collector,
        threshold_source=config.block_threshold,
        # Without this, decision 10A's observe-only posture is permanent:
        # every signal is measured and none can ever decide anything.
        promoted_source=config.promoted_signals,
        # None means the shipped baseline, always. A deployment model must
        # never be picked up by a process that did not ask for one.
        deployment_id=deployment_id,
    )

    CheckHandler.scorer = scorer
    CheckHandler.redis_client = r
    CheckHandler.trust_forwarded_for = trust_forwarded_for

    # Threaded, not the plain HTTPServer. The reason is the Redis round trip,
    # not the CPU: scoring is pure Python and GIL-bound, so threads buy little
    # there (measured on a local Redis: 728 -> 894 req/s, and median latency
    # actually rose). But Python releases the GIL during socket I/O, so waits
    # on Redis overlap under threads and serialize without them. With a 15ms
    # round trip, which is what a Redis on another host looks like, 24
    # concurrent checks took 0.61s serialized versus 0.11s threaded, and the
    # worst request went from 612ms to 106ms. nginx calls /check for every
    # request to the protected location, so that tail is a real visitor waiting.
    #
    # What the threads share is read-only or already thread-safe: CheckHandler's
    # `scorer` and `trust_forwarded_for` are set once here and never written
    # again; redis-py hands each thread its own connection from a pool and a
    # fresh pipeline object per call; and BotDetector.predict only reads the
    # model parameters (verified: 40 concurrent predicts, identical results,
    # parameters and grads untouched). Sessions are keyed per IP in Redis, where
    # the append is atomic.
    #
    # daemon_threads so a Ctrl-C is not held up by an in-flight request.
    server = ThreadingHTTPServer((host, port), CheckHandler)
    server.daemon_threads = True
    print(f"microguard check server listening on {host}:{port}")
    print(f"  redis: {redis_url}")
    print(f"  threshold: {block_threshold}")
    print(f"  session TTL: {session_ttl}s")
    # A missing model is not a startup failure, but it does mean every decision
    # below is heuristics-only. Say so where an operator will actually see it.
    print(f"  model: {'loaded' if scorer.model_loaded else 'NOT LOADED (heuristics only)'}")
    print(f"  trust X-Forwarded-For: {trust_forwarded_for}")
    print(f"  model in use: {scorer.active_model_path}")
    # Said up front, because this server looks dead when it is working: it
    # logs nothing per request and serves one machine-facing route.
    print("  web UI: not here - run 'microguard dashboard' (this serves nginx)")
    print("  public routes: GET /fingerprint.js, POST /fp (needs a non-internal")
    print("                 nginx location - see docs/howto-deploy-behind-nginx.md)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(description="Microguard live check server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8400)
    parser.add_argument("--redis-url", default="redis://localhost:6379")
    parser.add_argument("--block-threshold", type=float, default=BLOCK_THRESHOLD_DEFAULT)
    parser.add_argument("--session-ttl", type=int, default=1800)
    parser.add_argument("--deployment-id", default=None)
    parser.add_argument(
        "--trust-forwarded-for",
        action="store_true",
        help="Honor X-Forwarded-For. Only enable behind a proxy that overwrites it.",
    )
    args = parser.parse_args()
    run_server(
        host=args.host,
        port=args.port,
        redis_url=args.redis_url,
        block_threshold=args.block_threshold,
        session_ttl=args.session_ttl,
        trust_forwarded_for=args.trust_forwarded_for,
        deployment_id=args.deployment_id,
    )


if __name__ == "__main__":
    main()
