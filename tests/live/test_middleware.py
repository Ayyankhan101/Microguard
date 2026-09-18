"""Tests for ASGI + WSGI middleware.

In-memory store for unit tests. No Redis needed.
Integration tests with Redis are in test_server_integration.py.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from microguard.live.middleware import (
    MicroguardASGI,
    MicroguardWSGI,
    _decode_header,
    _extract_ip,
)
from microguard.live.scorer import LiveScorer
from microguard.parser import LogEntry

from .conftest import InMemoryStore


def _make_entry(ip="1.2.3.4", ua="Mozilla/5.0", url="/test", method="GET"):
    return LogEntry(
        ip=ip,
        timestamp=datetime.now(timezone.utc),
        method=method,
        url=url,
        status=0,
        size=0,
        referer="",
        user_agent=ua,
    )


@pytest.fixture()
def asgi_store():
    return InMemoryStore()


# --- ASGI tests ---


def _make_asgi_app(store):
    async def app(scope, receive, send):
        if scope["type"] == "http":
            body = b"OK"
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": body})
    return MicroguardASGI(app, redis_url="redis://unused", block_threshold=0.85)


class TestASGIMiddleware:
    def test_first_request_passes(self, asgi_store):
        from microguard.live.middleware import MicroguardASGI as MG

        middleware = MG.__new__(MG)
        middleware._store = asgi_store
        middleware._scorer = LiveScorer(asgi_store, block_threshold=0.85)

        async def inner_app(scope, receive, send):
            body = b"OK"
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": body})

        middleware.app = inner_app

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/test",
            "headers": [
                [b"x-real-ip", b"1.2.3.4"],
                [b"user-agent", b"Mozilla/5.0"],
            ],
        }
        sent = []
        async def mock_send(msg):
            sent.append(msg)

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            middleware(scope, MagicMock(), mock_send)
        )
        # First request should pass through — inner app sends 200
        starts = [m for m in sent if m.get("type") == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 200

    def test_bot_request_gets_403(self, asgi_store):
        from microguard.live.middleware import MicroguardASGI as MG

        middleware = MG.__new__(MG)
        middleware._store = asgi_store
        middleware._scorer = LiveScorer(asgi_store, block_threshold=0.85)
        middleware.app = MagicMock()

        # Build up a bot session
        for i in range(10):
            entry = _make_entry(ip="10.0.0.1", ua="python-requests/2.28", url=f"/wp-admin/{i}")
            asgi_store.record_request("10.0.0.1", "python-requests/2.28", entry)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/wp-admin/install.php",
            "headers": [
                [b"x-real-ip", b"10.0.0.1"],
                [b"user-agent", b"python-requests/2.28"],
            ],
        }
        sent = []
        async def mock_send(msg):
            sent.append(msg)

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            middleware(scope, MagicMock(), mock_send)
        )
        # Should get a 403 response start
        starts = [m for m in sent if m.get("type") == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 403


# --- WSGI tests ---


def _dummy_wsgi_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"OK"]


class TestWSGIMiddleware:
    def test_first_request_passes(self):
        store = InMemoryStore()
        middleware = MicroguardWSGI(_dummy_wsgi_app, redis_url="redis://unused", block_threshold=0.85)
        middleware._store = store  # type: ignore[attr-defined]
        middleware._scorer = LiveScorer(store, block_threshold=0.85)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/test",
            "HTTP_X_REAL_IP": "1.2.3.4",
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "REMOTE_ADDR": "127.0.0.1",
        }
        responses = []
        def start_response(status, headers):
            responses.append((status, headers))

        _result = middleware(environ, start_response)
        assert responses[0][0] == "200 OK"

    def test_bot_request_gets_403(self):
        store = InMemoryStore()
        middleware = MicroguardWSGI(_dummy_wsgi_app, redis_url="redis://unused", block_threshold=0.85)
        middleware._store = store  # type: ignore[attr-defined]
        middleware._scorer = LiveScorer(store, block_threshold=0.85)

        # Build up bot session through the real append path
        for i in range(10):
            store.record_request(
                "10.0.0.1",
                "curl/7.68",
                _make_entry(ip="10.0.0.1", ua="curl/7.68", url=f"/scan/{i}"),
            )

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/scan/10",
            "HTTP_USER_AGENT": "curl/7.68",
            "REMOTE_ADDR": "10.0.0.1",
        }
        responses = []
        def start_response(status, headers):
            responses.append((status, headers))

        result = middleware(environ, start_response)
        assert responses[0][0] == "403 Forbidden"
        body = json.loads(b"".join(result))
        assert body["label"] == "bot"

    def test_human_gets_200_with_headers(self):
        store = InMemoryStore()
        middleware = MicroguardWSGI(_dummy_wsgi_app, redis_url="redis://unused", block_threshold=0.85)
        middleware._store = store  # type: ignore[attr-defined]
        middleware._scorer = LiveScorer(store, block_threshold=0.85)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/page",
            "HTTP_USER_AGENT": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "REMOTE_ADDR": "1.2.3.4",
        }
        responses = []
        def start_response(status, headers):
            responses.append((status, headers))

        _result = middleware(environ, start_response)
        assert responses[0][0] == "200 OK"
        # Check that microguard headers were added to environ
        assert environ.get("HTTP_X_MICROGUARD_LABEL") == "human"

    def _run(self, environ, trust_forwarded_for=False):
        store = InMemoryStore()
        middleware = MicroguardWSGI(
            _dummy_wsgi_app,
            redis_url="redis://unused",
            block_threshold=0.85,
            trust_forwarded_for=trust_forwarded_for,
        )
        middleware._store = store  # type: ignore[attr-defined]
        middleware._scorer = LiveScorer(store, block_threshold=0.85)
        middleware(environ, lambda status, headers: None)
        return store

    def test_xff_ignored_by_default(self):
        """X-Forwarded-For is client-supplied; trusting it lets a bot rotate sessions."""
        store = self._run({
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/test",
            "HTTP_X_FORWARDED_FOR": "10.0.0.99, 10.0.0.100",
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "REMOTE_ADDR": "127.0.0.1",
        })
        assert store.peek("10.0.0.99") is None
        assert store.peek("127.0.0.1") is not None

    def test_xff_used_when_trusted(self):
        store = self._run({
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/test",
            "HTTP_X_FORWARDED_FOR": "10.0.0.99, 10.0.0.100",
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "REMOTE_ADDR": "127.0.0.1",
        }, trust_forwarded_for=True)
        assert store.peek("10.0.0.99") is not None

    def test_scoring_failure_fails_open(self):
        """A Redis outage must not 500 every request through the app."""
        store = InMemoryStore()
        middleware = MicroguardWSGI(
            _dummy_wsgi_app, redis_url="redis://unused", block_threshold=0.85
        )
        middleware._store = store  # type: ignore[attr-defined]
        middleware._scorer = MagicMock()
        middleware._scorer.score_request.side_effect = RuntimeError("redis down")

        responses = []
        middleware({
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/test",
            "REMOTE_ADDR": "127.0.0.1",
        }, lambda status, headers: responses.append((status, headers)))
        assert responses[0][0] == "200 OK"


# --- Constructor signature ---


class TestConstructorRejectsUnknownKwargs:
    """A mistyped knob must fail loudly, not fall back to the default threshold."""

    def test_asgi_rejects_unknown_kwarg(self):
        async def app(scope, receive, send):
            pass

        with pytest.raises(TypeError):
            MicroguardASGI(app, block_treshold=0.5)  # typo, must not be swallowed

    def test_wsgi_rejects_unknown_kwarg(self):
        with pytest.raises(TypeError):
            MicroguardWSGI(_dummy_wsgi_app, block_treshold=0.5)


class TestMiddlewareRecordsDecisions:
    """In-process deployments feed the dashboard too, not just `serve`."""

    def test_asgi_scorer_gets_a_redis_backed_recorder(self):
        from microguard.live.redis_events import RedisDecisionRecorder

        async def app(scope, receive, send):
            pass

        middleware = MicroguardASGI(app)

        assert isinstance(middleware._scorer._recorder, RedisDecisionRecorder)

    def test_wsgi_scorer_gets_a_redis_backed_recorder(self):
        from microguard.live.redis_events import RedisDecisionRecorder

        middleware = MicroguardWSGI(_dummy_wsgi_app)

        assert isinstance(middleware._scorer._recorder, RedisDecisionRecorder)


class TestMiddlewareRuntimeConfig:
    """A threshold set from the dashboard reaches an in-process deployment.

    Real Redis, because the point is that a value written by one process
    changes a decision made in another.
    """

    @pytest.fixture()
    def redis_url(self):
        redis = pytest.importorskip("redis")
        url = "redis://localhost:6379/15"
        try:
            client = redis.Redis.from_url(url, decode_responses=True)
            client.ping()
        except redis.ConnectionError:
            pytest.skip("Redis not available on localhost:6379")
        client.flushdb()
        yield url
        client.flushdb()

    def _set_override(self, redis_url, value):
        import redis as redis_module

        from microguard.live.runtime_config import RedisRuntimeConfig

        client = redis_module.Redis.from_url(redis_url, decode_responses=True)
        RedisRuntimeConfig(client).set_block_threshold(value)

    def test_wsgi_blocks_a_benign_request_once_the_threshold_is_dropped(self, redis_url):
        self._set_override(redis_url, 0.0)
        middleware = MicroguardWSGI(_dummy_wsgi_app, redis_url=redis_url)

        status = []
        middleware(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/test",
                "HTTP_X_REAL_IP": "9.9.9.9",
                "HTTP_USER_AGENT": "Mozilla/5.0",
            },
            lambda code, headers: status.append(code),
        )

        assert status[0].startswith("403")

    def test_wsgi_allows_the_same_request_with_no_override_set(self, redis_url):
        middleware = MicroguardWSGI(_dummy_wsgi_app, redis_url=redis_url)

        status = []
        middleware(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/test",
                "HTTP_X_REAL_IP": "9.9.9.8",
                "HTTP_USER_AGENT": "Mozilla/5.0",
            },
            lambda code, headers: status.append(code),
        )

        assert status[0].startswith("200")


# --- ASGI fail-open and scope handling ---


class TestASGIFailOpen:
    """The WSGI fail-open path was covered; the ASGI one was not.

    Fail-open is load-bearing: a Redis outage must allow traffic rather than
    500 every visitor. That property is worth pinning on both middlewares.
    """

    def _run(self, middleware, scope):
        sent = []

        async def send(message):
            sent.append(message)

        asyncio.get_event_loop().run_until_complete(
            middleware(scope, MagicMock(), send)
        )
        return sent

    def _http_scope(self):
        return {
            "type": "http",
            "method": "GET",
            "path": "/api/items",
            "headers": [[b"x-real-ip", b"1.2.3.4"], [b"user-agent", b"Mozilla/5.0"]],
        }

    def test_a_scoring_failure_lets_the_request_through(self, asgi_store, caplog):
        from microguard.live.middleware import MicroguardASGI as MG

        reached = []

        async def inner_app(scope, receive, send):
            reached.append(scope["path"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"OK"})

        class ExplodingScorer:
            def score_request(self, entry):
                raise RuntimeError("redis is down")

        middleware = MG.__new__(MG)
        middleware._store = asgi_store
        middleware._scorer = ExplodingScorer()
        middleware.app = inner_app

        with caplog.at_level(logging.ERROR):
            sent = self._run(middleware, self._http_scope())

        assert reached == ["/api/items"]
        assert sent[0]["status"] == 200
        assert "redis is down" in caplog.text

    def test_the_fail_open_verdict_is_forwarded_to_the_app(self, asgi_store):
        from microguard.live.middleware import MicroguardASGI as MG

        seen_headers = {}

        async def inner_app(scope, receive, send):
            seen_headers.update({k.decode(): v.decode() for k, v in scope["headers"]})
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"OK"})

        class ExplodingScorer:
            def score_request(self, entry):
                raise RuntimeError("boom")

        middleware = MG.__new__(MG)
        middleware._store = asgi_store
        middleware._scorer = ExplodingScorer()
        middleware.app = inner_app

        self._run(middleware, self._http_scope())

        assert seen_headers["x-microguard-label"] == "human"
        assert seen_headers["x-microguard-reason"] == "scoring unavailable"

    def test_non_http_scopes_pass_straight_through_unscored(self, asgi_store):
        from microguard.live.middleware import MicroguardASGI as MG

        reached = []

        async def inner_app(scope, receive, send):
            reached.append(scope["type"])

        class NeverCalledScorer:
            def score_request(self, entry):
                raise AssertionError("a websocket scope must not be scored")

        middleware = MG.__new__(MG)
        middleware._store = asgi_store
        middleware._scorer = NeverCalledScorer()
        middleware.app = inner_app

        asyncio.get_event_loop().run_until_complete(
            middleware({"type": "websocket"}, MagicMock(), MagicMock())
        )

        assert reached == ["websocket"]


# --- The IP trust boundary ---


class TestExtractIP:
    """Sessions key on this value, so a forgeable one defeats detection.

    A bot that can set its own X-Forwarded-For gets a fresh session per
    request and never accumulates the history the rules need.
    """

    def test_x_real_ip_is_used(self):
        assert _extract_ip({b"x-real-ip": b"1.2.3.4"}) == "1.2.3.4"

    def test_x_forwarded_for_is_ignored_by_default(self):
        headers = {b"x-forwarded-for": b"9.9.9.9"}

        assert _extract_ip(headers, fallback="10.0.0.1") == "10.0.0.1"

    def test_x_forwarded_for_is_honored_when_trusted(self):
        headers = {b"x-forwarded-for": b"9.9.9.9"}

        assert _extract_ip(headers, trust_forwarded_for=True) == "9.9.9.9"

    def test_the_first_hop_wins_in_a_forwarded_chain(self):
        headers = {b"x-forwarded-for": b"9.9.9.9, 10.0.0.5, 172.16.0.1"}

        assert _extract_ip(headers, trust_forwarded_for=True) == "9.9.9.9"

    def test_x_real_ip_wins_over_a_trusted_forwarded_for(self):
        headers = {b"x-real-ip": b"1.2.3.4", b"x-forwarded-for": b"9.9.9.9"}

        assert _extract_ip(headers, trust_forwarded_for=True) == "1.2.3.4"

    def test_falls_back_to_the_transport_peer(self):
        assert _extract_ip({}, fallback="192.0.2.7") == "192.0.2.7"

    def test_last_resort_is_loopback_not_a_shared_constant(self):
        # A constant would collapse every unproxied client into one session.
        assert _extract_ip({}) == "127.0.0.1"

    def test_empty_forwarded_for_is_not_treated_as_an_address(self):
        assert _extract_ip({b"x-forwarded-for": b""}, trust_forwarded_for=True,
                           fallback="10.0.0.2") == "10.0.0.2"


class TestDecodeHeader:
    def test_decodes_bytes(self):
        assert _decode_header(b"Mozilla/5.0") == "Mozilla/5.0"

    def test_passes_through_str(self):
        assert _decode_header("Mozilla/5.0") == "Mozilla/5.0"

    def test_empty_becomes_empty_string(self):
        assert _decode_header(b"") == ""
        assert _decode_header(None) == ""

    def test_invalid_utf8_is_replaced_rather_than_raising(self):
        assert _decode_header(b"caf\xff") == "caf�"


class TestRefererReachesTheScorer:
    """Fix: the ASGI and WSGI middleware now pass the real Referer to the
    scorer. Before, both built the LogEntry with referer="", so referer-based
    rules were dead in the in-process deployment modes too."""

    def test_asgi_extracts_referer(self):
        from microguard.live.scorer import fail_open_result
        mw = MicroguardASGI.__new__(MicroguardASGI)
        mw._trust_xff = False
        mw._scorer = MagicMock()
        mw._scorer.score_request.return_value = fail_open_result()

        async def inner_app(scope, receive, send):
            pass

        mw.app = inner_app

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/catalog",
            "headers": [
                [b"x-real-ip", b"1.2.3.4"],
                [b"user-agent", b"Mozilla/5.0"],
                [b"referer", b"https://example.com/home"],
            ],
        }

        async def mock_send(msg):
            pass

        asyncio.new_event_loop().run_until_complete(
            mw(scope, MagicMock(), mock_send)
        )
        entry = mw._scorer.score_request.call_args[0][0]
        assert entry.referer == "https://example.com/home"

    def test_wsgi_extracts_referer(self):
        from microguard.live.scorer import fail_open_result
        mw = MicroguardWSGI.__new__(MicroguardWSGI)
        mw._trust_xff = False
        mw._scorer = MagicMock()
        mw._scorer.score_request.return_value = fail_open_result()
        mw.app = MagicMock(return_value=[b"OK"])

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/catalog",
            "HTTP_X_REAL_IP": "1.2.3.4",
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "HTTP_REFERER": "https://example.com/home",
            "REMOTE_ADDR": "127.0.0.1",
        }
        mw(environ, lambda status, headers: None)
        entry = mw._scorer.score_request.call_args[0][0]
        assert entry.referer == "https://example.com/home"
