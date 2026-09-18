"""ASGI + WSGI middleware for real-time bot detection.

Drop-in middleware for FastAPI/Starlette (ASGI) and Flask (WSGI).
Intercepts every request, scores it against live session state,
and blocks bots with 403 while passing humans through.

Usage (FastAPI):
    from microguard.live.middleware import MicroguardASGI
    app = FastAPI()
    app.add_middleware(MicroguardASGI, redis_url="redis://localhost:6379")

Usage (Flask):
    from microguard.live.middleware import MicroguardWSGI
    app = Flask(__name__)
    app.wsgi_app = MicroguardWSGI(app.wsgi_app, redis_url="redis://localhost:6379")
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

import redis

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

# --- ASGI Middleware (FastAPI / Starlette) ---


class MicroguardASGI:
    """ASGI middleware for real-time bot detection.

    Constructor args match `microguard serve` flags:
        redis_url, block_threshold, session_ttl, trust_forwarded_for
    """

    # Class-level default so instances built without __init__ still resolve it.
    _trust_xff: bool = False

    def __init__(
        self,
        app: Any,
        redis_url: str = "redis://localhost:6379",
        block_threshold: float = BLOCK_THRESHOLD_DEFAULT,
        session_ttl: int = 1800,
        trust_forwarded_for: bool = False,
    ):
        self.app = app
        self._trust_xff = trust_forwarded_for
        self._r = redis.Redis.from_url(redis_url, decode_responses=True)
        self._store = RedisSessionStateStore(self._r, default_ttl=session_ttl)
        _config = RedisRuntimeConfig(self._r)
        self._scorer = LiveScorer(
            self._store,
            block_threshold=block_threshold,
            session_ttl=session_ttl,
            # Same Redis, same keys as `microguard serve`, so an in-process
            # deployment shows up in `microguard dashboard` too — and honors a
            # threshold moved from it without a restart.
            recorder=RedisDecisionRecorder(self._r),
            threshold_source=_config.block_threshold,
            # Without this, decision 10A's observe-only posture is
            # permanent: every signal is measured and none can decide.
            promoted_source=_config.promoted_signals,
        )

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract request info from ASGI scope
        headers = dict(scope.get("headers", []))
        client = scope.get("client") or ()
        ip = _extract_ip(headers, self._trust_xff, client[0] if client else "")
        ua = _decode_header(headers.get(b"user-agent", b""))
        referer = _decode_header(headers.get(b"referer", b""))
        method = scope.get("method", "GET")
        path = scope.get("path", "/")

        # The two public fingerprint routes are answered here rather than
        # passed through. Without this, fingerprinting would exist only in the
        # `microguard serve` deployment mode, and the epic requires both modes
        # to carry the same capability.
        if path in SCRIPT_PATHS:
            await _asgi_send_script(send)
            return
        if path in FP_PATHS:
            await self._asgi_fingerprint(scope, receive, send)
            return

        entry = LogEntry(
            ip=ip,
            timestamp=datetime.now(timezone.utc),
            method=method,
            url=path,
            status=0,
            size=0,
            referer=referer,
            user_agent=ua,
        )

        try:
            result = self._scorer.score_request(entry)
        except Exception:
            # Fail open: a Redis outage must not 500 every request.
            logger.exception("scoring failed, allowing request")
            result = fail_open_result()

        if result["label"] == "bot":
            body = json.dumps(result).encode()
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    *_score_headers_asgi(result),
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                ],
            })
            await send({"type": "http.response.body", "body": body})
        else:
            # Replace, never append: a client can send its own
            # x-microguard-* headers, and header lookups return the first
            # match, so appending would let the client's value win.
            scope["headers"] = [
                (k, v)
                for k, v in scope.get("headers", [])
                if not k.lower().startswith(b"x-microguard-")
            ]
            scope["headers"].extend(
                (k, v) for k, v in _score_headers_asgi(result)
            )
            await self.app(scope, receive, send)


    async def _asgi_fingerprint(self, scope: dict, receive: Any, send: Any) -> None:
        body = b""
        while len(body) <= MAX_FP_BODY_BYTES:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        ip = _extract_ip(headers, self._trust_xff, _asgi_client(scope))
        # Off the event loop: handle_fp_post talks to Redis synchronously,
        # and /fp is the public route -- every page load fires one, so a
        # blocking call here serializes every concurrent request behind it.
        status, payload = await asyncio.to_thread(handle_fp_post, self._r, ip, body)
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(payload)).encode()],
            ],
        })
        await send({"type": "http.response.body", "body": payload})


def _asgi_client(scope: dict) -> str:
    client = scope.get("client")
    return client[0] if client else ""


async def _asgi_send_script(send: Any) -> None:
    body, content_type = fingerprint_script()
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [
            [b"content-type", content_type.encode()],
            [b"content-length", str(len(body)).encode()],
            [b"cache-control", b"public, max-age=3600"],
        ],
    })
    await send({"type": "http.response.body", "body": body})


# --- WSGI Middleware (Flask) ---


class MicroguardWSGI:
    """WSGI middleware for real-time bot detection.

    Constructor args match `microguard serve` flags:
        redis_url, block_threshold, session_ttl, trust_forwarded_for
    """

    # Class-level default so instances built without __init__ still resolve it.
    _trust_xff: bool = False

    def __init__(
        self,
        app: Any,
        redis_url: str = "redis://localhost:6379",
        block_threshold: float = BLOCK_THRESHOLD_DEFAULT,
        session_ttl: int = 1800,
        trust_forwarded_for: bool = False,
    ):
        self.app = app
        self._trust_xff = trust_forwarded_for
        self._r = redis.Redis.from_url(redis_url, decode_responses=True)
        self._store = RedisSessionStateStore(self._r, default_ttl=session_ttl)
        _config = RedisRuntimeConfig(self._r)
        self._scorer = LiveScorer(
            self._store,
            block_threshold=block_threshold,
            session_ttl=session_ttl,
            # Same Redis, same keys as `microguard serve`, so an in-process
            # deployment shows up in `microguard dashboard` too — and honors a
            # threshold moved from it without a restart.
            recorder=RedisDecisionRecorder(self._r),
            threshold_source=_config.block_threshold,
            # Without this, decision 10A's observe-only posture is
            # permanent: every signal is measured and none can decide.
            promoted_source=_config.promoted_signals,
        )

    def __call__(self, environ: dict, start_response: Any) -> Any:
        ip = environ.get("HTTP_X_REAL_IP", "").strip()
        if not ip and self._trust_xff:
            ip = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
        if not ip:
            ip = environ.get("REMOTE_ADDR", "")
        ua = environ.get("HTTP_USER_AGENT", "")
        referer = environ.get("HTTP_REFERER", "")
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")

        # Same reason as the ASGI side: both deployment modes carry the same
        # capability, or one of them is quietly second-class.
        if path in SCRIPT_PATHS:
            body, content_type = fingerprint_script()
            start_response("200 OK", [
                ("Content-Type", content_type),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "public, max-age=3600"),
            ])
            return [body]
        if path in FP_PATHS:
            return self._wsgi_fingerprint(environ, start_response)

        entry = LogEntry(
            ip=ip,
            timestamp=datetime.now(timezone.utc),
            method=method,
            url=path,
            status=0,
            size=0,
            referer=referer,
            user_agent=ua,
        )

        try:
            result = self._scorer.score_request(entry)
        except Exception:
            # Fail open: a Redis outage must not 500 every request.
            logger.exception("scoring failed, allowing request")
            result = fail_open_result()

        if result["label"] == "bot":
            body = json.dumps(result).encode()
            headers = [
                *_score_headers(result),
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ]
            start_response("403 Forbidden", headers)
            return [body]
        else:
            for name, value in _score_headers(result):
                environ["HTTP_" + name.upper().replace("-", "_")] = value
            return self.app(environ, start_response)

    def _wsgi_fingerprint(self, environ: dict, start_response: Any) -> Any:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        # Read at most the cap, never the declared length. A client that
        # announces a large body gets its announcement ignored.
        body = environ["wsgi.input"].read(min(max(length, 0), MAX_FP_BODY_BYTES + 1))

        headers = {
            k[5:].replace("_", "-").lower(): v
            for k, v in environ.items()
            if k.startswith("HTTP_")
        }
        ip = _extract_ip(headers, self._trust_xff, environ.get("REMOTE_ADDR", ""))
        status, payload = handle_fp_post(self._r, ip, body)
        start_response(f"{status} OK", [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(payload))),
        ])
        return [payload]



# --- Helpers ---


def _score_headers(result: dict) -> list[tuple[str, str]]:
    """The decision as headers, for the wrapped app to read.

    The blended score alone cannot tell the app whether the rules or the model
    drove the call, which is what you need to tune a threshold or explain a
    block to a customer.
    """
    return [
        ("X-Microguard-Label", result["label"]),
        ("X-Microguard-Score", str(result["score"])),
        ("X-Microguard-Model-Score", str(result["model_score"])),
        ("X-Microguard-Heuristic", result["heuristic_label"]),
        ("X-Microguard-Reason", result["heuristic_reason"]),
    ]


def _score_headers_asgi(result: dict) -> list[list[bytes]]:
    """The same headers, ASGI's lowercase byte-pair form."""
    return [
        [name.lower().encode(), value.encode()]
        for name, value in _score_headers(result)
    ]


def _extract_ip(headers: dict, trust_forwarded_for: bool = False, fallback: str = "") -> str:
    """Resolve the client IP from ASGI headers.

    X-Real-IP is proxy-set and not forgeable by the client; X-Forwarded-For is,
    so it is honored only when the caller opts in. Falls back to the transport
    peer address rather than a constant, which would collapse every unproxied
    client into one shared session.
    """
    xri = _decode_header(headers.get(b"x-real-ip", b""))
    if xri:
        return xri.strip()
    if trust_forwarded_for:
        xff = _decode_header(headers.get(b"x-forwarded-for", b""))
        if xff:
            return xff.split(",")[0].strip()
    return fallback or "127.0.0.1"


def _decode_header(value: Any) -> str:
    """Decode ASGI header value (bytes or str) to str."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value) if value else ""
