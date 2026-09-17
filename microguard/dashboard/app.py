"""FastAPI application factory for the microguard dashboard."""

from __future__ import annotations

import hmac
import logging
import os

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Starlette's, not FastAPI's: StaticFiles raises the base class, and
# FastAPI's subclass would not catch it.
from starlette.exceptions import HTTPException

from .. import __version__
from ..events import DecisionRecorder, InMemoryDecisionRecorder
from . import api_health, api_live, api_model, api_scan

logger = logging.getLogger(__name__)


def _redis_backends(
    redis_url: str,
) -> tuple[DecisionRecorder | None, object | None, object | None]:
    """Connect to the Redis the live path writes to, or None if it is not there.

    An unreachable Redis is not a startup failure. `microguard serve` exits on
    it because it cannot score without one, but the dashboard's scan and model
    tabs work regardless — dropping those too, because a live feed is missing,
    would be the wrong trade. /api/health reports which one is in play.
    """
    try:
        import redis

        from ..live.redis_events import RedisDecisionRecorder
        from ..live.runtime_config import RedisRuntimeConfig
    except ImportError:
        logger.warning(
            "redis is not installed - live tab will be empty "
            "(pip install 'microguard[live]')"
        )
        return None, None, None

    try:
        client = redis.Redis.from_url(redis_url, decode_responses=True)
        client.ping()
    except redis.RedisError:
        logger.warning(
            "redis at %s is unreachable - live tab will be empty", redis_url
        )
        return None, None, None
    return RedisDecisionRecorder(client), RedisRuntimeConfig(client), client


def create_app(
    recorder: DecisionRecorder | None = None,
    redis_url: str | None = None,
    allow_config_writes: bool = False,
    static_dir: str | None = None,
    token: str | None = None,
    deployment_id: str | None = None,
    feedback_dir: str | None = None,
) -> FastAPI:
    """Build the dashboard app.

    `recorder` is where the live tab reads decisions from. Given a `redis_url`
    the app reads the same keys `microguard serve` and the middleware write to;
    with neither, it falls back to a process-local recorder that stays empty
    unless something in this process is scoring.
    """
    app = FastAPI(title="Microguard Dashboard", version=__version__)

    runtime_config = None
    client = None
    if recorder is None and redis_url:
        recorder, runtime_config, client = _redis_backends(redis_url)
    app.state.recorder = recorder if recorder is not None else InMemoryDecisionRecorder()
    app.state.redis_connected = not isinstance(
        app.state.recorder, InMemoryDecisionRecorder
    )
    app.state.runtime_config = runtime_config
    app.state.redis = client
    app.state.allow_config_writes = allow_config_writes
    # Corrections are per-deployment by definition: the whole point is
    # adapting to ONE deployment's traffic, so without an id there is
    # nothing to attribute them to and the endpoint reports that.
    app.state.deployment_id = deployment_id
    app.state.feedback_dir = feedback_dir

    if token:
        _require_token(app, token)

    app.include_router(api_health.router)
    app.include_router(api_scan.router)
    app.include_router(api_model.router)
    app.include_router(api_live.router)

    if static_dir and os.path.isdir(static_dir):
        _mount_spa(app, static_dir)
    elif static_dir:
        logger.warning("no built UI at %s - serving the API only", static_dir)

    return app


def _require_token(app: FastAPI, token: str) -> None:
    """Gate the API behind a shared secret.

    For the case where loopback binding is not an option. It is a single
    secret over whatever transport the operator terminates, not an auth
    system — the page itself stays open so a browser can load it, and only
    /api is gated. Compared with compare_digest so a wrong guess takes the
    same time as any other.
    """

    @app.middleware("http")
    async def check_token(request, call_next):
        if request.url.path.startswith("/api"):
            supplied = request.headers.get("X-Microguard-Token", "")
            if not hmac.compare_digest(supplied, token):
                return JSONResponse(
                    {"detail": "Missing or invalid X-Microguard-Token"}, status_code=401
                )
        return await call_next(request)


def _is_api_path(scope: dict) -> bool:
    """Whether this request is for the API rather than the SPA.

    Reads the request path from the ASGI scope, NOT the path StaticFiles
    passes its handler: that one is os.sep-normalized, so on Windows it
    arrives as "api\\live\\stats" and a "api/" check silently misses,
    turning every mistyped endpoint into a 200 with the HTML shell.
    """
    return scope.get("path", "").lstrip("/").startswith("api/")


def _mount_spa(app: FastAPI, static_dir: str) -> None:
    """Serve the built SPA, with unknown paths falling back to index.html.

    Mounted last and at the root, so every /api route is matched first and a
    mistyped endpoint still returns a JSON 404 rather than the HTML shell —
    an API that answers 200 with a page is far harder to debug from the
    browser than one that 404s.
    """
    index = os.path.join(static_dir, "index.html")

    class SpaFiles(StaticFiles):
        async def get_response(self, path: str, scope):
            try:
                return await super().get_response(path, scope)
            except HTTPException as missing:
                # StaticFiles raises rather than returning a 404 response.
                if missing.status_code != 404 or not os.path.isfile(index):
                    raise
                # A mistyped endpoint must stay a 404. Answering it with the
                # HTML shell turns a clear error into a confusing 200 that
                # fails later, wherever the response is parsed.
                if _is_api_path(scope):
                    raise
                return FileResponse(index)

    app.mount("/", SpaFiles(directory=static_dir, html=True), name="spa")
