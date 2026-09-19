"""Middleware wrapped around real FastAPI and Flask apps.

Spec 0001 acceptance criteria #9 and #10 ask for exactly this: not "the
middleware object was constructed", but a request routed through a real
framework's test client, reaching (or not reaching) a real handler.
`test_middleware.py` covers the ASGI/WSGI protocol mechanics with hand-built
scopes and environs; this file proves the two integration paths customers
actually use.

Bot signal: a request to a vulnerability-scanner path, which `label_session`
returns as ('bot', 0.95) on the very first request — deterministic, and
independent of the user-agent lists and timing rules that shift with tuning.
"""

import pytest

redis = pytest.importorskip("redis", reason="needs the 'live' extra")

from microguard.live.middleware import MicroguardASGI, MicroguardWSGI

# An unambiguous probe: no browser requests /phpmyadmin in the course of
# using a site. /wp-admin used to live here, but it is a path a human
# administrator legitimately visits, so it moved to the rule that gates on
# no-referrer-across-the-session and no longer returns the 0.95 scanner
# verdict these tests are asserting.
SCANNER_PATH = "/phpmyadmin/index.php"
BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


@pytest.fixture()
def redis_url():
    """A dedicated db, flushed per test, or skip if no Redis is running."""
    url = "redis://localhost:6379/12"
    try:
        client = redis.Redis.from_url(url, decode_responses=True)
        client.ping()
    except redis.ConnectionError:
        pytest.skip("Redis not available on localhost:6379")
    client.flushdb()
    yield url
    client.flushdb()
    client.close()


# --- ASGI / FastAPI (spec AC#9) ---


@pytest.fixture()
def asgi_client(redis_url):
    fastapi = pytest.importorskip("fastapi", reason="needs the 'fastapi' extra")
    testclient = pytest.importorskip("starlette.testclient", reason="needs the 'fastapi' extra")

    app = fastapi.FastAPI()
    reached: list[str] = []

    @app.get("/{path:path}")
    def handler(path: str):
        reached.append(path)
        return {"ok": True}

    wrapped = MicroguardASGI(app, redis_url=redis_url, block_threshold=0.85)
    client = testclient.TestClient(wrapped)
    client.reached = reached  # type: ignore[attr-defined]
    return client


class TestFastAPIIntegration:
    def test_bot_gets_403_and_never_reaches_the_app(self, asgi_client):
        resp = asgi_client.get(SCANNER_PATH, headers={"X-Real-IP": "203.0.113.10"})
        assert resp.status_code == 403
        assert resp.json()["label"] == "bot"
        assert asgi_client.reached == [], "blocked request still hit the handler"

    def test_human_reaches_the_app(self, asgi_client):
        resp = asgi_client.get(
            "/api/items",
            headers={"X-Real-IP": "203.0.113.11", "User-Agent": BROWSER_UA},
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        assert asgi_client.reached == ["api/items"]

    def test_block_response_carries_the_score_headers(self, asgi_client):
        resp = asgi_client.get(SCANNER_PATH, headers={"X-Real-IP": "203.0.113.12"})
        assert resp.headers["x-microguard-label"] == "bot"
        assert float(resp.headers["x-microguard-score"]) >= 0.85


# --- WSGI / Flask (spec AC#10) ---


@pytest.fixture()
def wsgi_client(redis_url):
    flask = pytest.importorskip("flask", reason="needs the 'flask' extra")

    app = flask.Flask(__name__)
    reached: list[str] = []

    @app.route("/<path:path>")
    def handler(path: str):
        reached.append(path)
        return {"ok": True}

    app.wsgi_app = MicroguardWSGI(app.wsgi_app, redis_url=redis_url, block_threshold=0.85)
    client = app.test_client()
    client.reached = reached  # type: ignore[attr-defined]
    return client


class TestFlaskIntegration:
    def test_bot_gets_403_and_never_reaches_the_app(self, wsgi_client):
        resp = wsgi_client.get(SCANNER_PATH, headers={"X-Real-IP": "203.0.113.20"})
        assert resp.status_code == 403
        assert resp.get_json()["label"] == "bot"
        assert wsgi_client.reached == [], "blocked request still hit the handler"

    def test_human_reaches_the_app(self, wsgi_client):
        resp = wsgi_client.get(
            "/api/items",
            headers={"X-Real-IP": "203.0.113.21", "User-Agent": BROWSER_UA},
        )
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True}
        assert wsgi_client.reached == ["api/items"]

    def test_block_response_carries_the_score_headers(self, wsgi_client):
        resp = wsgi_client.get(SCANNER_PATH, headers={"X-Real-IP": "203.0.113.22"})
        assert resp.headers["X-Microguard-Label"] == "bot"
        assert float(resp.headers["X-Microguard-Score"]) >= 0.85


class TestScoreHeaders:
    """The wrapped app receives the breakdown, not just a verdict."""

    BREAKDOWN = (
        "x-microguard-label",
        "x-microguard-score",
        "x-microguard-model-score",
        "x-microguard-heuristic",
        "x-microguard-reason",
    )

    def test_block_response_carries_the_breakdown(self, asgi_client):
        resp = asgi_client.get(SCANNER_PATH, headers={"X-Real-IP": "203.0.113.30"})
        assert resp.status_code == 403
        for name in self.BREAKDOWN:
            assert name in resp.headers, name
        assert resp.headers["x-microguard-heuristic"] == "bot"
        assert "scanner" in resp.headers["x-microguard-reason"]

    def test_client_cannot_forge_its_own_verdict(self, asgi_client):
        """A client sending x-microguard-* must not have it reach the app.

        Header lookups return the first match, so appending ours alongside a
        client's would let the client's value win.
        """
        resp = asgi_client.get(
            "/api/items",
            headers={
                "X-Real-IP": "203.0.113.31",
                "User-Agent": BROWSER_UA,
                "X-Microguard-Label": "human",
                "X-Microguard-Score": "0.0",
            },
        )
        assert resp.status_code == 200
        assert asgi_client.reached == ["api/items"]

    def test_wsgi_block_response_carries_the_breakdown(self, wsgi_client):
        resp = wsgi_client.get(SCANNER_PATH, headers={"X-Real-IP": "203.0.113.40"})
        assert resp.status_code == 403
        assert resp.headers["X-Microguard-Heuristic"] == "bot"
        assert float(resp.headers["X-Microguard-Model-Score"]) >= 0.0
