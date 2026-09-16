"""The fingerprint script, in a real browser.

Decision 9A. Everything asserted here is unfalsifiable without one: canvas and
WebGL do not exist under Node, and they are where the actual signal comes from.
A unit test of the hashing would pass with every probe returning a constant.

Two claims are checked here and nowhere else:

  1. The hash varies with the environment. A fingerprint that is identical
     everywhere is a constant wearing a fingerprint's name, and nothing else in
     the suite can tell the difference.
  2. Only the hash leaves the page. That is a claim the README makes, and
     asserting it in prose is not evidence -- this reads the real request body.

The page and the script are served from one routed origin rather than from a
running check server. The endpoint in the script is relative, which is correct
in production and unresolvable from `about:blank`; routing a real origin is
what makes the relative path behave the way it does on a real site. The server
side of /fp is covered against a real process in tests/live/.

Skipped when Playwright or its browser is absent, matching how this project
already handles its network-dependent tests. CI installs both.
"""

import json
from pathlib import Path

import pytest

playwright_api = pytest.importorskip(
    "playwright.sync_api",
    reason="browser tests need playwright: pip install playwright && playwright install chromium",
)

SCRIPT = Path("microguard/live/static/fingerprint.js").resolve()
ORIGIN = "https://microguard.test"
PAGE = (
    "<!doctype html><html><head><title>fp</title></head><body>"
    '<h1>page</h1><script src="/fingerprint.js"></script>'
    "</body></html>"
)


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"chromium not installed: {exc}")
        yield chromium
        chromium.close()


def _capture(browser, init_script: str | None = None, **context_kwargs) -> str | None:
    """Load a page embedding the real script; return the body it POSTs.

    `init_script` runs before any page script, which is how a blocked API is
    simulated: it replaces the API before fingerprint.js can reach it.
    """
    context = browser.new_context(**context_kwargs)
    if init_script is not None:
        context.add_init_script(init_script)
    page = context.new_page()
    captured: dict[str, str] = {}

    def handle(route):
        url = route.request.url
        if url.endswith("/fingerprint.js"):
            route.fulfill(
                status=200,
                content_type="application/javascript",
                body=SCRIPT.read_text(encoding="utf-8"),
            )
        elif url.endswith("/microguard/fp"):
            captured["body"] = route.request.post_data or ""
            route.fulfill(status=200, content_type="application/json", body='{"ok":true}')
        else:
            route.fulfill(status=200, content_type="text/html", body=PAGE)

    page.route(f"{ORIGIN}/**", handle)
    page.goto(f"{ORIGIN}/")
    page.wait_for_timeout(1200)
    context.close()
    return captured.get("body")


class TestTheScriptRunsInARealBrowser:
    def test_it_posts_a_sha256_hex_digest(self, browser):
        body = _capture(browser)

        assert body is not None, "the script never called /microguard/fp"
        digest = json.loads(body)["fingerprint_hash"]
        assert len(digest) == 64
        int(digest, 16)  # raises unless it is hex

    def test_the_hash_is_stable_for_the_same_environment(self, browser):
        first = json.loads(_capture(browser))["fingerprint_hash"]
        second = json.loads(_capture(browser))["fingerprint_hash"]

        assert first == second

    def test_the_hash_changes_with_the_environment(self, browser):
        baseline = json.loads(_capture(browser))["fingerprint_hash"]
        altered = json.loads(_capture(
            browser,
            viewport={"width": 800, "height": 600},
            screen={"width": 800, "height": 600},
            timezone_id="Asia/Karachi",
            locale="ur-PK",
        ))["fingerprint_hash"]

        assert baseline != altered


# Canvas blocked two ways. Browsers with canvas disabled return null from
# getContext; privacy extensions commonly throw instead. WebGL goes through the
# same call, so both are blocked at once.
CANVAS_RETURNS_NULL = "HTMLCanvasElement.prototype.getContext = function () { return null; };"
CANVAS_THROWS = (
    "HTMLCanvasElement.prototype.getContext = function () {"
    " throw new Error('blocked by extension'); };"
)


class TestBlockedApis:
    """The absence rule reads a missing fingerprint as evidence of a bot, so a
    human with canvas or WebGL blocked must still produce a hash and still
    reach the endpoint. Each case also asserts the hash moved off the
    unblocked one -- otherwise a block that silently failed to apply would
    pass this test while proving nothing.
    """

    @pytest.mark.parametrize(
        "init_script",
        [CANVAS_RETURNS_NULL, CANVAS_THROWS],
        ids=["canvas-and-webgl-return-null", "canvas-and-webgl-throw"],
    )
    def test_it_still_posts_a_hash_with_canvas_and_webgl_blocked(self, browser, init_script):
        unblocked = json.loads(_capture(browser))["fingerprint_hash"]
        body = _capture(browser, init_script=init_script)

        assert body is not None, "the script never called /microguard/fp with canvas blocked"
        digest = json.loads(body)["fingerprint_hash"]
        assert len(digest) == 64
        int(digest, 16)
        assert digest != unblocked, "the block did not apply; this test proved nothing"


class TestPrivacy:
    def test_only_the_hash_is_transmitted(self, browser):
        """The privacy claim, read off the wire rather than asserted in prose.

        A raw canvas data URL, a WebGL renderer string, or a font list reaching
        the server would show up here as an extra key or as a payload far
        larger than one digest.
        """
        body = _capture(browser)
        payload = json.loads(body)

        assert set(payload) == {"fingerprint_hash"}
        assert len(body) < 120, f"payload is larger than one hash: {body[:200]}"
        assert "data:image" not in body
        assert "ANGLE" not in body  # a common WebGL renderer string


class TestSecureContextRequirement:
    def test_it_says_why_it_cannot_run_on_an_insecure_origin(self, browser):
        """SubtleCrypto does not exist outside a secure context, so the script
        is inert on a plain-HTTP site. The absence rule reads a missing
        fingerprint as evidence, which would make such a site look like it was
        full of bots -- so the reason has to be visible in the console rather
        than the script just returning.
        """
        context = browser.new_context()
        page = context.new_page()
        warnings = []
        page.on("console", lambda m: warnings.append(m.text) if m.type == "warning" else None)

        def handle(route):
            if route.request.url.endswith("/fingerprint.js"):
                route.fulfill(status=200, content_type="application/javascript",
                              body=SCRIPT.read_text(encoding="utf-8"))
            else:
                route.fulfill(status=200, content_type="text/html", body=PAGE)

        page.route("http://microguard.test/**", handle)
        page.goto("http://microguard.test/")
        page.wait_for_timeout(600)
        context.close()

        assert any("secure context" in w for w in warnings), warnings
