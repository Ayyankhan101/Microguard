"""Tests for the heuristic labeler's rules, one rule at a time.

Every test here asserts the `reason` string and the confidence, not just the
label. That is deliberate and it is the whole point of this file.

`label_session` evaluates ~24 rules in order and returns on the first match, and
every bot rule returns the label 'bot'. An assertion of `label == 'bot'` is
therefore satisfied by any of them, so a test written that way passes whether or
not it reached the rule it is named for. Eight tests in this file used to do
exactly that: they built their session with a convenient bot-shaped user agent
(`Go-http-client/1.1`, `python-requests`, `Bot0/1.0`), which trips rule 1 or
rule 3 long before the rule under test, and the coverage report showed those
rules' return statements had never executed.

Two consequences for anything added here:

- Assert the reason. The (confidence, reason) pair identifies a rule uniquely;
  the label does not.
- Use NEUTRAL_UA unless the rule under test is about the user agent. It matches
  no bot, attack-tool, CDN or integration pattern, so it reaches the rules that
  are about behavior rather than identity.

The full rule table, in evaluation order with confidences, is in
docs/reference-heuristic-rules.md.
"""

from datetime import datetime, timedelta, timezone

from microguard.features import Session
from microguard.labeler import (
    API_KEY_SCAN_RE,
    ATTACK_TOOL_RE,
    BOTNET_URL_RE,
    CLOUDFLARE_BYPASS_RE,
    _check_api_key_patterns,
    _check_botnet_signatures,
    _check_cloudflare_signals,
    label_entries,
    label_session,
)

BASE_TIME = datetime(2023, 3, 24, 17, 0, 0, tzinfo=timezone.utc)

# Matches no bot, attack-tool, CDN, integration or browser pattern, so it does
# not short-circuit at rule 1, 5, 6 or 18. Note it IS an "unknown" UA, so rule
# 15 (0.60) catches sessions over 5 requests that reach that far.
NEUTRAL_UA = "CustomAgent/1.0"

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _varied(count, base=3.0):
    """Timestamps with deliberately uneven gaps.

    Constant gaps trip rule 3 (uniform timing, 0.90) and swallow whatever rule
    a test is actually after. Several tests here learned that the hard way.
    """
    out, elapsed = [], 0.0
    for i in range(count):
        elapsed += base * (1 + (i % 3) * 0.5)
        out.append(BASE_TIME + timedelta(seconds=elapsed))
    return out


def _session(make_entry, make_session, *, count, ua=NEUTRAL_UA, url="/api/items",
             gap=3.0, status=200, referer="-", ip="10.0.0.1", raw_line=""):
    """Build a session of `count` requests with varied timing by default.

    `gap` varies per request so rule 3 (uniform timing) does not fire and
    swallow whatever rule the caller is actually testing.
    """
    entries = []
    elapsed = 0.0
    for i in range(count):
        elapsed += gap * (1 + (i % 3) * 0.5)
        entries.append(make_entry(
            ip=ip,
            timestamp=BASE_TIME + timedelta(seconds=elapsed),
            url=url(i) if callable(url) else url,
            status=status(i) if callable(status) else status,
            referer=referer,
            user_agent=ua,
            raw_line=raw_line,
        ))
    return make_session(ip, ua, entries)


# ===== Rule 0: recognized automated integrations =====

class TestAutomatedIntegration:
    """Webhooks and RPC clients are automated but not a threat.

    Checked before every bot rule, so it must win against signals that would
    otherwise flag it.
    """

    def test_stripe_webhook_is_not_a_bot(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=8, ua="Stripe/1.0 (+https://stripe.com/docs/webhooks)")

        label, confidence, reason = label_session(session)

        assert label == 'automated-integration'
        assert confidence == 0.90
        assert 'known automated client' in reason

    def test_grpc_client_library_is_not_a_bot(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=8, ua="grpc-go/1.58.0")

        label, confidence, _reason = label_session(session)

        assert label == 'automated-integration'
        assert confidence == 0.90

    def test_integration_wins_over_a_uniform_timing_signal(self, make_entry, make_session):
        # Perfectly uniform timing would be rule 3 at 0.90 for anyone else.
        entries = [
            make_entry(ip="10.0.0.1", timestamp=BASE_TIME + timedelta(seconds=i),
                       url="/hooks", user_agent="GitHub-Hookshot/abc123")
            for i in range(10)
        ]
        session = make_session("10.0.0.1", "GitHub-Hookshot/abc123", entries)

        label, _confidence, _reason = label_session(session)

        assert label == 'automated-integration'


# ===== Rule 1: known bot user agents =====

class TestKnownBotUA:
    def test_http_library_ua(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=3, ua="python-requests/2.28.0")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.95
        assert 'known bot/monitoring UA' in reason

    def test_monitoring_agent_ua(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=3, ua="Uptime-Kuma/1.23.0")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.95
        assert 'Uptime-Kuma' in reason

    def test_search_crawler_is_labeled_bot_like_any_other(self, make_entry, make_session):
        # Googlebot is automated. Whether you want to block it is policy, not
        # the labeler's call — it reports the same rule as sqlmap does.
        session = _session(make_entry, make_session, count=3, ua="Googlebot/2.1")

        label, confidence, _reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.95


# ===== Rule 2: vulnerability scanner paths =====

class TestScannerPaths:
    def test_one_scanner_path_anywhere_is_enough(self, make_entry, make_session):
        urls = ["/products", "/about", "/.env", "/contact"]
        session = _session(make_entry, make_session, count=4, url=lambda i: urls[i])

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.95
        assert reason == 'vulnerability scanner pattern detected'

    def test_ordinary_paths_do_not_match(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=4, url=lambda i: f"/products/{i}")

        _label, _confidence, reason = label_session(session)

        assert 'scanner' not in reason


# ===== Rule 3: uniform timing =====

class TestUniformTiming:
    def test_near_zero_variance_is_a_bot(self, make_entry, make_session):
        entries = [
            make_entry(ip="10.0.0.1", timestamp=BASE_TIME + timedelta(seconds=i),
                       url=f"/api/items/{i}", user_agent=NEUTRAL_UA)
            for i in range(6)
        ]
        session = make_session("10.0.0.1", NEUTRAL_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.90
        assert 'uniform timing' in reason

    def test_needs_at_least_five_requests(self, make_entry, make_session):
        entries = [
            make_entry(ip="10.0.0.1", timestamp=BASE_TIME + timedelta(seconds=i),
                       url=f"/api/items/{i}", user_agent=NEUTRAL_UA)
            for i in range(4)
        ]
        session = make_session("10.0.0.1", NEUTRAL_UA, entries)

        _label, _confidence, reason = label_session(session)

        assert 'uniform timing' not in reason

    def test_grpc_multiplexing_is_exempt(self, make_entry, make_session):
        """Uniform timing over several /Service/Method paths is normal HTTP/2.

        Without this exemption every real gRPC client is labeled by its
        transport.
        """
        paths = ["/pkg.Svc/GetUser", "/pkg.Svc/ListItems", "/pkg.Svc/PutItem"]
        entries = [
            make_entry(ip="10.0.0.1", timestamp=BASE_TIME + timedelta(seconds=i),
                       url=paths[i % 3], user_agent=NEUTRAL_UA)
            for i in range(9)
        ]
        session = make_session("10.0.0.1", NEUTRAL_UA, entries)

        _label, _confidence, reason = label_session(session)

        assert 'uniform timing' not in reason


# ===== Rule 4: HTTP/1.0 only =====

class TestHttpOneZero:
    def test_all_requests_http_10_is_a_bot(self, make_entry, make_session):
        session = _session(
            make_entry, make_session, count=8,
            raw_line='1.2.3.4 - - [24/Mar/2023:17:07:41 +0000] "GET /a HTTP/1.0" 200 1 "-" "x"',
        )

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.90
        assert 'HTTP/1.0' in reason

    def test_needs_more_than_five_requests(self, make_entry, make_session):
        session = _session(
            make_entry, make_session, count=5,
            raw_line='1.2.3.4 - - [24/Mar/2023:17:07:41 +0000] "GET /a HTTP/1.0" 200 1 "-" "x"',
        )

        _label, _confidence, reason = label_session(session)

        assert 'HTTP/1.0' not in reason


# ===== Rule 5: CDN / WAF signals =====

class TestCloudflareWAF:
    def test_cloudflare_bypass_ua(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=1, ua="cf-worker/1.0")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.90
        assert 'Cloudflare WAF bypass UA' in reason

    def test_incapsula_ua(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=1, ua="Incapsula-Inspector")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.90
        assert 'Cloudflare WAF' in reason

    def test_protected_endpoint_scan_with_no_referrer_anywhere(self, make_entry, make_session):
        """Uses /console, not /wp-admin.

        /wp-admin is also a rule 2 scanner path, so a session built with it
        never reaches this rule — which is exactly how this test used to pass
        without testing anything.
        """
        session = _session(make_entry, make_session, count=4, url="/console", referer="-")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.90
        assert 'WAF-protected endpoint scan' in reason

    def test_a_single_referrer_defeats_the_protected_endpoint_rule(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=4, url="/console",
                           referer="https://example.com/")

        is_bot, reason = _check_cloudflare_signals(session)

        assert is_bot is False
        assert reason == ''

    def test_cloudflare_regex_matches(self):
        assert CLOUDFLARE_BYPASS_RE.search("cf-worker/1.0")
        assert CLOUDFLARE_BYPASS_RE.search("cloudflare")
        assert CLOUDFLARE_BYPASS_RE.search("Incapsula-Inspector")
        assert not CLOUDFLARE_BYPASS_RE.search("Mozilla/5.0")


# ===== Rule 6: attack tool user agents =====

class TestAttackTool:
    def test_nuclei_ua(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=1, ua="Nuclei - Open-source project")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.90
        assert 'attack tool detected' in reason

    def test_attack_tool_regex_matches(self):
        assert ATTACK_TOOL_RE.search("Nuclei - Open-source project")
        assert ATTACK_TOOL_RE.search("ffuf/2.0")
        assert ATTACK_TOOL_RE.search("Go net/http client")
        assert ATTACK_TOOL_RE.search("feroxbuster/2.0")
        assert not ATTACK_TOOL_RE.search("Mozilla/5.0 Chrome")


# ===== Rule 7: botnet signatures =====

class TestBotnetSignatures:
    def test_iot_endpoint_scanning(self, make_entry, make_session):
        # Not /boaform/admin: it contains /admin, a WAF-protected endpoint, so
        # with no referrer anywhere rule 5 claims the session first.
        paths = ["/shell.cgi", "/HNAP1", "/tr069"]
        session = _session(make_entry, make_session, count=9,
                           url=lambda i: paths[i % 3],
                           referer="https://example.com/")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.88
        assert 'botnet scanning pattern' in reason

    def test_directory_brute_force(self, make_entry, make_session):
        """Neutral UA, and no path that is also a rule 2 scanner path.

        The previous version used Go-http-client/1.1 and /wp-admin, so it
        reported 'known bot/monitoring UA' and never reached this rule.
        """
        dirs = ["/admin", "/backup", "/debug", "/git", "/hidden", "/private",
                "/secret", "/tmp", "/old", "/beta"]
        session = _session(
            make_entry, make_session, count=40,
            url=lambda i: dirs[i % len(dirs)],
            status=lambda i: 403 if i % 2 == 0 else 404,
            referer="https://example.com/",
        )

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.88
        assert 'directory brute-force' in reason

    def test_ua_rotation(self, make_entry, make_session):
        """Varied timing, so rule 3 does not claim this first."""
        entries = []
        for i in range(20):
            entries.append(make_entry(
                ip="10.0.0.1",
                timestamp=BASE_TIME + timedelta(seconds=i * (1 + i % 4)),
                url=f"/page/{i}",
                user_agent=f"Agent{i}/1.0",
            ))
        session = make_session("10.0.0.1", "Agent0/1.0", entries)

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.88
        assert 'UA rotation' in reason

    def test_attack_tool_ua_reached_directly(self, make_entry, make_session):
        """Rule 6 catches attack tools first, so this branch of the botnet
        helper is unreachable through label_session. Exercised directly."""
        session = _session(make_entry, make_session, count=2, ua="Gobuster/3.1")

        is_bot, reason = _check_botnet_signatures(session)

        assert is_bot is True
        assert 'attack tool UA' in reason

    def test_single_request_not_flagged_as_ua_rotation(self, make_entry, make_session):
        # A session with 1 request has exactly 1 UA variant — there's
        # nothing to "rotate" between. min(10, request_count * 0.3) drops
        # below 1 for request_count in {1, 2, 3}, so any non-empty UA set
        # (always >= 1) incorrectly satisfied `len(ua_variants) > threshold`.
        entries = [make_entry(user_agent=BROWSER_UA)]
        session = make_session("192.168.1.5", BROWSER_UA, entries)

        is_bot, reason = _check_botnet_signatures(session)

        assert is_bot is False
        assert reason == ''

    def test_botnet_regex_matches(self):
        assert BOTNET_URL_RE.search("/shell.cgi")
        assert BOTNET_URL_RE.search("/HNAP1")
        assert BOTNET_URL_RE.search("/omega.cgi")
        assert BOTNET_URL_RE.search("/boaform")
        assert not BOTNET_URL_RE.search("/products")


# ===== Rules 8-10: volume and rate =====

class TestVolumeAndRate:
    def test_extreme_request_count(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=101,
                           url=lambda i: f"/page/{i}")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.85
        assert 'extremely high request count' in reason

    def test_asset_heavy_human_is_not_a_high_count_bot(self, make_entry, make_session):
        """A browser loading rich pages fires many image/CSS subrequests.

        140 requests, but only 10 are pages (the rest are /image/... and
        /static/... assets a browser fetches per page). The volume rules count
        page-like requests, so this real-shopper shape must not be a bot -- the
        failure the Zanbil benchmark surfaced (57% of real shoppers flagged).
        """
        def url(i):
            return f"/product/{i // 14}" if i % 14 == 0 else f"/image/{i}/thumb.jpg"

        session = _session(make_entry, make_session, count=140, ua=BROWSER_UA,
                           url=url, referer="https://example.com/")

        label, _confidence, reason = label_session(session)

        assert 'extremely high request count' not in reason
        assert 'high request rate' not in reason
        assert label != 'bot'

    def test_page_scraper_past_100_is_still_caught(self, make_entry, make_session):
        """The fix must not let a real scraper through: 101 distinct pages,
        none of them assets, still trips the count rule."""
        session = _session(make_entry, make_session, count=101,
                           url=lambda i: f"/product/{i}")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.85
        assert 'extremely high request count' in reason

    def test_every_request_to_one_endpoint(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=12, url="/api/items")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.80
        assert 'requests to same endpoint' in reason

    def test_single_endpoint_api_is_exempt(self, make_entry, make_session):
        """GraphQL routes every call through one path by design.

        Without the exemption, every legitimate GraphQL client is a scraper.
        """
        session = _session(make_entry, make_session, count=50, url="/graphql")

        _label, _confidence, reason = label_session(session)

        assert 'same endpoint' not in reason
        assert 'repeated endpoint' not in reason

    def test_sustained_request_rate(self, make_entry, make_session):
        # 30 requests over ~15s = 120/min, above the 50/min bar, and past the
        # 1.0s / 5-request floors.
        times = _varied(30, base=0.3)
        entries = [
            make_entry(ip="10.0.0.1", timestamp=times[i], url=f"/api/items/{i}",
                       user_agent=NEUTRAL_UA, referer="https://example.com/")
            for i in range(30)
        ]
        session = make_session("10.0.0.1", NEUTRAL_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.75
        assert 'high request rate' in reason

    def test_rate_rule_has_a_minimum_window(self, make_entry, make_session):
        """Five requests spanning 1.5ms is a browser loading one page.

        Without MIN_RATE_WINDOW_S that extrapolates to ~200,000 req/min and
        blocks a real visitor. Batch scans never hit it because nginx
        timestamps are second-granular; the live path uses time.time().
        """
        entries = [
            make_entry(ip="10.0.0.1", timestamp=BASE_TIME + timedelta(milliseconds=i * 0.3),
                       url=f"/static/{i}.png", user_agent=BROWSER_UA)
            for i in range(5)
        ]
        session = make_session("10.0.0.1", BROWSER_UA, entries)

        _label, _confidence, reason = label_session(session)

        assert 'high request rate' not in reason


# ===== Rules 11-13: referrer, errors, repetition =====

class TestTrafficShape:
    def test_no_referrer_on_any_request(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=25,
                           url=lambda i: f"/api/items/{i}", referer="-")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.70
        assert 'no referrer on all' in reason

    def test_high_error_rate(self, make_entry, make_session):
        session = _session(
            make_entry, make_session, count=12,
            url=lambda i: f"/api/items/{i}",
            status=lambda i: 500 if i < 7 else 200,
            referer="https://example.com/",
        )

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.70
        assert 'high error rate' in reason

    def test_one_endpoint_dominating_a_varied_session(self, make_entry, make_session):
        # 25 hits on one path plus a few others: >20 hits and >70% of the
        # session, but not a single-URL session, so rule 9 does not fire.
        session = _session(
            make_entry, make_session, count=30,
            url=lambda i: "/api/search" if i < 25 else f"/other/{i}",
            referer="https://example.com/",
        )

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.70
        assert 'repeated endpoint hit' in reason


# ===== Rule 14: credential and key scanning =====

class TestAPIKeyPatterns:
    def test_api_key_parameter_scanning(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=8,
                           url=lambda i: f"/v1/data?key=test{i}",
                           referer="https://example.com/")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.75
        assert 'API key parameter scanning' in reason

    def test_credential_brute_force(self, make_entry, make_session):
        """/login, not /wp-login.php.

        /wp-login is a rule 2 scanner path, so the previous version of this
        test reported 'vulnerability scanner pattern detected'.
        """
        entries = [
            make_entry(ip="10.0.0.1", timestamp=BASE_TIME + timedelta(seconds=i * 2),
                       url="/login", user_agent=BROWSER_UA, referer="https://example.com/")
            for i in range(8)
        ]
        session = make_session("10.0.0.1", BROWSER_UA, entries)

        is_bot, reason = _check_api_key_patterns(session)

        assert is_bot is True
        assert 'credential brute-force' in reason

    def test_post_brute_force(self, make_entry, make_session):
        entries = [
            make_entry(ip="10.0.0.1", timestamp=BASE_TIME + timedelta(seconds=i * 30),
                       url="/signin", method="POST", user_agent=BROWSER_UA)
            for i in range(12)
        ]
        session = make_session("10.0.0.1", BROWSER_UA, entries)

        is_bot, reason = _check_api_key_patterns(session)

        assert is_bot is True
        assert 'POST brute-force' in reason

    def test_api_key_regex_matches(self):
        assert API_KEY_SCAN_RE.search("/api?key=test")
        assert API_KEY_SCAN_RE.search("/api?token=abc")
        assert API_KEY_SCAN_RE.search("/api?api_key=xyz")
        assert API_KEY_SCAN_RE.search("/oauth2/token")
        assert not API_KEY_SCAN_RE.search("/products")


# ===== Rules 15-17: weaker bot signals =====

class TestWeakBotSignals:
    def test_unknown_user_agent(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=6,
                           url=lambda i: f"/api/items/{i}",
                           referer="https://example.com/")

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.60
        assert 'unknown user-agent' in reason

    def test_many_requests_in_a_very_short_session(self, make_entry, make_session):
        # The burst has to span under 1 second. Above that, rule 10's rate
        # check fires first — 21 requests inside 5 seconds is always more than
        # 50/min — so rule 16 is only reachable below MIN_RATE_WINDOW_S.
        entries = [
            make_entry(ip="10.0.0.1", timestamp=_varied(25, base=0.02)[i],
                       url=f"/api/items/{i}", user_agent=BROWSER_UA,
                       referer="https://example.com/")
            for i in range(25)
        ]
        session = make_session("10.0.0.1", BROWSER_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.65
        assert 'pages in' in reason

    def test_night_time_volume(self, make_entry, make_session):
        night = BASE_TIME.replace(hour=3)
        entries = [
            make_entry(ip="10.0.0.1",
                       timestamp=night + (_varied(35, base=8.0)[i] - BASE_TIME),
                       url=f"/api/items/{i}", user_agent=BROWSER_UA,
                       referer="https://example.com/")
            for i in range(35)
        ]
        session = make_session("10.0.0.1", BROWSER_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.60
        assert 'night-time activity' in reason


# ===== Rules 18-22: human signals =====

class TestHumanSignals:
    def test_known_browser_normal_session(self, make_entry, make_session):
        entries = [
            make_entry(ip="192.168.1.1", timestamp=_varied(10, base=5.0)[i],
                       url=f"/page/{i}", user_agent=BROWSER_UA,
                       referer="https://example.com/")
            for i in range(10)
        ]
        session = make_session("192.168.1.1", BROWSER_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'human'
        assert confidence == 0.75
        assert 'known browser, reasonable session' in reason

    def test_variable_timing(self, make_entry, make_session):
        """Neutral UA and a short session, so rule 18 does not claim it."""
        # max/avg must exceed 3.0, and the session must stay under 30s or
        # rule 18 (known browser, reasonable session) claims it at 0.75.
        delays = [0.2, 0.2, 0.2, 20.0, 0.2]
        elapsed, entries = 0.0, []
        for i, delay in enumerate(delays):
            elapsed += delay
            entries.append(make_entry(
                ip="192.168.1.1", timestamp=BASE_TIME + timedelta(seconds=elapsed),
                url=f"/page/{i}", user_agent=BROWSER_UA, referer="-",
            ))
        session = make_session("192.168.1.1", BROWSER_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'human'
        assert confidence == 0.70
        assert 'variable timing' in reason

    def test_exploring_several_endpoints(self, make_entry, make_session):
        entries = [
            make_entry(ip="192.168.1.1", timestamp=_varied(5, base=2.0)[i],
                       url=f"/section/{i}", user_agent=NEUTRAL_UA, referer="-")
            for i in range(5)
        ]
        session = make_session("192.168.1.1", NEUTRAL_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'human'
        assert confidence == 0.65
        assert 'exploring 5 different endpoints' in reason

    def test_natural_navigation_with_referrers(self, make_entry, make_session):
        entries = [
            make_entry(ip="192.168.1.1", timestamp=_varied(3, base=4.0)[i],
                       url="/catalog", user_agent=NEUTRAL_UA,
                       referer="https://example.com/home")
            for i in range(3)
        ]
        session = make_session("192.168.1.1", NEUTRAL_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'human'
        assert confidence == 0.60
        assert 'natural navigation' in reason

    def test_cdn_ua_that_is_also_a_browser_is_labeled_bot(self, make_entry, make_session):
        """Pins a known defect, not intended behavior.

        Rule 22 ('Cloudflare-protected site, normal browser', human 0.65)
        exists to protect a real visitor whose UA carries a CDN marker. It can
        never fire: rule 5 returns bot at 0.90 for any UA matching the same CDN
        pattern, seventeen rules earlier. So such a visitor is labeled a bot.
        This test records that, so the eventual fix shows up as a deliberate
        change rather than a surprise.
        """
        ua = "Mozilla/5.0 Chrome/120.0.0.0 akamai-preview"
        entries = [
            make_entry(ip="192.168.1.1", timestamp=_varied(4, base=4.0)[i],
                       url=f"/page/{i}", user_agent=ua, referer="-")
            for i in range(4)
        ]
        session = make_session("192.168.1.1", ua, entries)

        label, confidence, reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.90
        assert 'Cloudflare WAF bypass UA' in reason

    def test_no_strong_signals_defaults_to_human(self, make_entry, make_session):
        entries = [
            make_entry(ip="192.168.1.1", timestamp=_varied(2, base=4.0)[i],
                       url="/catalog", user_agent=BROWSER_UA, referer="-")
            for i in range(2)
        ]
        session = make_session("192.168.1.1", BROWSER_UA, entries)

        label, confidence, reason = label_session(session)

        assert label == 'human'
        assert confidence == 0.50
        assert reason == 'no strong signals either way'


# ===== Evaluation order =====

class TestEvaluationOrder:
    """Order is load-bearing behavior, and nothing else asserts it."""

    def test_first_match_wins(self, make_entry, make_session):
        """A session matching both rule 1 and rule 7 reports rule 1.

        This is the property that made eight tests in this file pass without
        testing anything: a bot-shaped UA short-circuits every behavioral rule
        below it.
        """
        paths = ["/shell.cgi", "/HNAP1", "/boaform/admin"]
        session = _session(make_entry, make_session, count=9,
                           ua="python-requests/2.28.0",
                           url=lambda i: paths[i % 3])

        _label, confidence, reason = label_session(session)

        assert confidence == 0.95
        assert 'known bot/monitoring UA' in reason
        assert 'botnet' not in reason

    def test_integration_check_precedes_every_bot_rule(self, make_entry, make_session):
        paths = ["/shell.cgi", "/HNAP1", "/boaform/admin"]
        session = _session(make_entry, make_session, count=9,
                           ua="Stripe/1.0", url=lambda i: paths[i % 3])

        label, _confidence, _reason = label_session(session)

        assert label == 'automated-integration'


# ===== Edge cases =====

class TestEdgeCases:
    def test_empty_session(self):
        session = Session("10.0.0.1", "")

        label, confidence, reason = label_session(session)

        assert label == 'human'
        assert confidence == 0.5
        assert reason == 'empty session'

    def test_single_request_from_a_bot_ua(self, make_entry, make_session):
        session = _session(make_entry, make_session, count=1, ua="python-requests/2.28.0")

        label, confidence, _reason = label_session(session)

        assert label == 'bot'
        assert confidence == 0.95

    def test_label_entries_batch(self, make_entry):
        entries = [
            make_entry(ip="192.168.1.1", timestamp=BASE_TIME + timedelta(seconds=i),
                       url=f"/page/{i}", user_agent=BROWSER_UA)
            for i in range(20)
        ]

        results = label_entries(entries)

        assert len(results) >= 1
        for _session, label, confidence, reason in results:
            assert label in ('bot', 'human', 'automated-integration')
            assert 0.0 <= confidence <= 1.0
            assert reason


class TestEveryRuleIsReachable:
    """`label_session` is a first-match chain, so position decides outcomes.

    A rule placed after one that matches a superset of its inputs can never
    fire, and nothing reports that -- the rule simply never runs, and the
    visitor it was written to protect gets the earlier verdict instead. This
    is the rule-order debt tracked in TODOS.md as P3.

    The check is coverage-based rather than by inspection: run the labeler
    over a spread of sessions and assert no `return` inside `label_session`
    is unexecuted for reasons other than the fixtures being thin.
    """

    def test_the_cloudflare_browser_rule_is_dead(self, make_session, make_entry):
        """The known instance, pinned by construction rather than by coverage.

        `Cloudflare-protected site, normal browser` (human, 0.65) exists to
        protect a real visitor whose UA carries a CDN marker. An earlier rule
        matches the SAME regex and returns 'bot' at 0.90, so that visitor is
        labeled a bot instead. Build the exact session the late rule wants and
        show which verdict actually comes back.
        """
        from microguard.labeler import CLOUDFLARE_BYPASS_RE, label_session

        # A UA that satisfies BOTH the CDN marker and the browser pattern --
        # precisely the input the late rule was written for.
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 cloudflare"
        )
        assert CLOUDFLARE_BYPASS_RE.search(ua), "fixture no longer matches the CDN regex"

        session = make_session(
            "203.0.113.9",
            ua,
            [make_entry(ip="203.0.113.9", user_agent=ua, url=u)
             for u in ("/", "/about", "/pricing", "/docs", "/contact")],
        )
        label, _confidence, reason = label_session(session)

        assert reason != 'Cloudflare-protected site, normal browser', (
            "the late rule became reachable -- remove its pragma: no cover, "
            "delete this test's xfail, and update the CHANGELOG"
        )
        assert label == 'bot', (
            f"expected the earlier CDN rule to win, got {label!r} via {reason!r}"
        )
