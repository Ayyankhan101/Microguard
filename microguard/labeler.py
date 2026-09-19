"""Heuristic labeler for creating bot/human labels from log data.

Uses known bot signatures + timing patterns to create labels.
Labels are noisy but good enough for pre-training. Retrain on real data later.
"""

import re
from typing import NamedTuple

from .features import BROWSER_UA_RE, Session, SessionLike
from .parser import LogEntry
from .signals import EMPTY_SIGNALS, Signals

# High-confidence bot user agent patterns
HIGH_CONFIDENCE_BOT_PATTERNS = [
    r'curl', r'wget', r'python-requests', r'python-urllib',
    r'go-http-client', r'java/', r'perl', r'ruby', r'php/',
    r'scrapy', r'headless', r'phantom', r'selenium', r'puppeteer',
    r'playwright', r'httpclient', r'okhttp', r'apache-httpclient',
    r'mechanize', r'beautifulsoup', r'lxml', r'http\.client',
    r'bot\b', r'\bbot\b', r'spider', r'crawler', r'scraper',
    r'Uptime-Kuma', r'HetrixTools', r'Pingdom', r'UptimeRobot',
    r'Nagios', r'Zabbix', r'Prometheus', r'Grafana',
    r'Semrush', r'Ahrefs', r'MozBot', r'MJ12bot',
    r'Googlebot', r'Bingbot', r'YandexBot', r'DuckDuckBot',
    r'Applebot', r'Bytespider', r'GPTBot', r'CCBot',
    r'facebookexternalhit', r'Twitterbot', r'LinkedInBot',
    r'Masscan', r'Nmap', r'ZmEu', r'nikto', r'sqlmap',
    r'Havij', r'w3af', r'OpenVAS', r'Nessus', r'Qualys',
]

HIGH_CONF_BOT_RE = re.compile('|'.join(HIGH_CONFIDENCE_BOT_PATTERNS), re.IGNORECASE)


# --- Cloudflare WAF / CDN detection ---
# Requests that bypass Cloudflare (direct IP access) or hit protected endpoints
CLOUDFLARE_BYPASS_UA = [
    r'cf-', r'cloudflare', r'incapsula', r'akamai', r'sucuri', r'akamaighost',
]
CLOUDFLARE_BYPASS_RE = re.compile('|'.join(CLOUDFLARE_BYPASS_UA), re.IGNORECASE)

# Endpoints commonly behind Cloudflare WAF
CLOUDFLARE_PROTECTED_ENDPOINTS = [
    '/wp-admin', '/wp-login', '/wp-json', '/xmlrpc.php',
    '/.env', '/.git', '/config', '/debug', '/phpinfo',
    '/admin', '/dashboard', '/console', '/manager',
    '/.well-known', '/api/v1/auth', '/api/v2/auth',
]

# --- API key / credential scanning patterns ---
# Credential-bearing query parameters, and nothing else.
#
# Bare auth-ish PATHS used to live here too -- /signup, /register,
# /forgot-password, /token, /authenticate, /oauth2/, /api/.*auth -- and that
# conflated "this URL mentions authentication" with "this request is an
# attack". A browser loading /signup once matched at 1/1 = 100%, cleared the
# >0.5 ratio in _check_api_key_patterns, and after rule 11 was promoted from
# 0.75 to 0.90 it BLOCKED at the 0.85 live threshold: the first page of every
# signup funnel, every OAuth callback, every password reset.
#
# A credential in the query string is the actual signal. Brute force against
# an auth *endpoint* is still caught, by the two branches below that require
# repetition over time (BRUTE_FORCE_ENDPOINTS), which is what distinguishes an
# attack from a visit.
#
# Matched on [?&] rather than a bare ? so a credential in the second or later
# parameter counts -- `/x?page=2&token=...` was previously invisible here.
API_KEY_SCAN_PATTERNS = [
    r'[?&]key=', r'[?&]token=', r'[?&]api_key=', r'[?&]apikey=',
    r'[?&]access_token=', r'[?&]auth=', r'[?&]password=', r'[?&]pass=',
    r'[?&]secret=', r'[?&]credential=', r'[?&]jwt=', r'[?&]bearer=',
]
API_KEY_SCAN_RE = re.compile('|'.join(API_KEY_SCAN_PATTERNS), re.IGNORECASE)

# A ratio test over a tiny session says nothing: one request carrying a token
# is 100% of a one-request session. Rule 11 blocks at 0.90, so it needs enough
# requests for "most of this session is credential traffic" to be a finding
# rather than an artifact of the denominator.
MIN_CREDENTIAL_SCAN_REQUESTS = 5

# --- Known botnet / attack signatures ---
# Mirai and IoT botnet scanning patterns, anchored to the start of the path.
#
# These were unanchored substrings, and three of them matched the ordinary web:
#   \.php$  every page of a phpBB, WordPress, MediaWiki or Joomla site
#   \.asp$  every page of a classic ASP site
#   /adv    /advanced-search, /advertising, /advice
# With the 0.3 ratio in _check_botnet_signatures that returned bot 0.88, above
# the 0.85 live threshold, so a phpBB reader or anyone visiting /advanced-search
# was blocked. Verified before the fix:
#   ['/index.php', '/viewforum.php', '/viewtopic.php'] -> bot 0.88
#   ['/', '/advanced-search', '/advertising']          -> bot 0.88
#
# A Mirai probe requests these as whole paths, so anchoring costs no detection:
# /shell.cgi is still /shell.cgi. The page extensions are simply not botnet
# signatures and are gone.
BOTNET_URL_PATTERNS = [
    r'^/shell\.cgi', r'^/omega\.cgi', r'^/boaform',
    r'^/HNAP1?\b', r'^/tr069', r'^/goform', r'^/cgi-bin/luci',
    r'^/adv$', r'^/cpe$', r'^/device$',
    r'^/cmd$', r'^/system$', r'^/exec$', r'^/run$',
]
BOTNET_URL_RE = re.compile('|'.join(BOTNET_URL_PATTERNS), re.IGNORECASE)

# Below this many requests the 0.3 botnet ratio is measuring the denominator:
# one request to /cmd is 100% of a one-request session.
MIN_BOTNET_SCAN_REQUESTS = 3

# Above this many requests in one session, the client is not a person, whatever
# its timing or endpoint variety looks like.
#
# Measured against the 3,266 real Zanbil human sessions in
# data/realistic_training_data.json: p50 60, p95 345, p99 599, p99.9 1123,
# max 1497. At 2000 the rule flags 0 of them and catches 46 bot sessions
# (1.30%); at 300 it would have flagged 220 real humans (6.74%).
#
# Caveat for whoever retunes this: that human label is Zanbil's converting
# shoppers, roughly 0.80% of the actors in the log, so it is the best available
# distribution and not the whole human population. Revisit when the day-holdout
# re-measurement lands.
MAX_HUMAN_SESSION_REQUESTS = 2000

# Credential stuffing / brute-force patterns
BRUTE_FORCE_ENDPOINTS = [
    '/wp-login.php', '/wp-admin', '/xmlrpc.php',
    '/wp-json/wp/v2/users', '/?rest_route=/wp/v2/users',
    '/login', '/signin', '/auth', '/api/login',
    '/api/auth/login', '/api/v1/login', '/api/v2/login',
]

# Known attack tool signatures in user agents
ATTACK_TOOL_UA_PATTERNS = [
    r'Masscan', r'Nmap', r'ZmEu', r'nikto', r'sqlmap',
    r'Havij', r'w3af', r'OpenVAS', r'Nessus', r'Qualys',
    r'Wapiti', r'Arachni', r'DirBuster', r'Gobuster', r'Feroxbuster',
    r'wfuzz', r'Switchblade', r'Katory', r'fuzz',
    r'ZmEu', r'WinHTTP', r'WinInet',
    r'Nuclei', r'ffuf', r'feroxbuster',
    r'Go\s*net/http',  # Go HTTP client (common in attack tools)
]
ATTACK_TOOL_RE = re.compile('|'.join(ATTACK_TOOL_UA_PATTERNS), re.IGNORECASE)


# --- Single-endpoint API detection ---
# GraphQL, SOAP, and RPC-style APIs route every call through one path by
# design. "All requests hit the same endpoint" is a scraper signal for
# REST-style, path-per-resource APIs — it's just how these APIs work, and
# flagging it would brand every legitimate client as a bot.
SINGLE_ENDPOINT_API_PATTERNS = [
    r'/graphql', r'/graphiql', r'/trpc/', r'/rpc\b', r'/soap',
    r'/services/', r'\.asmx', r'/ws\b',
]
SINGLE_ENDPOINT_API_RE = re.compile('|'.join(SINGLE_ENDPOINT_API_PATTERNS), re.IGNORECASE)

# Rule 7 (high request rate) divides request_count by session duration. Below
# these floors the window is too narrow for the quotient to mean anything —
# five requests spanning 1.5ms extrapolate to ~200,000 req/min, which is a
# browser page load, not a flood.
MIN_RATE_WINDOW_S = 1.0
MIN_RATE_REQUESTS = 5

# AbuseIPDB reports a 0-100 confidence-of-abuse score. 75 is the value its own
# docs treat as 'probably malicious'; below that the reports are thin enough
# that a shared NAT address can accumulate one.
THREAT_INTEL_ABUSE_THRESHOLD = 75.0

# How long a session may run before a missing fingerprint means anything. A
# real browser POSTs within milliseconds of parsing the tag; this is room for a
# slow connection and a deferred script, not for the script itself.
FINGERPRINT_GRACE_SECONDS = 5.0
# And how many requests it must have made. One page view that never finished
# loading is not evidence of anything.
FINGERPRINT_MIN_REQUESTS = 3
# Distinct IPs sharing one fingerprint inside the submission window before it
# reads as a farm rather than a household behind one NAT.
SHARED_FINGERPRINT_IPS = 5

# Routes that would have served the script tag. A session that never touches
# one never had the chance to run the script, so its missing fingerprint says
# nothing -- a REST or GraphQL client is the obvious case, and flagging it
# would reintroduce the single-endpoint-API false positive this project has
# already fixed once.
API_ROUTE_RE = re.compile(
    r"^/(?:api|graphql|gql|rpc|v\d+|rest|oauth|auth|token|webhook)\b|"
    r"^/[A-Za-z0-9_.]+\.[A-Za-z0-9_]+/[A-Za-z0-9_]+$",
    re.IGNORECASE,
)
# Embedded subresources a browser fetches per page — matched by extension AND by
# common asset path prefixes, because many sites serve images without a file
# extension (e.g. Zanbil's `/image/60844/productModel/200x200`). Counting these
# as "requests" is what made the volume rules read a real shopper as a scraper.
STATIC_ASSET_RE = re.compile(
    r"(?:^|/)(?:images?|img|static|assets?|media|thumbnails?|thumbs?|icons?|"
    r"css|js|fonts?|avatars?|uploads?|cdn|sprites?)(?:/|$)"
    r"|\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp|avif|mp4|json|xml|txt)$"
    r"|/favicon\.ico$",
    re.IGNORECASE,
)

# gRPC calls are routed as POST /package.Service/Method — two path segments,
# method name capitalized by convention, no file extension.
GRPC_PATH_RE = re.compile(r'^/[\w.]+/[A-Z]\w*$')

# --- Known automated clients: webhooks + RPC/gRPC client libraries ---
# Neither has a human operator by definition — a webhook sender and a gRPC
# service client are both expected, legitimate automation, not a "bot" in
# the threat sense. Recognized senders get a distinct label instead of
# being scored as malicious or dinged by the generic "unknown UA" rule.
KNOWN_AUTOMATED_CLIENT_PATTERNS = [
    # Webhook / server-to-server integrations
    r'Stripe/\d', r'GitHub-Hookshot', r'Shopify', r'Slackbot-LinkExpanding',
    r'Slack-Webhooks', r'PayPal-IPN', r'Twilio', r'svix-webhooks',
    r'WhatsApp/', r'Zapier', r'HubSpot', r'Mailgun',
    # gRPC client library user agents (grpc-<lang>/<version>)
    r'grpc-go', r'grpc-java', r'grpc-python', r'grpc-node',
    r'grpc-c/', r'grpc-c\+\+', r'grpc-swift', r'grpc-dotnet', r'grpc-objc',
]
KNOWN_AUTOMATED_CLIENT_RE = re.compile('|'.join(KNOWN_AUTOMATED_CLIENT_PATTERNS), re.IGNORECASE)


def _check_cloudflare_signals(session: SessionLike) -> tuple[bool, str]:
    """Check for Cloudflare WAF bypass or protection signals.
    
    Returns:
        (is_bot, reason)
    """
    entries = session.requests
    ua = session.user_agent.lower()
    urls = [e.url.split('?')[0] for e in entries]
    
    # Cloudflare-specific UA patterns (bypassing WAF)
    if CLOUDFLARE_BYPASS_RE.search(ua):
        return True, 'Cloudflare WAF bypass UA detected'
    
    # Requests targeting Cloudflare-protected endpoints with no referrer
    no_referrer = sum(1 for e in entries if e.referer in ('-', '', 'none'))
    protected_hits = sum(
        1 for url in urls
        if any(p in url.lower() for p in CLOUDFLARE_PROTECTED_ENDPOINTS)
    )
    if protected_hits > 0 and no_referrer == len(entries):
        return True, f'WAF-protected endpoint scan ({protected_hits} hits, no referrer)'
    
    return False, ''


class _Volume(NamedTuple):
    """Everything the volume rules are allowed to count, computed once.

    Five rules ask "how much traffic was this?" and each used to derive its own
    answer from raw fields. That is how commit b2edd14 wired page-like counting
    into rules 5, 7 and 12 and missed rule 13, which kept counting a browser's
    image subrequests and so kept labelling a 3am shopper a bot -- the exact
    false positive that commit set out to remove. One source, computed here, so
    a rule cannot reach for the raw field by accident.

        entries ──┬─> requests      raw total, embedded assets included
                  ├─> pages         non-asset requests: what "volume" means
                  ├─> night_pages   pages timestamped 02:00-05:59
                  └─> duration      seconds, first request to last

    `pages` can be 0 for a session that is entirely assets, so any ratio over
    it must guard against that. `requests` is never 0 (an empty session
    returns before this is built).
    """

    requests: int
    pages: int
    night_pages: int
    duration: float


def _volume_of(
    entries: list[LogEntry], urls: list[str], duration: float
) -> _Volume:
    """Count a session's traffic once, for every volume rule to share."""
    page_flags = [not STATIC_ASSET_RE.search(u) for u in urls]
    return _Volume(
        requests=len(entries),
        pages=sum(page_flags),
        night_pages=sum(
            1
            for entry, is_page in zip(entries, page_flags)
            if is_page and 2 <= entry.timestamp.hour < 6
        ),
        duration=duration,
    )


def _check_api_key_patterns(session: SessionLike) -> tuple[bool, str]:
    """Check for API key scanning or credential brute-force patterns.
    
    Returns:
        (is_bot, reason)
    """
    entries = session.requests
    urls = [e.url for e in entries]
    
    # API key parameter scanning. The request floor is load-bearing, not
    # defensive: without it a single request carrying a credential param is
    # 1/1 = 100% and trips a rule that blocks at 0.90.
    key_param_hits = sum(1 for url in urls if API_KEY_SCAN_RE.search(url))
    if (len(entries) >= MIN_CREDENTIAL_SCAN_REQUESTS
            and key_param_hits / len(entries) > 0.5):
        return True, f'API key parameter scanning ({key_param_hits}/{len(entries)} requests)'
    
    # Credential brute-force (rapid attempts to auth endpoints)
    auth_hits = sum(
        1 for url in urls
        if any(ep in url.lower() for ep in BRUTE_FORCE_ENDPOINTS)
    )
    if auth_hits >= 5 and session.duration < 300:
        rate = auth_hits / (session.duration / 60.0) if session.duration > 0 else 999
        if rate > 5:
            return True, f'credential brute-force ({auth_hits} auth attempts in {session.duration:.0f}s)'
    
    # Rapid POST to auth endpoints
    post_auth = sum(
        1 for e in entries
        if e.method == 'POST' and any(ep in e.url.lower() for ep in BRUTE_FORCE_ENDPOINTS)
    )
    if post_auth >= 10:
        return True, f'POST brute-force ({post_auth} POST to auth endpoints)'
    
    return False, ''


def _check_botnet_signatures(session: SessionLike) -> tuple[bool, str]:
    """Check for known botnet and attack tool signatures.
    
    Returns:
        (is_bot, reason)
    """
    entries = session.requests
    ua = session.user_agent.lower()
    # Query strings stripped: the patterns are anchored whole paths, so /adv?x=1
    # must still match /adv. _check_cloudflare_signals strips for the same reason.
    urls = [e.url.split('?')[0] for e in entries]

    # Known attack tools
    if ATTACK_TOOL_RE.search(ua):
        return True, f'attack tool UA: {session.user_agent[:50]}'

    # Botnet URL patterns (Mirai, IoT scanning)
    # Two hits minimum, not one. Anchoring fixed the ordinary-web matches, but
    # /system, /cmd, /exec and /run are still plausible application paths, and a
    # single hit in a three-request session clears a 0.3 ratio: ['/', '/system',
    # '/status'] was blocked at 0.88. A router sweep probes several endpoints;
    # one path that happens to share a name with a Mirai target is not a sweep.
    botnet_hits = sum(1 for url in urls if BOTNET_URL_RE.search(url))
    if (botnet_hits >= 2
            and len(entries) >= MIN_BOTNET_SCAN_REQUESTS
            and botnet_hits / len(entries) > 0.3):
        return True, f'botnet scanning pattern ({botnet_hits} IoT endpoint hits)'
    
    # High-volume scanning with 403/404 responses (directory brute-force)
    errors_4xx = sum(1 for e in entries if 400 <= e.status < 500)
    if errors_4xx / len(entries) > 0.7 and session.request_count > 30:
        return True, f'directory brute-force ({errors_4xx}/{len(entries)} 4xx responses)'
    
    # User-agent rotation (common in distributed attacks). Requires at
    # least 2 variants — a single UA can't "rotate", and the scaled
    # threshold below 1 for request_count < 4 would otherwise flag every
    # single-UA session regardless of actual diversity.
    ua_variants = {e.user_agent for e in entries}
    if len(ua_variants) >= 2 and len(ua_variants) > min(10, session.request_count * 0.3):
        return True, f'UA rotation ({len(ua_variants)} variants in {session.request_count} requests)'
    
    return False, ''


def _looks_like_page_traffic(urls: list[str]) -> bool:
    """Whether this actor ever requested something that serves HTML.

    Any single page request is enough: that is where the script tag lives, so
    one is all it takes for a real browser to have had the chance to run it.
    Requiring more would exempt a bot that loads exactly one page.
    """
    return any(
        not API_ROUTE_RE.search(url) and not STATIC_ASSET_RE.search(url)
        for url in urls
    )


def _check_fingerprint_signals(
    session: SessionLike, signals: Signals, urls: list[str]
) -> tuple[bool, float, str]:
    """Verdict from client-side fingerprint evidence.

    Two rules of opposite kinds. Rule 2 is positive evidence -- one browser
    profile arriving from many addresses -- and applies to any session. Rule 1
    is an inference from ABSENCE, which is far weaker and far easier to get
    wrong, so it is gated three ways: the pipeline must actually have been
    consulted, the session must have had a real chance to run the script, and
    it must have had time to.
    """
    if not signals.is_promoted("fingerprint"):
        return False, 0.0, ""

    if signals.shared_hash_ips >= SHARED_FINGERPRINT_IPS:
        return (
            True,
            0.90,
            f"one browser fingerprint across {signals.shared_hash_ips} distinct IPs",
        )

    if (
        signals.fingerprint_hash is None
        and session.request_count >= FINGERPRINT_MIN_REQUESTS
        and session.duration >= FINGERPRINT_GRACE_SECONDS
        and _looks_like_page_traffic(urls)
    ):
        return (
            True,
            0.80,
            f"no fingerprint after {session.duration:.0f}s of page traffic",
        )

    return False, 0.0, ""


def _check_threat_intel_signals(signals: Signals) -> tuple[bool, float, str]:
    """Verdict from externally resolved reputation data, if any applies.

    Reads only from `signals`. It never looks anything up: this runs inline on
    every nginx `auth_request`, and a lookup here would put a network round
    trip in front of a real visitor.

    Two gates before any source is consulted, both inside `is_promoted`:
    the data must have actually been resolved (in a batch scan it never is),
    and the deployment must have promoted that source out of observe-only.

    Returns (matched, confidence, reason).
    """
    if signals.is_promoted("tor") and signals.tor_exit:
        # Not 0.90. Real people use Tor, so this blocks only when the model
        # agrees: compute_combined_score floors a confident bot at its own
        # confidence, and the live threshold is a strict `> 0.85`.
        return True, 0.85, "Tor exit node"

    if (
        signals.is_promoted("abuseipdb")
        and signals.abuse_score is not None
        and signals.abuse_score >= THREAT_INTEL_ABUSE_THRESHOLD
    ):
        return True, 0.90, f"AbuseIPDB abuse score {signals.abuse_score:.0f}"

    # `signals.hosting_range` is deliberately not enforced. A datacenter IP is
    # weak evidence on its own -- plenty of legitimate API clients live there --
    # and spec 0002 left the combination rule open precisely because choosing
    # it needs real traffic rather than a guess. It is resolved and recorded so
    # the evidence can be gathered; it decides nothing until it can be.
    return False, 0.0, ""


def label_session(
    session: SessionLike, signals: Signals = EMPTY_SIGNALS
) -> tuple[str, float, str]:
    """Label a session as 'bot', 'human', or 'automated-integration' with confidence.

    Returns:
        (label, confidence, reason)
        label: 'bot', 'human', or 'automated-integration' (recognized
               webhook/server-to-server senders — automated by definition,
               but not a security threat, so kept distinct from 'bot')
        confidence: 0.0 to 1.0
        reason: human-readable explanation
    """
    if session.request_count == 0:
        return 'human', 0.5, 'empty session'
    
    entries = session.requests
    ua = session.user_agent.lower()
    urls = [e.url.split('?')[0] for e in entries]

    # Every volume rule below reads from this and nothing else. See _Volume.
    volume = _volume_of(entries, urls, session.duration)

    # === KNOWN AUTOMATED INTEGRATIONS (not a threat signal) ===

    # 0. Recognized webhook/integration sender — automated by definition,
    # but not a security threat. Checked first so it isn't caught by the
    # broader bot-signal rules below.
    if KNOWN_AUTOMATED_CLIENT_RE.search(ua):
        return 'automated-integration', 0.90, f'known automated client (webhook/RPC): {session.user_agent[:50]}'

    # === HIGH CONFIDENCE BOT SIGNALS (0.90-0.99) ===

    # 1. Known bot/monitoring user agent
    if HIGH_CONF_BOT_RE.search(ua):
        return 'bot', 0.95, f'known bot/monitoring UA: {session.user_agent[:50]}'
    
    # 2. Known vulnerability scanner patterns in URL.
    #
    # Only paths a browser never requests in the course of using a site, so a
    # single hit stays sufficient. A ratio gate would be the wrong instrument
    # here: it would let an attacker hide one /.env probe behind a handful of
    # ordinary requests.
    #
    # Removed, with reasons, because each matched ordinary traffic and this
    # rule returns 0.95 -- well above the 0.85 live threshold:
    #   /wp-content, /wp-includes  WordPress serves every theme stylesheet and
    #                              every upload from these. Verified: a visitor
    #                              loading ['/', '/wp-content/themes/x/style.css']
    #                              was blocked at 0.95.
    #   /config.json               a common SPA boot file. ['/', '/config.json',
    #                              '/app/home'] was blocked at 0.95.
    #   /admin/login, /wp-admin,   a human administrator signing in. These stay
    #   /wp-login                  covered by rule 5 below, which gates the same
    #                              endpoints on no-referrer-across-the-whole-
    #                              session: an admin browsing has a referer
    #                              chain, a scanner sweeping them has none.
    scanner_patterns = ['/phpmyadmin', '/.env', '/.git', '/phpinfo',
                        '/xmlrpc.php', '/cgi-bin']
    if any(any(p in url.lower() for p in scanner_patterns) for url in urls):
        return 'bot', 0.95, 'vulnerability scanner pattern detected'
    
    # 3. Extremely uniform timing (all requests within 1ms of each other)
    if session.request_count >= 5:
        timestamps = sorted([e.timestamp for e in entries])
        gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                for i in range(len(timestamps)-1)]
        if gaps:
            avg_gap = sum(gaps) / len(gaps)
            max_gap = max(gaps)
            min_gap = min(gaps)
            # All gaps nearly identical = bot — unless this looks like
            # multiplexed gRPC traffic (many distinct /Service/Method paths
            # pipelined over one HTTP/2 connection), where uniform timing is
            # expected from real clients, not a bot signal.
            grpc_like = len({u for u in urls if GRPC_PATH_RE.match(u)}) >= 3
            if avg_gap > 0 and (max_gap - min_gap) / avg_gap < 0.05 and not grpc_like:
                return 'bot', 0.90, f'uniform timing (avg {avg_gap:.3f}s, near-zero variance)'
    
    # 4. HTTP/1.0 only (no modern browser uses this)
    if all(e.raw_line and 'HTTP/1.0' in e.raw_line for e in entries) and session.request_count > 5:
        return 'bot', 0.90, 'all requests use HTTP/1.0 (not a modern browser)'
    
    # 5. Cloudflare WAF bypass / protected endpoint scanning
    cf_bot, cf_reason = _check_cloudflare_signals(session)
    if cf_bot:
        return 'bot', 0.90, f'Cloudflare WAF: {cf_reason}'
    
    # 6. Known attack tool user agent
    if ATTACK_TOOL_RE.search(ua):
        return 'bot', 0.90, f'attack tool detected: {session.user_agent[:50]}'
    
    # 7. Botnet scanning patterns (Mirai, IoT)
    botnet_bot, botnet_reason = _check_botnet_signatures(session)
    if botnet_bot:
        return 'bot', 0.88, botnet_reason

    # 8. Externally resolved reputation, checked here rather than higher up.
    # Chain order is semantics in this function, and everything above is a
    # direct local observation of this actor's own traffic. A third-party
    # lookup should not be able to relabel one of those.
    ti_bot, ti_conf, ti_reason = _check_threat_intel_signals(signals)
    if ti_bot:
        return 'bot', ti_conf, f'threat intel: {ti_reason}'

    # 9. Client-side fingerprint evidence, checked alongside threat intel for
    # the same reason: a direct observation of this actor's own traffic should
    # not be relabelled by a signal resolved somewhere else.
    fp_bot, fp_conf, fp_reason = _check_fingerprint_signals(session, signals, urls)
    if fp_bot:
        return 'bot', fp_conf, f'fingerprint: {fp_reason}'

    # === MEDIUM CONFIDENCE BOT SIGNALS (0.70-0.89) ===
    
    # 5. Very high request rate (>100 non-asset requests in session)
    if volume.pages > 100:
        return 'bot', 0.85, f'extremely high request count: {volume.pages} pages'

    # 5b. Raw request volume, embedded assets included.
    #
    # Rules 5, 7 and 12 count pages on purpose: that is what stops a browser's
    # subresource loads reading as a flood. The cost is that a session made
    # ENTIRELY of asset-shaped URLs has volume.pages == 0 and is invisible to
    # all three. STATIC_ASSET_RE matches `.json$` and the segments /media/,
    # /uploads/, /cdn/ and /static/, so a JSON-API or image scrape hit 3,000
    # requests, fell through to the human rules below, and scoring.py then
    # capped its blended score at 1 - 0.70 = 0.30: unblockable at any model
    # score.
    #
    # This is the floor under that. See MAX_HUMAN_SESSION_REQUESTS for the
    # measurement behind the number.
    # 0.90, not 0.85: scorer.py:380 blocks on `combined > threshold` with a
    # default threshold of 0.85, so a rule returning exactly 0.85 only blocks
    # when the model happens to push it over, and P2-14 measured the shipped
    # model's scores as rarely high enough to do that. A backstop that blocks
    # conditionally is not a backstop. The number is carried by the
    # measurement: 0 of 3,266 real human sessions reach this volume.
    if volume.requests > MAX_HUMAN_SESSION_REQUESTS:
        return 'bot', 0.90, (
            f'extremely high raw request count: {volume.requests} requests'
        )
    
    # 6. All requests to same endpoint (scraper pattern) — not for
    # single-endpoint APIs (GraphQL/SOAP/RPC), where this is normal.
    unique_urls = set(urls)
    if (len(unique_urls) == 1 and session.request_count > 10
            and not SINGLE_ENDPOINT_API_RE.search(urls[0])):
        return 'bot', 0.80, f'all {session.request_count} requests to same endpoint: {urls[0]}'
    
    # 7. High request rate (>50 req/min sustained)
    # "Sustained" needs a window wide enough to mean something. A browser
    # loading one page fires its subresource requests within a few
    # milliseconds; dividing by that window extrapolates to six figures per
    # minute and blocks a real visitor. Batch scans never hit this because
    # nginx log timestamps are second-granular (duration == 0, rule skipped),
    # but the live path uses time.time() and trips it on every page load.
    # Rate over non-asset requests: a browser firing image subrequests is not
    # a high request rate in the sense this rule means.
    if volume.duration >= MIN_RATE_WINDOW_S and volume.pages >= MIN_RATE_REQUESTS:
        rate = volume.pages / (volume.duration / 60.0)
        if rate > 50:
            return 'bot', 0.75, f'high request rate: {rate:.1f} pages/min'
    
    # 8. No referrer on all requests (direct API hits)
    no_referrer = sum(1 for e in entries if e.referer in ('-', '', 'none'))
    if no_referrer == len(entries) and session.request_count > 20:
        return 'bot', 0.70, f'no referrer on all {session.request_count} requests'
    
    # 9. High error rate (>50% 4xx/5xx responses)
    errors = sum(1 for e in entries if e.status >= 400)
    if errors / len(entries) > 0.5 and session.request_count > 10:
        return 'bot', 0.70, f'high error rate: {errors}/{len(entries)} failed requests'
    
    # 10. Repeated same endpoint with different parameters (API abuse) —
    # not for single-endpoint APIs, same exemption as rule 6.
    from collections import Counter
    path_counts = Counter(urls)
    most_common_path, most_common_count = path_counts.most_common(1)[0] if path_counts else ('', 0)
    if (most_common_count > 20 and most_common_count / len(entries) > 0.7
            and not SINGLE_ENDPOINT_API_RE.search(most_common_path)):
        return 'bot', 0.70, f'repeated endpoint hit {most_common_count} times'
    
    # 11. API key scanning / credential brute-force. High confidence, not
    # medium: every branch of _check_api_key_patterns is unambiguously an
    # attack (>50% of requests carrying a credential param, 5+ rapid auth
    # attempts, or 10+ POSTs to auth endpoints) — no human or legitimate
    # client does this. At 0.75 the rule could never block at the 0.85 live
    # threshold; at 0.90 it clears the bar and the credential-stuffing case the
    # benchmark showed the blend discarding is caught, with no human-FP risk.
    api_bot, api_reason = _check_api_key_patterns(session)
    if api_bot:
        return 'bot', 0.90, api_reason
    
    # === LOW CONFIDENCE BOT SIGNALS (0.55-0.69) ===
    
    # 11. Unknown user agent (not a known browser)
    if ua and ua != '-' and not BROWSER_UA_RE.search(ua) and session.request_count > 5:
        return 'bot', 0.60, f'unknown user-agent: {session.user_agent[:50]}'
    
    # 12. Very short session with many non-asset requests (< 5 seconds, > 20)
    if volume.duration < 5.0 and volume.pages > 20:
        return 'bot', 0.65, f'{volume.pages} pages in {volume.duration:.1f}s'
    
    # 13. Night-time activity (2am-6am) with high volume. Counts pages, not
    # raw requests, for the same reason as rules 5, 7 and 12: a shopper who
    # loads one rich page at 3am fires dozens of image subrequests, and
    # counting those made this rule report a real human as a bot at 0.60.
    # `volume.pages` is 0 for an all-asset session, hence the guard.
    if (volume.pages > 30
            and volume.night_pages / volume.pages > 0.5):
        return 'bot', 0.60, f'mostly night-time activity ({volume.night_pages}/{volume.pages} pages)'
    
    # === HUMAN SIGNALS (0.55-0.75) ===
    #
    # Every rule below is bounded by MAX_HUMAN_SESSION_REQUESTS. A confident
    # human verdict is not a neutral outcome: scoring.py caps the blended score
    # at 1 - confidence for a human label, so rule 16 returning 0.70 on a
    # 3,000-request scrape pinned it at 0.30 and made it unblockable whatever
    # the model said. Rule 5b above catches those first now; this bound is the
    # second half of the same fix, so a large session can never acquire a
    # confident human label on timing or endpoint variety alone. Past the
    # bound, the chain falls through to the 0.50 "no strong signals" default,
    # which is the honest answer: these rules recognise a visitor, and this is
    # not one.
    human_plausible = volume.requests <= MAX_HUMAN_SESSION_REQUESTS

    # 15. Known browser user agent with normal behavior
    if BROWSER_UA_RE.search(ua) and session.request_count < 50 and session.duration > 30:
        return 'human', 0.75, f'known browser, reasonable session ({session.request_count} req, {session.duration:.0f}s)'
    
    # 16. Variable timing pattern (high CV)
    if human_plausible and session.request_count >= 3:
        timestamps = sorted([e.timestamp for e in entries])
        gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                for i in range(len(timestamps)-1)]
        if gaps:
            avg_gap = sum(gaps) / len(gaps)
            max_gap = max(gaps)
            if avg_gap > 0 and max_gap / avg_gap > 3.0:
                return 'human', 0.70, f'variable timing (max/avg ratio: {max_gap/avg_gap:.1f})'
    
    # 17. Multiple different endpoints explored (browsing pattern)
    if human_plausible and len(unique_urls) >= 5 and session.request_count >= 5:
        return 'human', 0.65, f'exploring {len(unique_urls)} different endpoints'
    
    # 18. Has referer chain (natural navigation)
    has_referer = sum(1 for e in entries if e.referer not in ('-', '', 'none'))
    if (human_plausible and has_referer > len(entries) * 0.5
            and session.request_count >= 3):
        return 'human', 0.60, f'natural navigation with {has_referer} referrers'
    
    # 19. Behind Cloudflare with normal browser (likely real user)
    #
    # UNREACHABLE. Rule 5 above returns bot at 0.90 for ANY user agent matching
    # CLOUDFLARE_BYPASS_RE, so no session that satisfies the first condition
    # here ever gets this far. The rule was meant to protect a real visitor
    # whose UA carries a CDN marker; today that visitor is labeled a bot
    # instead. Left in place rather than deleted because the intent is right
    # and the fix is a behavior change — see CHANGELOG.
    if CLOUDFLARE_BYPASS_RE.search(ua) and BROWSER_UA_RE.search(ua) and session.request_count < 30:  # pragma: no cover
        return 'human', 0.65, 'Cloudflare-protected site, normal browser'
    
    # === DEFAULT ===
    
    # If we can't tell, lean toward human (avoid false positives)
    return 'human', 0.50, 'no strong signals either way'


def label_entries(
    entries: list[LogEntry],
    timeout_minutes: int = 30
) -> list[tuple[Session, str, float, str]]:
    """Label all sessions in a list of log entries.
    
    Returns:
        List of (session, label, confidence, reason) tuples
    """
    from .features import group_into_sessions
    
    sessions = group_into_sessions(entries, timeout_minutes)
    results = []
    
    for session in sessions:
        label, confidence, reason = label_session(session)
        results.append((session, label, confidence, reason))
    
    return results
