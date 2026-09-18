"""Heuristic labeler for creating bot/human labels from log data.

Uses known bot signatures + timing patterns to create labels.
Labels are noisy but good enough for pre-training. Retrain on real data later.
"""

import re

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
# Bot patterns targeting authentication endpoints
API_KEY_SCAN_PATTERNS = [
    r'\?key=', r'\?token=', r'\?api_key=', r'\?apikey=',
    r'\?access_token=', r'\?auth=', r'\?password=', r'\?pass=',
    r'\?secret=', r'\?credential=', r'\?jwt=', r'\?bearer=',
    r'/api/.*key', r'/api/.*token', r'/api/.*auth', r'/api/.*login',
    r'/oauth2?/', r'/jwt/', r'/token', r'/authenticate',
    r'/signup', r'/register', r'/forgot-password',
    r'/_debug',
]
API_KEY_SCAN_RE = re.compile('|'.join(API_KEY_SCAN_PATTERNS), re.IGNORECASE)

# --- Known botnet / attack signatures ---
# Mirai and IoT botnet scanning patterns
BOTNET_URL_PATTERNS = [
    r'/shell\.cgi', r'/omega\.cgi', r'/adv', r'/boaform',
    r'/HNAP1', r'/tr069', r'/cpe', r'/device',
    r'/HNAP', r'/goform', r'/cgi-bin/luci',
    r'\.asp$', r'\.cgi$', r'\.php$',  # common IoT endpoints
    r'/cmd', r'/system', r'/exec', r'/run',
]
BOTNET_URL_RE = re.compile('|'.join(BOTNET_URL_PATTERNS), re.IGNORECASE)

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


def _check_api_key_patterns(session: SessionLike) -> tuple[bool, str]:
    """Check for API key scanning or credential brute-force patterns.
    
    Returns:
        (is_bot, reason)
    """
    entries = session.requests
    urls = [e.url for e in entries]
    
    # API key parameter scanning
    key_param_hits = sum(1 for url in urls if API_KEY_SCAN_RE.search(url))
    if key_param_hits > 0 and key_param_hits / len(entries) > 0.5:
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
    urls = [e.url for e in entries]
    
    # Known attack tools
    if ATTACK_TOOL_RE.search(ua):
        return True, f'attack tool UA: {session.user_agent[:50]}'
    
    # Botnet URL patterns (Mirai, IoT scanning)
    botnet_hits = sum(1 for url in urls if BOTNET_URL_RE.search(url))
    if botnet_hits > 0 and botnet_hits / len(entries) > 0.3:
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

    # Requests that are not embedded static assets. The volume rules below
    # count these, not the raw request total: a real browser loading one rich
    # page fires dozens of image/CSS/JS subrequests, so raw count reads a
    # normal visitor as a high-volume scraper. Measured on real e-commerce
    # traffic (Zanbil), the raw-count rule flagged 57% of genuine human
    # shoppers. A page/endpoint scraper still hits many non-assets and is still
    # caught. See docs/results/2026-09-benchmark.md.
    page_like_count = sum(1 for u in urls if not STATIC_ASSET_RE.search(u))

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
    
    # 2. Known vulnerability scanner patterns in URL
    scanner_patterns = ['/wp-admin', '/wp-login', '/phpmyadmin', '/.env',
                       '/config.json', '/admin/login', '/xmlrpc.php',
                       '/wp-content', '/wp-includes', '/cgi-bin']
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
    if page_like_count > 100:
        return 'bot', 0.85, f'extremely high request count: {page_like_count} pages'
    
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
    if session.duration >= MIN_RATE_WINDOW_S and page_like_count >= MIN_RATE_REQUESTS:
        rate = page_like_count / (session.duration / 60.0)
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
    
    # 11. API key scanning / credential brute-force
    api_bot, api_reason = _check_api_key_patterns(session)
    if api_bot:
        return 'bot', 0.75, api_reason
    
    # === LOW CONFIDENCE BOT SIGNALS (0.55-0.69) ===
    
    # 11. Unknown user agent (not a known browser)
    if ua and ua != '-' and not BROWSER_UA_RE.search(ua) and session.request_count > 5:
        return 'bot', 0.60, f'unknown user-agent: {session.user_agent[:50]}'
    
    # 12. Very short session with many non-asset requests (< 5 seconds, > 20)
    if session.duration < 5.0 and page_like_count > 20:
        return 'bot', 0.65, f'{page_like_count} pages in {session.duration:.1f}s'
    
    # 13. Night-time activity (2am-6am) with high volume
    night_count = sum(1 for e in entries if 2 <= e.timestamp.hour < 6)
    if night_count / len(entries) > 0.5 and session.request_count > 30:
        return 'bot', 0.60, f'mostly night-time activity ({night_count}/{len(entries)} requests)'
    
    # === HUMAN SIGNALS (0.55-0.75) ===
    
    # 15. Known browser user agent with normal behavior
    if BROWSER_UA_RE.search(ua) and session.request_count < 50 and session.duration > 30:
        return 'human', 0.75, f'known browser, reasonable session ({session.request_count} req, {session.duration:.0f}s)'
    
    # 16. Variable timing pattern (high CV)
    if session.request_count >= 3:
        timestamps = sorted([e.timestamp for e in entries])
        gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                for i in range(len(timestamps)-1)]
        if gaps:
            avg_gap = sum(gaps) / len(gaps)
            max_gap = max(gaps)
            if avg_gap > 0 and max_gap / avg_gap > 3.0:
                return 'human', 0.70, f'variable timing (max/avg ratio: {max_gap/avg_gap:.1f})'
    
    # 17. Multiple different endpoints explored (browsing pattern)
    if len(unique_urls) >= 5 and session.request_count >= 5:
        return 'human', 0.65, f'exploring {len(unique_urls)} different endpoints'
    
    # 18. Has referer chain (natural navigation)
    has_referer = sum(1 for e in entries if e.referer not in ('-', '', 'none'))
    if has_referer > len(entries) * 0.5 and session.request_count >= 3:
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
