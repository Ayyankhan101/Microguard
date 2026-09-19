"""HTTP scanner for live URL probing.

Makes requests to a target URL and extracts bot-detection features
from the response. No external dependencies — uses stdlib only.
"""

import base64
import hashlib
import math
import os
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field

from .report import score_label, score_label_color

# RFC 6455 fixed handshake GUID
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass
class ProbeResult:
    """Result of probing a single URL."""
    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timing: dict[str, float] = field(default_factory=dict)
    error: str | None = None
    
    # Extracted features (populated by extract_probe_features)
    features: dict[str, float] = field(default_factory=dict)
    
    @property
    def body_text(self) -> str:
        try:
            return self.body.decode('utf-8', errors='replace')
        except Exception:  # noqa: BLE001 — malformed bytes fall back to empty string
            return ""


def _shannon_entropy(data) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _timing_pattern_consistency(timings: list[float]) -> float:
    """Measure consistency of timing pattern (low CV = bot-like)."""
    if len(timings) < 2:
        return 0.0
    mean = sum(timings) / len(timings)
    if mean == 0:
        return 0.0
    variance = sum((t - mean) ** 2 for t in timings) / len(timings)
    std = math.sqrt(variance)
    cv = std / mean if mean > 0 else 0.0
    return cv


def probe_url(
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
    user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    headers: dict[str, str] | None = None,
) -> ProbeResult:
    """Probe a live URL and capture response details.
    
    Args:
        url: Target URL to probe
        method: HTTP method (GET, POST, etc.)
        timeout: Request timeout in seconds
        user_agent: User-Agent header to send
        follow_redirects: Whether to follow HTTP redirects
        verify_ssl: Whether to verify SSL certificates
        headers: Additional headers to send
    
    Returns:
        ProbeResult with response data and timing
    """
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Build request headers
    req_headers = {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'identity',
        'Connection': 'close',
    }
    if headers:
        req_headers.update(headers)
    
    req = urllib.request.Request(url, method=method, headers=req_headers)
    
    # SSL context
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context()
    
    # Build opener with handlers
    handlers: list[urllib.request.BaseHandler] = []
    
    # HTTPS handler with SSL context
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    handlers.append(https_handler)
    
    if not follow_redirects:
        # Disable redirect following
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(newurl, code, msg, headers, fp)
        handlers.append(NoRedirect())
    
    opener = urllib.request.build_opener(*handlers)
    
    result = ProbeResult(url=url)
    
    try:
        # Measure timing. perf_counter, not time(): every value below is an
        # elapsed span, and time() has a ~15.6ms resolution on Windows, so a
        # loopback probe finishing inside one tick reports exactly 0.0.
        t_start = time.perf_counter()
        try:
            response = opener.open(req, timeout=timeout)
            t_connected = time.perf_counter()
            
            # Read response body
            body = response.read(1024 * 1024)  # Max 1MB
            t_complete = time.perf_counter()
            
            result.status_code = response.status
            result.headers = dict(response.headers)
            result.body = body
            result.timing = {
                'dns': t_connected - t_start,  # Approximate
                'connect': 0.0,  # Not easily separable with urllib
                'ttfb': t_connected - t_start,
                'total': t_complete - t_start,
                'transfer': t_complete - t_connected,
            }
        except urllib.error.HTTPError as e:
            t_error = time.perf_counter()
            result.status_code = e.code
            result.headers = dict(e.headers) if e.headers else {}
            result.timing = {
                'dns': 0.0,
                'connect': 0.0,
                'ttfb': 0.0,
                'total': t_error - t_start,
                'transfer': 0.0,
            }
        except urllib.error.URLError as e:
            result.error = str(e.reason)
            result.timing = {'total': time.perf_counter() - t_start}
    
    except Exception as e:  # noqa: BLE001 — probe result surfaces any failure via result.error
        result.error = str(e)
        result.timing = {'total': time.perf_counter() - t_start}
    
    return result


def probe_url_multiple(
    url: str,
    count: int = 1,
    delay: float = 0.0,
    method: str = "GET",
    timeout: float = 10.0,
    user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    randomize_ua: bool = False,
) -> list[ProbeResult]:
    """Probe a URL multiple times to detect timing patterns.
    
    Args:
        url: Target URL to probe
        count: Number of probes to send
        delay: Delay between probes in seconds
        method: HTTP method
        timeout: Request timeout
        user_agent: User-Agent header
        randomize_ua: Rotate through common browser UAs
    
    Returns:
        List of ProbeResult objects
    """
    user_agents = [
        user_agent,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ]
    
    results = []
    for i in range(count):
        ua = user_agents[i % len(user_agents)] if randomize_ua else user_agent
        result = probe_url(url, method=method, timeout=timeout, user_agent=ua)
        results.append(result)
        
        if delay > 0 and i < count - 1:
            time.sleep(delay)
    
    return results


def extract_probe_features(results: list[ProbeResult]) -> dict[str, float]:
    """Extract bot-detection features from probe results.
    
    Features extracted:
    - response_time: Total response time (seconds)
    - ttfb: Time to first byte (seconds)
    - status_code: HTTP status code (normalized 0-1)
    - header_count: Number of response headers (normalized)
    - body_entropy: Shannon entropy of response body
    - has_server_header: 1.0 if Server header present
    - has_x_powered_by: 1.0 if X-Powered-By header present
    - has_content_security_policy: 1.0 if CSP header present
    - has_x_frame_options: 1.0 if X-Frame-Options present
    - has_strict_transport: 1.0 if HSTS header present
    - timing_cv: Coefficient of variation of response times
    - body_length: Response body length (normalized)
    - redirect_count: Number of redirects followed
    - has_accept_language: 1.0 if response suggests content negotiation
    
    Args:
        results: List of ProbeResult objects (1 for single, N for multi)
    
    Returns:
        Dictionary of feature name -> value
    """
    if not results:
        return {}
    
    first = results[0]
    features = {}
    
    # --- Timing features ---
    features['response_time'] = first.timing.get('total', 0.0)
    features['ttfb'] = first.timing.get('ttfb', 0.0)
    
    # Timing consistency (multiple probes)
    if len(results) > 1:
        timings = [r.timing.get('total', 0.0) for r in results]
        features['timing_cv'] = _timing_pattern_consistency(timings)
    else:
        features['timing_cv'] = 0.0
    
    # --- Response features ---
    features['status_code'] = first.status_code / 1000.0  # Normalize to 0-1
    features['header_count'] = min(len(first.headers) / 20.0, 1.0)  # Normalize
    features['body_entropy'] = _shannon_entropy(first.body)
    features['body_length'] = min(len(first.body) / (1024 * 100), 1.0)  # Normalize to 100KB
    
    # --- Security header detection ---
    headers_lower = {k.lower(): v for k, v in first.headers.items()}
    
    features['has_server_header'] = 1.0 if 'server' in headers_lower else 0.0
    features['has_x_powered_by'] = 1.0 if 'x-powered-by' in headers_lower else 0.0
    features['has_content_security_policy'] = 1.0 if 'content-security-policy' in headers_lower else 0.0
    features['has_x_frame_options'] = 1.0 if 'x-frame-options' in headers_lower else 0.0
    features['has_strict_transport'] = 1.0 if 'strict-transport-security' in headers_lower else 0.0
    
    # --- Content features ---
    body_text = first.body_text.lower()
    features['has_accept_language'] = 1.0 if 'lang=' in body_text or 'language' in body_text else 0.0
    
    # --- Redirect detection ---
    redirect_count = 0
    for r in results:
        if r.status_code in (301, 302, 303, 307, 308):
            redirect_count += 1
    features['redirect_count'] = min(redirect_count / 5.0, 1.0)  # Normalize
    
    # --- Bot signal features ---
    # Check for common bot detection headers
    server = headers_lower.get('server', '').lower()

    # Bot-friendly servers (Cloudflare, etc.) tend to block bots
    features['server_bot_score'] = 0.0
    if 'cloudflare' in server or 'akamai' in server:
        features['server_bot_score'] = 0.3  # CDN might be blocking bots
    elif 'apache' in server or 'nginx' in server:
        features['server_bot_score'] = 0.1  # Raw server, less protection
    
    # Check for rate limiting headers
    features['has_rate_limit'] = 1.0 if 'x-ratelimit' in str(headers_lower) or 'retry-after' in headers_lower else 0.0
    
    return features


def probe_and_analyze(
    url: str,
    model=None,
    count: int = 1,
    delay: float = 0.0,
    threshold: float = 0.7,
    verbose: bool = False,
) -> dict:
    """Probe a URL and fingerprint how automated/hardened it looks.

    This does NOT classify third-party visitors as bot or human — a probe
    is this tool making its own requests to the target and reading the
    target's response (timing, headers, entropy). The score reflects how
    automated-looking or defensively-hardened the *target* appears, not
    who's visiting it. For classifying real visitor traffic, use `scan`
    against server access logs instead.

    Args:
        url: Target URL to probe
        model: Unused. Accepted for signature compatibility with `scan`'s
            caller, which already loads a BotDetector — but the session-
            trained model has no valid input shape for probe data, so it
            is never scored here.
        count: Number of probes (more = better timing analysis)
        delay: Delay between probes
        threshold: Score threshold
        verbose: Print progress to stderr

    Returns:
        Dictionary with probe results and analysis
    """
    import sys
    
    if verbose:
        print(f"🔍 Probing {url}...", file=sys.stderr, flush=True)
    
    # Run probes
    results = probe_url_multiple(url, count=count, delay=delay)
    
    if verbose:
        for i, r in enumerate(results):
            status = f"HTTP {r.status_code}" if r.status_code else f"Error: {r.error}"
            print(f"   Probe {i+1}/{count}: {status} ({r.timing.get('total', 0):.3f}s)", file=sys.stderr, flush=True)
    
    # Extract features
    features = extract_probe_features(results)

    # Analyze with heuristic rules. This is the probe's sole scorer — the
    # session-trained MLP (`model`) has no valid input here: probe data
    # (response headers/timing/entropy) isn't shaped like session-log data,
    # and there's no meaningful way to map one onto the other. `model` is
    # accepted for API-compatibility with callers that already load one for
    # `scan`, but it is intentionally not used to score probes.
    heuristic_score, heuristic_reason = _analyze_probes(results, features)
    model_score = 0.0
    combined_score = heuristic_score

    # Classify
    is_bot = combined_score >= threshold
    label = 'bot' if is_bot else 'human'
    
    return {
        'url': url,
        'probes': count,
        'features': features,
        'heuristic_score': heuristic_score,
        'heuristic_reason': heuristic_reason,
        'model_score': model_score,
        'combined_score': combined_score,
        'label': label,
        'threshold': threshold,
        'timing': results[0].timing if results else {},
        'status_code': results[0].status_code if results else 0,
        'headers': results[0].headers if results else {},
        'body_preview': results[0].body_text[:500] if results else '',
    }


def _analyze_probes(
    results: list[ProbeResult],
    features: dict[str, float],
) -> tuple[float, str]:
    """Analyze probe results with heuristic rules.
    
    Returns:
        (score, reason) tuple
    """
    if not results:
        return 0.5, 'no probe results'
    
    first = results[0]
    
    # Rule 1: Connection error (might be blocking bots)
    if first.error:
        return 0.6, f'connection error: {first.error[:50]}'
    
    # Rule 2: Very fast response (< 50ms) = likely cached or CDN
    total_time = first.timing.get('total', 0)
    if total_time < 0.05:
        return 0.3, f'extremely fast response ({total_time:.3f}s) — likely cached'
    
    # Rule 3: Very slow response (> 5s) = might be rate limiting
    if total_time > 5.0:
        return 0.5, f'slow response ({total_time:.3f}s) — possible rate limiting'
    
    # Rule 4: 429 Too Many Requests = rate limited
    if first.status_code == 429:
        return 0.8, 'rate limited (HTTP 429)'
    
    # Rule 5: 403 Forbidden = blocked
    if first.status_code == 403:
        return 0.7, 'forbidden (HTTP 403) — might be blocking'
    
    # Rule 6: 5xx Error = server issue
    if first.status_code >= 500:
        return 0.5, f'server error (HTTP {first.status_code})'
    
    # Rule 7: Security headers present = well-protected site
    headers_lower = {k.lower(): v for k, v in first.headers.items()}
    security_headers = [
        'content-security-policy',
        'x-frame-options',
        'strict-transport-security',
        'x-content-type-options',
    ]
    security_count = sum(1 for h in security_headers if h in headers_lower)
    if security_count >= 3:
        return 0.2, f'well-protected site ({security_count} security headers)'
    
    # Rule 8: Timing consistency across probes (bot signal)
    if len(results) > 2:
        cv = features.get('timing_cv', 0)
        if cv < 0.05 and cv > 0:
            return 0.7, f'very consistent timing (CV={cv:.3f}) — likely automated'
    
    # Rule 9: Very low body entropy (empty or minimal response)
    body_entropy = features.get('body_entropy', 0)
    if body_entropy < 1.0 and len(first.body) > 0:
        return 0.4, f'low response entropy ({body_entropy:.2f})'
    
    # Rule 10: High body entropy (random/encrypted content)
    if body_entropy > 7.5:
        return 0.3, f'high response entropy ({body_entropy:.2f}) — likely encrypted/compressed'
    
    # Default: no strong signals
    return 0.3, 'no strong bot signals detected'


def format_probe_verbose(result: dict) -> str:
    """Format probe result with full feature details and rule analysis.
    
    Args:
        result: Dictionary from probe_and_analyze()
    
    Returns:
        Formatted verbose string for terminal display
    """
    lines = []
    
    reset = '\033[0m'
    bold = '\033[1m'
    cyan = '\033[96m'
    
    lines.append("")
    lines.append(f"{bold}  Microguard URL Probe — Verbose{reset}")
    lines.append(f"{cyan}  ──────────────────────────────{reset}")
    lines.append("")
    
    score = result['combined_score']
    label = result['label']
    heuristic_score = result['heuristic_score']
    heuristic_reason = result['heuristic_reason']
    model_score = result['model_score']
    
    if score > 0.7:
        score_ansi = '\033[91m'
        icon = '🚨'
    elif score > 0.3:
        score_ansi = '\033[93m'
        icon = '⚠️ '
    else:
        score_ansi = '\033[92m'
        icon = '✅'
    
    from .report import score_label
    risk = score_label(score)
    
    lines.append(f"  🌐 Target:    {result['url']}")
    lines.append(f"  📡 Status:    HTTP {result['status_code']}")
    lines.append(f"  ⏱️  Response:  {result['timing'].get('total', 0):.3f}s")
    lines.append(f"  🔍 Probes:    {result['probes']}")
    lines.append("")
    lines.append(f"  {icon} Score: {score_ansi}{score:.3f}{reset} — {risk} ({label.upper()})")
    lines.append("")
    
    # Analysis breakdown
    lines.append(f"{bold}  Analysis:{reset}")
    lines.append(f"    Heuristic: {heuristic_score:.3f}")
    lines.append(f"      Rule: {heuristic_reason}")
    if model_score > 0:
        lines.append(f"    ML Model:  {model_score:.3f}")
    lines.append("")
    
    # Full feature vector
    features = result.get('features', {})
    if features:
        lines.append(f"{bold}{cyan}  Feature Vector:{reset}")
        lines.append("  " + "─" * 55)
        lines.append(f"  {'Feature':<35} {'Value':>10}  Notes")
        lines.append("  " + "─" * 55)
        
        for name, val in features.items():
            # Add context for key features
            if name == 'response_time' or name == 'ttfb':
                note = f'{val*1000:.0f}ms'
            elif name == 'timing_cv':
                if val < 0.05:
                    note = f'{bold}bot signal{reset}'
                elif val < 0.2:
                    note = 'moderate'
                else:
                    note = 'variable (human)'
            elif name == 'status_code':
                code = int(val * 1000)
                note = f'HTTP {code}'
            elif name in ('has_content_security_policy', 'has_x_frame_options', 'has_strict_transport', 'has_server_header'):
                note = 'yes' if val > 0.5 else 'no'
            elif name == 'body_entropy':
                if val < 1.0:
                    note = 'low (empty?)'
                elif val > 7.0:
                    note = 'high (compressed?)'
                else:
                    note = 'normal'
            elif name == 'body_length':
                note = f'{val * 100:.0f}KB'
            else:
                note = ''
            
            lines.append(f"  {name:<35} {val:>10.4f}  {note}")
        
        lines.append("  " + "─" * 55)
    
    # Headers
    headers = result.get('headers', {})
    if headers:
        lines.append("")
        lines.append(f"{bold}  Response Headers:{reset}")
        for k, v in sorted(headers.items()):
            if len(v) > 60:
                v = v[:57] + '...'
            lines.append(f"    {k}: {v}")
    
    lines.append("")
    
    return '\n'.join(lines)


def format_probe_report(result: dict) -> str:
    """Format probe result for terminal output.
    
    Args:
        result: Dictionary from probe_and_analyze()
    
    Returns:
        Formatted string for terminal display
    """
    lines = []
    
    # Header
    lines.append("")
    lines.append("  Microguard URL Probe Report")
    lines.append("  ───────────────────────────")
    lines.append("")
    
    # Target info
    lines.append(f"  🌐 Target:    {result['url']}")
    lines.append(f"  📡 Status:    HTTP {result['status_code']}")
    lines.append(f"  ⏱️  Response:  {result['timing'].get('total', 0):.3f}s")
    lines.append(f"  🔍 Probes:    {result['probes']}")
    lines.append("")
    
    # Score
    score = result['combined_score']
    label = result['label']
    
    if score > 0.7:
        score_color = '\033[91m'  # Red
        icon = '🚨'
    elif score > 0.3:
        score_color = '\033[93m'  # Yellow
        icon = '⚠️ '
    else:
        score_color = '\033[92m'  # Green
        icon = '✅'
    
    reset = '\033[0m'
    risk = score_label(score)
    risk_ansi = score_label_color(score)
    risk_colors = {'green': '\033[92m', 'blue': '\033[94m', 'yellow': '\033[93m', 'red': '\033[91m'}
    risk_ansi_color = risk_colors.get(risk_ansi, '')
    lines.append(f"  {icon} Automation Fingerprint: {score_color}{score:.2f}{reset} — {risk_ansi_color}{risk}{reset} ({label.upper()})")
    lines.append(f"  📊 Threshold: {result['threshold']:.2f}")
    lines.append("")
    
    # Analysis breakdown
    lines.append("  Analysis:")
    lines.append(f"    Heuristic:  {result['heuristic_score']:.2f} — {result['heuristic_reason']}")
    if result.get('model_score', 0) > 0:
        lines.append(f"    ML Model:   {result['model_score']:.2f}")
    lines.append("")
    
    # Key features
    features = result.get('features', {})
    if features:
        lines.append("  Key Features:")
        lines.append(f"    Response time:    {features.get('response_time', 0):.3f}s")
        lines.append(f"    TTFB:             {features.get('ttfb', 0):.3f}s")
        lines.append(f"    Body entropy:     {features.get('body_entropy', 0):.2f}")
        lines.append(f"    Body length:      {features.get('body_length', 0) * 100:.0f}KB (normalized)")
        lines.append(f"    Timing CV:        {features.get('timing_cv', 0):.3f}")
        lines.append(f"    Security headers: {int(features.get('has_content_security_policy', 0)) + int(features.get('has_x_frame_options', 0)) + int(features.get('has_strict_transport', 0))}")
        lines.append("")
    
    # Headers
    headers = result.get('headers', {})
    if headers:
        lines.append("  Response Headers:")
        for k, v in sorted(headers.items()):
            if len(v) > 60:
                v = v[:57] + '...'
            lines.append(f"    {k}: {v}")
        lines.append("")
    
    # Body preview
    body = result.get('body_preview', '')
    if body:
        lines.append("  Body Preview (first 200 chars):")
        preview = body[:200].replace('\n', ' ').replace('\r', '')
        lines.append(f"    {preview}")
        lines.append("")
    
    return '\n'.join(lines)


def format_probe_html(result: dict) -> str:
    """Format probe result as HTML report.
    
    Args:
        result: Dictionary from probe_and_analyze()
    
    Returns:
        Complete HTML document string
    """
    score = result['combined_score']

    if score > 0.7:
        status_color = '#ef4444'
        status_text = 'HIGHLY AUTOMATED-LOOKING'
    elif score > 0.3:
        status_color = '#f59e0b'
        status_text = 'SOMEWHAT AUTOMATED-LOOKING'
    else:
        status_color = '#10b981'
        status_text = 'LOW AUTOMATION SIGNAL'
    
    features = result.get('features', {})
    headers = result.get('headers', {})
    
    # Build features list
    features_html = ''
    feature_display = [
        ('response_time', 'Response Time', 's'),
        ('ttfb', 'Time to First Byte', 's'),
        ('timing_cv', 'Timing Consistency', ''),
        ('body_entropy', 'Body Entropy', ''),
        ('body_length', 'Body Size', 'KB'),
        ('header_count', 'Header Count', ''),
        ('has_content_security_policy', 'CSP Header', ''),
        ('has_x_frame_options', 'X-Frame-Options', ''),
        ('has_strict_transport', 'HSTS Header', ''),
    ]
    
    for key, name, unit in feature_display:
        val = features.get(key, 0)
        if 'has_' in key:
            val_str = '✅ Yes' if val > 0.5 else '❌ No'
        elif 'length' in key:
            val_str = f'{val * 100:.0f}{unit}'
        else:
            val_str = f'{val:.3f}{unit}'
        features_html += f'<tr><td>{name}</td><td class="mono">{val_str}</td></tr>\n'
    
    # Build headers list
    headers_html = ''
    for k, v in sorted(headers.items()):
        if len(v) > 80:
            v = v[:77] + '...'
        headers_html += f'<tr><td class="mono">{k}</td><td>{v}</td></tr>\n'
    
    body_preview = result.get('body_preview', '')[:500]
    if body_preview:
        body_preview = body_preview.replace('<', '&lt;').replace('>', '&gt;')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microguard Probe — {result['url']}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --card-border: #334155;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --green: #10b981;
            --yellow: #f59e0b;
            --red: #ef4444;
            --blue: #3b82f6;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 2rem; padding-bottom: 2rem; border-bottom: 1px solid var(--card-border); }}
        .header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        .header h1 span {{ color: var(--blue); }}
        .header .url {{ color: var(--text-muted); font-family: monospace; font-size: 0.9rem; word-break: break-all; }}
        .score-card {{
            background: var(--card);
            border: 2px solid {status_color};
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
        }}
        .score-card .label {{ font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.5rem; }}
        .score-card .value {{ font-size: 3rem; font-weight: 700; color: {status_color}; }}
        .score-card .status {{ font-size: 1.2rem; font-weight: 600; color: {status_color}; margin-top: 0.5rem; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .info-item {{ background: var(--card); border: 1px solid var(--card-border); border-radius: 8px; padding: 1rem; text-align: center; }}
        .info-item .value {{ font-size: 1.5rem; font-weight: 600; }}
        .info-item .label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }}
        .section {{ background: var(--card); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .section h2 {{ font-size: 1rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--card-border); }}
        .analysis {{ padding: 1rem; background: #0f172a; border-radius: 8px; }}
        .analysis .label {{ color: var(--text-muted); font-size: 0.85rem; }}
        .analysis .value {{ font-weight: 600; }}
        .analysis .reason {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th {{ text-align: left; padding: 0.5rem; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }}
        td {{ padding: 0.5rem; border-top: 1px solid var(--card-border); }}
        .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; }}
        .footer {{ text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--card-border); }}
        .footer a {{ color: var(--blue); text-decoration: none; }}
        @media print {{
            body {{ background: white; color: #1e293b; }}
            .card {{ background: #f8fafc; border-color: #e2e8f0; }}
            .score-card {{ background: #f8fafc; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 <span>Microguard</span> URL Probe</h1>
            <div class="url">{result['url']}</div>
        </div>
        
        <div class="score-card">
            <div class="label">Automation Fingerprint</div>
            <div class="value">{score:.2f}</div>
            <div class="status">{status_text}</div>
        </div>
        
        <div class="info-grid">
            <div class="info-item">
                <div class="value">HTTP {result['status_code']}</div>
                <div class="label">Status</div>
            </div>
            <div class="info-item">
                <div class="value">{result['timing'].get('total', 0):.3f}s</div>
                <div class="label">Response Time</div>
            </div>
            <div class="info-item">
                <div class="value">{result['probes']}</div>
                <div class="label">Probes Sent</div>
            </div>
            <div class="info-item">
                <div class="value">{result['threshold']:.0%}</div>
                <div class="label">Threshold</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Analysis</h2>
            <div class="analysis">
                <div class="label">Heuristic Score</div>
                <div class="value">{result['heuristic_score']:.2f}</div>
                <div class="reason">{result['heuristic_reason']}</div>
            </div>
            {f'<div class="analysis" style="margin-top: 1rem"><div class="label">ML Model Score</div><div class="value">{result["model_score"]:.2f}</div></div>' if result.get('model_score', 0) > 0 else ''}
        </div>
        
        <div class="section">
            <h2>Extracted Features</h2>
            <table>
                <thead><tr><th>Feature</th><th>Value</th></tr></thead>
                <tbody>
                    {features_html}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Response Headers</h2>
            <table>
                <thead><tr><th>Header</th><th>Value</th></tr></thead>
                <tbody>
                    {headers_html if headers_html else '<tr><td colspan="2" style="color: var(--text-muted)">No headers captured</td></tr>'}
                </tbody>
            </table>
        </div>
        
        {f'<div class="section"><h2>Body Preview</h2><pre class="mono" style="white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; color: var(--text-muted);">{body_preview}</pre></div>' if body_preview else ''}
        
        <div class="footer">
            <p>This fingerprints how automated/hardened the target looks from this single probe — it does not classify third-party visitors. Use <code>microguard scan</code> against access logs for that.</p>
            <p>Powered by <a href="https://github.com/karpathy/micrograd">micrograd</a> · Microguard v2.0.0</p>
        </div>
    </div>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# WebSocket probing
#
# Standard access logs capture only the WS upgrade handshake (GET .. -> 101);
# the message stream after that is invisible to any log-based tool. This is
# a live probe, not a log parser: it opens a real connection and fingerprints
# the handshake/response behavior, the same way probe_url() fingerprints an
# HTTP target — it does not and cannot classify third-party WS clients.
# ---------------------------------------------------------------------------


def _ws_encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    """Encode a masked WebSocket frame (client -> server, per RFC 6455).

    Client frames MUST be masked. Payload is assumed small (< 64KB).
    """
    fin_opcode = 0x80 | opcode
    length = len(payload)
    mask_key = os.urandom(4)
    if length <= 125:
        header = struct.pack('!BB', fin_opcode, 0x80 | length)
    elif length <= 0xFFFF:
        header = struct.pack('!BBH', fin_opcode, 0x80 | 126, length)
    else:
        header = struct.pack('!BBQ', fin_opcode, 0x80 | 127, length)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return header + mask_key + masked


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes (or fewer, on EOF/timeout)."""
    if n <= 0:
        return b''
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _ws_decode_frame(sock: socket.socket, timeout: float) -> tuple[int, bytes] | None:
    """Read and decode one WebSocket frame from the socket.

    Returns (opcode, payload), or None on timeout/EOF/short read.
    """
    sock.settimeout(timeout)
    try:
        header = _recv_exact(sock, 2)
    except (TimeoutError, OSError):
        return None
    if len(header) < 2:
        return None

    b0, b1 = header[0], header[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F

    try:
        if length == 126:
            length = struct.unpack('!H', _recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack('!Q', _recv_exact(sock, 8))[0]
        mask_key = _recv_exact(sock, 4) if masked else b''
        payload = _recv_exact(sock, length) if length else b''
    except (TimeoutError, OSError, struct.error):
        return None

    if masked and payload:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, payload


@dataclass
class WSProbeResult:
    """Result of one WebSocket handshake + optional message probe."""
    url: str
    connected: bool = False
    handshake_ok: bool = False
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    frames_received: list[bytes] = field(default_factory=list)
    timing: dict[str, float] = field(default_factory=dict)
    error: str | None = None


def probe_websocket(
    url: str,
    timeout: float = 10.0,
    send_message: str = "ping",
    verify_ssl: bool = True,
) -> WSProbeResult:
    """Open a real WebSocket connection and probe it.

    Performs the RFC 6455 handshake by hand over a raw socket (stdlib
    only — no `websockets`/`websocket-client` dependency): sends the
    HTTP Upgrade request, verifies the server's `Sec-WebSocket-Accept`
    against the spec's fixed-GUID SHA-1 derivation, optionally sends one
    text frame, and reads back whatever the server sends within `timeout`.
    """
    parsed = urllib.parse.urlparse(url if '://' in url else f'ws://{url}')
    is_wss = parsed.scheme == 'wss'
    host = parsed.hostname or ''
    port = parsed.port or (443 if is_wss else 80)
    path = parsed.path or '/'
    if parsed.query:
        path = f'{path}?{parsed.query}'

    result = WSProbeResult(url=url)
    # perf_counter for the same reason as probe_url: elapsed spans only, and
    # time()'s Windows tick is coarse enough to report a local handshake as 0.0.
    t_start = time.perf_counter()
    sock: socket.socket | ssl.SSLSocket | None = None

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        if is_wss:  # pragma: no cover - needs a TLS loopback server; the test
            # suite has no certificate to serve and the project takes no
            # dependency on a library that can generate one.
            ctx = ssl.create_default_context()
            if not verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
        t_connected = time.perf_counter()
        result.connected = True

        ws_key = base64.b64encode(os.urandom(16)).decode('ascii')
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode('ascii'))

        sock.settimeout(timeout)
        response = b''
        while b'\r\n\r\n' not in response and len(response) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        t_handshake = time.perf_counter()

        header_blob = response.split(b'\r\n\r\n', 1)[0]
        lines = header_blob.decode('iso-8859-1', errors='replace').split('\r\n')
        status_line = lines[0] if lines else ''
        try:
            result.status_code = int(status_line.split(' ')[1])
        except (IndexError, ValueError):
            result.status_code = 0

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip()] = v.strip()
        result.headers = headers

        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + _WS_GUID).encode('ascii')).digest()
        ).decode('ascii')
        # Header names are case-insensitive per HTTP — some real servers
        # (this was caught against a live endpoint) send them lowercased.
        accept_header = next(
            (v for k, v in headers.items() if k.lower() == 'sec-websocket-accept'), None
        )
        result.handshake_ok = (
            result.status_code == 101
            and accept_header == expected_accept
        )

        result.timing = {
            'connect': t_connected - t_start,
            'handshake': t_handshake - t_connected,
            'total_to_handshake': t_handshake - t_start,
        }

        if result.handshake_ok and send_message:
            sock.sendall(_ws_encode_frame(send_message.encode('utf-8')))
            t_sent = time.perf_counter()
            frame = _ws_decode_frame(sock, timeout)
            if frame is not None:
                _opcode, payload = frame
                result.frames_received.append(payload)
                result.timing['time_to_first_frame'] = time.perf_counter() - t_sent

    except (OSError, ssl.SSLError) as e:
        result.error = str(e)
        result.timing.setdefault('total_to_handshake', time.perf_counter() - t_start)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:  # pragma: no cover - close() failing is not
                # reproducible without patching the socket itself
                pass

    return result


def probe_websocket_multiple(
    url: str,
    count: int = 1,
    delay: float = 0.0,
    timeout: float = 10.0,
) -> list[WSProbeResult]:
    """Probe a WebSocket URL multiple times to measure handshake timing patterns."""
    results = []
    for i in range(count):
        results.append(probe_websocket(url, timeout=timeout))
        if delay > 0 and i < count - 1:
            time.sleep(delay)
    return results


def extract_ws_probe_features(results: list[WSProbeResult]) -> dict[str, float]:
    """Extract fingerprint features from WebSocket probe results."""
    if not results:
        return {}

    first = results[0]
    features: dict[str, float] = {
        'handshake_time': first.timing.get('handshake', 0.0),
        'connect_time': first.timing.get('connect', 0.0),
        'handshake_ok': 1.0 if first.handshake_ok else 0.0,
        'got_response_frame': 1.0 if first.frames_received else 0.0,
        'time_to_first_frame': first.timing.get('time_to_first_frame', 0.0),
    }

    if len(results) > 1:
        handshake_times = [r.timing.get('handshake', 0.0) for r in results if r.connected]
        features['handshake_timing_cv'] = _timing_pattern_consistency(handshake_times)
    else:
        features['handshake_timing_cv'] = 0.0

    if first.frames_received:
        payload = first.frames_received[0]
        features['frame_entropy'] = _shannon_entropy(payload)
        features['frame_size'] = min(len(payload) / 1024.0, 1.0)
    else:
        features['frame_entropy'] = 0.0
        features['frame_size'] = 0.0

    return features


def _analyze_ws_probes(
    results: list[WSProbeResult],
    features: dict[str, float],
) -> tuple[float, str]:
    """Heuristic automation/hardening fingerprint for a WebSocket target.

    A dedicated scorer, not a repurposed HTTP one — frame-level signals
    (handshake compliance, timing across handshakes, unsolicited server
    frames) are different enough from header-level HTTP signals to warrant
    their own rules.
    """
    if not results:
        return 0.5, 'no probe results'

    first = results[0]

    if not first.connected:
        return 0.6, f'connection failed: {(first.error or "unknown")[:50]}'

    if not first.handshake_ok:
        return 0.7, (
            f'WebSocket handshake rejected/malformed (HTTP {first.status_code}) '
            '— likely blocked or not a WS endpoint'
        )

    handshake = first.timing.get('handshake', 0.0)
    if handshake < 0.01:
        return 0.3, f'extremely fast handshake ({handshake:.3f}s) — likely local/cached'

    if len(results) > 2:
        cv = features.get('handshake_timing_cv', 0)
        if 0 < cv < 0.05:
            return 0.7, f'very consistent handshake timing (CV={cv:.3f}) — likely automated'

    if not first.frames_received:
        return 0.4, 'clean handshake, no unsolicited server frame — normal for most WS servers'

    return 0.3, 'clean handshake with server response — no strong automation signal'


def probe_ws_and_analyze(
    url: str,
    count: int = 1,
    delay: float = 0.0,
    threshold: float = 0.7,
    timeout: float = 10.0,
    verbose: bool = False,
) -> dict:
    """Probe a WebSocket URL and fingerprint how automated/hardened it looks.

    Same caveat as `probe_and_analyze`: this scores the target's handshake
    and response behavior against this tool's own connection attempt. It
    does not — and, from outside the message stream, cannot — classify
    real third-party WebSocket clients as bot or human.
    """
    import sys

    if verbose:
        print(f"🔌 Probing {url} (WebSocket)...", file=sys.stderr, flush=True)

    results = probe_websocket_multiple(url, count=count, delay=delay, timeout=timeout)

    if verbose:
        for i, r in enumerate(results):
            if r.connected:
                status = f"handshake {'OK' if r.handshake_ok else 'FAILED'} (HTTP {r.status_code})"
            else:
                status = f"error: {r.error}"
            print(
                f"   Probe {i+1}/{count}: {status} ({r.timing.get('total_to_handshake', 0):.3f}s)",
                file=sys.stderr, flush=True,
            )

    features = extract_ws_probe_features(results)
    score, reason = _analyze_ws_probes(results, features)

    is_automated_looking = score >= threshold
    label = 'bot' if is_automated_looking else 'human'

    first = results[0] if results else None
    return {
        'url': url,
        'protocol': 'websocket',
        'probes': count,
        'features': features,
        'heuristic_score': score,
        'heuristic_reason': reason,
        'model_score': 0.0,
        'combined_score': score,
        'label': label,
        'threshold': threshold,
        'connected': first.connected if first else False,
        'handshake_ok': first.handshake_ok if first else False,
        'status_code': first.status_code if first else 0,
        'headers': first.headers if first else {},
        'timing': first.timing if first else {},
        'error': first.error if first else None,
    }


def format_ws_probe_report(result: dict) -> str:
    """Format a WebSocket probe result for terminal output."""
    lines = []
    lines.append("")
    lines.append("  Microguard WebSocket Probe Report")
    lines.append("  ──────────────────────────────────")
    lines.append("")

    if result.get('handshake_ok'):
        handshake_str = 'OK (HTTP 101)'
    else:
        handshake_str = f"FAILED (HTTP {result.get('status_code', 0)})"

    lines.append(f"  🌐 Target:    {result['url']}")
    lines.append(f"  🔌 Connected: {'yes' if result.get('connected') else 'no'}")
    lines.append(f"  🤝 Handshake: {handshake_str}")
    lines.append(f"  🔍 Probes:    {result['probes']}")
    lines.append("")

    score = result['combined_score']
    label = result['label']

    if score > 0.7:
        score_color = '\033[91m'
        icon = '🚨'
    elif score > 0.3:
        score_color = '\033[93m'
        icon = '⚠️ '
    else:
        score_color = '\033[92m'
        icon = '✅'

    reset = '\033[0m'
    risk = score_label(score)
    risk_ansi = score_label_color(score)
    risk_colors = {'green': '\033[92m', 'blue': '\033[94m', 'yellow': '\033[93m', 'red': '\033[91m'}
    risk_color = risk_colors.get(risk_ansi, '')
    lines.append(
        f"  {icon} Automation Fingerprint: {score_color}{score:.2f}{reset} — "
        f"{risk_color}{risk}{reset} ({label.upper()})"
    )
    lines.append(f"  📊 Threshold: {result['threshold']:.2f}")
    lines.append("")

    lines.append("  Analysis:")
    lines.append(f"    Heuristic:  {result['heuristic_score']:.2f} — {result['heuristic_reason']}")
    lines.append("")

    features = result.get('features', {})
    if features:
        lines.append("  Key Features:")
        lines.append(f"    Handshake time:      {features.get('handshake_time', 0):.3f}s")
        lines.append(f"    Time to first frame: {features.get('time_to_first_frame', 0):.3f}s")
        lines.append(f"    Handshake timing CV: {features.get('handshake_timing_cv', 0):.3f}")
        lines.append(f"    Got response frame:  {'yes' if features.get('got_response_frame') else 'no'}")
        lines.append("")

    if result.get('error'):
        lines.append(f"  Error: {result['error']}")
        lines.append("")

    return '\n'.join(lines)


def format_ws_probe_html(result: dict) -> str:
    """Format a WebSocket probe result as a shareable HTML report."""
    score = result['combined_score']

    if score > 0.7:
        status_color = '#ef4444'
        status_text = 'HIGHLY AUTOMATED-LOOKING'
    elif score > 0.3:
        status_color = '#f59e0b'
        status_text = 'SOMEWHAT AUTOMATED-LOOKING'
    else:
        status_color = '#10b981'
        status_text = 'LOW AUTOMATION SIGNAL'

    features = result.get('features', {})
    feature_display = [
        ('handshake_time', 'Handshake Time', 's'),
        ('connect_time', 'Connect Time', 's'),
        ('time_to_first_frame', 'Time to First Frame', 's'),
        ('handshake_timing_cv', 'Handshake Timing Consistency', ''),
        ('got_response_frame', 'Got Response Frame', ''),
        ('frame_entropy', 'Response Frame Entropy', ''),
    ]
    features_html = ''
    for key, name, unit in feature_display:
        val = features.get(key, 0)
        if key == 'got_response_frame':
            val_str = '✅ Yes' if val > 0.5 else '❌ No'
        else:
            val_str = f'{val:.3f}{unit}'
        features_html += f'<tr><td>{name}</td><td class="mono">{val_str}</td></tr>\n'

    handshake_ok = result.get('handshake_ok', False)
    error = result.get('error') or ''

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microguard WebSocket Probe — {result['url']}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --card-border: #334155;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --green: #10b981;
            --yellow: #f59e0b;
            --red: #ef4444;
            --blue: #3b82f6;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 2rem; padding-bottom: 2rem; border-bottom: 1px solid var(--card-border); }}
        .header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        .header h1 span {{ color: var(--blue); }}
        .header .url {{ color: var(--text-muted); font-family: monospace; font-size: 0.9rem; word-break: break-all; }}
        .score-card {{
            background: var(--card);
            border: 2px solid {status_color};
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
        }}
        .score-card .label {{ font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.5rem; }}
        .score-card .value {{ font-size: 3rem; font-weight: 700; color: {status_color}; }}
        .score-card .status {{ font-size: 1.2rem; font-weight: 600; color: {status_color}; margin-top: 0.5rem; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .info-item {{ background: var(--card); border: 1px solid var(--card-border); border-radius: 8px; padding: 1rem; text-align: center; }}
        .info-item .value {{ font-size: 1.5rem; font-weight: 600; }}
        .info-item .label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }}
        .section {{ background: var(--card); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .section h2 {{ font-size: 1rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--card-border); }}
        .analysis {{ padding: 1rem; background: #0f172a; border-radius: 8px; }}
        .analysis .label {{ color: var(--text-muted); font-size: 0.85rem; }}
        .analysis .value {{ font-weight: 600; }}
        .analysis .reason {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th {{ text-align: left; padding: 0.5rem; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }}
        td {{ padding: 0.5rem; border-top: 1px solid var(--card-border); }}
        .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; }}
        .footer {{ text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--card-border); }}
        .footer a {{ color: var(--blue); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔌 <span>Microguard</span> WebSocket Probe</h1>
            <div class="url">{result['url']}</div>
        </div>

        <div class="score-card">
            <div class="label">Automation Fingerprint</div>
            <div class="value">{score:.2f}</div>
            <div class="status">{status_text}</div>
        </div>

        <div class="info-grid">
            <div class="info-item">
                <div class="value">{'Yes' if handshake_ok else 'No'}</div>
                <div class="label">Handshake OK</div>
            </div>
            <div class="info-item">
                <div class="value">HTTP {result.get('status_code', 0)}</div>
                <div class="label">Upgrade Status</div>
            </div>
            <div class="info-item">
                <div class="value">{result['probes']}</div>
                <div class="label">Probes Sent</div>
            </div>
            <div class="info-item">
                <div class="value">{result['threshold']:.0%}</div>
                <div class="label">Threshold</div>
            </div>
        </div>

        <div class="section">
            <h2>Analysis</h2>
            <div class="analysis">
                <div class="label">Heuristic Score</div>
                <div class="value">{result['heuristic_score']:.2f}</div>
                <div class="reason">{result['heuristic_reason']}</div>
            </div>
        </div>

        <div class="section">
            <h2>Extracted Features</h2>
            <table>
                <thead><tr><th>Feature</th><th>Value</th></tr></thead>
                <tbody>
                    {features_html}
                </tbody>
            </table>
        </div>

        {f'<div class="section"><h2>Error</h2><p style="color: var(--red)">{error}</p></div>' if error else ''}

        <div class="footer">
            <p>Captures only the WS upgrade handshake and one round of message exchange — not a full session recording.</p>
            <p>Powered by <a href="https://github.com/karpathy/micrograd">micrograd</a> · Microguard v2.0.0</p>
        </div>
    </div>
</body>
</html>"""

    return html
