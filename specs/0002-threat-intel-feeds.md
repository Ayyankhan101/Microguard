# Spec 0002: Threat-intel feed integration

Epic: [0000-epic-paid-alternative-parity.md](0000-epic-paid-alternative-parity.md)
Depends on: [0001-real-time-blocking.md](0001-real-time-blocking.md) (must be merged first)
Status: **SHIPPED** — v3.0.0 (`29aaf79`), with deliberate deviations

> **Read this before planning against the code below.**
>
> The premise of this spec was wrong in one way that mattered: it assumed
> `labeler.py` was offline batch code. It is not — `live/scorer.py` calls
> `label_session` inline on every nginx `auth_request`, so the AbuseIPDB call
> this spec put inside `_check_threat_intel_signals` would have sat in front of
> a real visitor, where nginx turns slowness into a 500.
>
> | Spec says | What exists |
> |---|---|
> | lookups inside `label_session` | Resolved out of process by `microguard signals`; `label_session(session, signals)` never fetches |
> | caches under `data/threatintel/` | `$XDG_CACHE_HOME/microguard` — `data/` ships in the wheel and is read-only on a normal install |
> | checked-in `hosting_asns.json` of CIDRs | Fetched from AWS's published `ip-ranges.json`, cached with stale-fallback. Hand-typed CIDR blocks in a security tool are wrong in ways nobody notices |
> | `ENABLE_THREAT_INTEL` / `MICROGUARD_DISABLE_THREAT_INTEL` | Replaced by per-source promotion in `mg:v1:config`. Every signal is observe-only until promoted, which is strictly more control than one global switch |
>
> **Item 2 of `_check_threat_intel_signals` is still open.** The spec correctly
> refused to guess the hosting-range combination rule. `hosting_range` is
> resolved and recorded on every decision, and no rule reads it — it is
> deliberately absent from `KNOWN_SIGNAL_SOURCES` so nobody can promote a
> control that does nothing. See `TODOS.md`.
Priority: High
Effort estimate: 2-3 days

## Context

Paid bot-management vendors' strongest signal is shared reputation across
thousands of customers — an IP that attacked one customer is pre-flagged for
all of them. Microguard has no equivalent: it only knows what's in its own
training data and heuristic patterns. This spec closes most of that gap using
free/public feeds instead of building a cross-customer network (explicitly
out of scope for this whole epic — see 0000's Out of Scope).

Decided already (epic-level, do not re-ask): AbuseIPDB is included from day
one, not deferred, and must degrade gracefully with no API key set.

## Current State (verified 2026-09-06)

- `microguard/labeler.py` already has this exact architectural pattern for
  external-signal checks: `_check_cloudflare_signals(session) -> tuple[bool,
  str]` (`labeler.py`, search `_check_cloudflare_signals`) and
  `_check_botnet_signatures(session) -> tuple[bool, str]`, both called from
  inside `label_session()`'s high-confidence rule chain (the first ~8 checks
  before the medium-confidence tier). This spec reuses that exact pattern —
  do not invent a different integration mechanism.
- `label_session()` (`labeler.py:221`) returns as soon as any high-confidence
  rule fires. New threat-intel checks belong in this same tier, checked
  early, same `(bool, str)` return contract.
- No network calls exist anywhere in `microguard/labeler.py` or
  `microguard/features.py` today — both are pure/offline. This spec
  introduces the first network dependency into the labeling path; it MUST be
  optional/cached so `scan`/`probe`/`watch`'s existing zero-network-required
  behavior for `labeler.py`-only usage isn't silently broken for users who
  never configure threat intel.
- No `data/threatintel/` directory exists yet.

## Proposed Change

New package `microguard/threatintel/`.

### 1. Keyless feeds (no setup required, ship enabled by default)

`microguard/threatintel/tor.py`:
```python
def load_tor_exit_nodes(cache_path: str = "data/threatintel/tor_exit_nodes.txt",
                         max_age_hours: int = 24) -> set[str]:
    """Fetch https://check.torproject.org/torbulkexitlist, cache to disk.
    On fetch failure, fall back to the existing cache file (however stale)
    rather than raising — a threat-intel signal must never break scoring.
    If no cache exists and the fetch fails, return an empty set (signal
    simply doesn't fire, not an error)."""
```

`microguard/threatintel/hosting_asn.py`:
```python
def load_hosting_ranges(path: str = "data/threatintel/hosting_asns.json") -> list:
    """Load a checked-in, version-controlled JSON file of known
    hosting/datacenter CIDR ranges (AWS, GCP, Azure, DigitalOcean, Hetzner,
    OVH published ranges). No network call — this file ships with the
    package and is updated as a periodic maintenance task, not fetched live.
    Returns a list of ipaddress.ip_network objects."""
```
Seed `data/threatintel/hosting_asns.json` with the publicly documented CIDR
ranges from AWS (`ip-ranges.json`), GCP, Azure, DigitalOcean, Hetzner, OVH —
cite the exact source URL for each in a comment/README inside that file's
directory so it's re-fetchable later, not hand-typed from memory.

### 2. AbuseIPDB (keyed, optional, cached)

`microguard/threatintel/abuseipdb.py`:
```python
class AbuseIPDBClient:
    """Wraps https://api.abuseipdb.com/api/v2/check.
    Reads API key from ABUSEIPDB_API_KEY env var. If unset,
    is_configured() returns False and check_ip() always returns None
    (signal doesn't fire) — never raises for a missing key.
    Caches responses to data/threatintel/abuseipdb_cache.json, TTL 24h,
    to respect the free tier's 1000 checks/day limit."""
    def is_configured(self) -> bool: ...
    def check_ip(self, ip: str) -> float | None:
        """Returns the AbuseIPDB confidence score (0-100) or None if
        unconfigured / not cached / request failed. Never raises."""
```

### 3. Wire into labeler.py

New function in `labeler.py`, same pattern as the two existing `_check_*`
functions:
```python
def _check_threat_intel_signals(session: Session) -> tuple[bool, str]:
    """Checks (in order, first match wins):
    1. session.ip in tor exit node set -> bot, 'Tor exit node'
    2. session.ip in a known hosting/datacenter range -> NOT automatically
       bot (real users don't come from datacenter IPs, but this alone is
       weak evidence — combine with existing behavioral signals rather than
       flagging solely on IP range; document the exact combination rule
       decided during implementation, this is a real design choice to make
       with evidence, not guess at here)
    3. AbuseIPDB confidence score, if configured, above a threshold
       (default 75 — make this a labeler.py module constant,
       THREAT_INTEL_ABUSE_THRESHOLD, not a magic number inline)
    """
```
Call it from `label_session()` in the high-confidence tier, alongside the
existing `_check_cloudflare_signals`/`_check_botnet_signatures` calls.

### 4. Feature flag / opt-out

Threat-intel checks must be individually disable-able (some users may not
want any outbound network calls from a security tool at all — legitimate,
common concern). Add a module-level toggle, e.g.
`labeler.py::ENABLE_THREAT_INTEL = True` respected by an env var
`MICROGUARD_DISABLE_THREAT_INTEL=1`, checked once at import time. Document
this explicitly in the README — a security tool making silent outbound
network calls without an obvious, documented off-switch is the kind of thing
that erodes trust fast.

## Acceptance Criteria

1. `load_tor_exit_nodes()` returns a non-empty set on a real network call in
   a test (or is explicitly skipped if network is unavailable, matching the
   existing `@pytest.mark.skip(reason="Requires network access")` pattern in
   `tests/test_scanner.py`), and correctly falls back to a stale cache file
   on a simulated fetch failure (mock the HTTP call to raise, verify the
   cached value is still returned).
2. `load_hosting_ranges()` parses the checked-in JSON and returns valid
   `ipaddress.ip_network` objects; a known AWS IP (from the checked-in
   ranges) is correctly identified as `ip_address in range`.
3. `AbuseIPDBClient.is_configured()` returns `False` and `check_ip()` returns
   `None` with no `ABUSEIPDB_API_KEY` set — verified with the env var
   explicitly unset in the test, not just "didn't crash."
4. `AbuseIPDBClient` caches a response and does not make a second HTTP call
   for the same IP within the TTL (mock the HTTP client, assert call count).
5. `_check_threat_intel_signals` correctly flags a session whose IP is a
   known Tor exit node (using a fixture IP, not a real live Tor check in
   this unit test).
6. `label_session()` with `MICROGUARD_DISABLE_THREAT_INTEL=1` set never
   calls any of the threat-intel functions — verified by mocking them and
   asserting zero calls.
7. `microguard scan` against the existing `data/sample_access.log` and
   `data/zenodo_data/organization-x/log/apache2/web-access.log.1` fixtures
   produces identical results before and
   after this change is merged, WITH threat intel disabled via the env var
   (proves this is purely additive when off) — run the existing test suite,
   it must still pass unmodified.

## Testing Plan

| Layer | What | Count |
|-------|------|-------|
| Unit | `load_tor_exit_nodes` fetch + cache fallback | +2 |
| Unit | `load_hosting_ranges` parsing + membership check | +2 |
| Unit | `AbuseIPDBClient` unconfigured / cached / cache-expiry behavior | +3 |
| Unit | `_check_threat_intel_signals` per-source flagging | +3 |
| Unit | `MICROGUARD_DISABLE_THREAT_INTEL` opt-out | +1 |
| Integration | `label_session()` end-to-end with a Tor-exit-IP fixture session | +1 |
| Regression | Full existing `tests/` suite passes with threat intel disabled | (existing, no new count) |

## Rollback Plan

Set `MICROGUARD_DISABLE_THREAT_INTEL=1` — reverts to pre-0002 behavior
instantly with no code change, since the toggle is checked at the top of the
one new function this spec wires into `label_session()`.

## Effort Estimate

| Component | Estimate |
|-----------|----------|
| Tor feed + cache fallback | 0.5 day |
| Hosting ASN static data + loader | 0.5 day |
| AbuseIPDB client + cache | 0.5 day |
| labeler.py wiring + opt-out toggle | 0.5 day |
| Tests | 0.5-1 day |
| **Total** | **~2.5-3 days** |

## Files Reference

| File | Change |
|------|--------|
| `microguard/threatintel/__init__.py` | New |
| `microguard/threatintel/tor.py` | New — `load_tor_exit_nodes()` |
| `microguard/threatintel/hosting_asn.py` | New — `load_hosting_ranges()` |
| `microguard/threatintel/abuseipdb.py` | New — `AbuseIPDBClient` |
| `data/threatintel/hosting_asns.json` | New — checked-in static data, with source URLs documented |
| `microguard/labeler.py` | Add `_check_threat_intel_signals`, `ENABLE_THREAT_INTEL`, `THREAT_INTEL_ABUSE_THRESHOLD`; wire into `label_session()` |
| `tests/test_threatintel.py` | New |
| `README.md` | Document `ABUSEIPDB_API_KEY` and `MICROGUARD_DISABLE_THREAT_INTEL` env vars |

## Out of Scope

- Any feed requiring a paid subscription.
- Building a shared/crowdsourced Microguard-native reputation network
  (ambitious, needs real adoption first — see epic's Out of Scope).
- Real-time feed refresh scheduling (a daemon that keeps `tor_exit_nodes.txt`
  warm) — the cache-on-read-with-max-age approach in this spec is sufficient
  for v1.

## Related

- Epic: [0000-epic-paid-alternative-parity.md](0000-epic-paid-alternative-parity.md)
- `microguard/labeler.py` — existing `_check_cloudflare_signals`,
  `_check_botnet_signatures` (the pattern this spec follows).
