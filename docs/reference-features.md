# The 19 features

Every score microguard produces starts here. `extract_features(session)` turns
one session into a list of exactly 19 floats, in a fixed order, and that vector
is the model's only input.

```python
from microguard.features import FEATURE_NAMES, extract_features, group_into_sessions
from microguard.parser import parse_file

sessions = group_into_sessions(list(parse_file("access.log")), timeout_minutes=30)
features = extract_features(sessions[0])          # list[float], len 19
dict(zip(FEATURE_NAMES, features))
```

An empty session returns `[0.0] * 19`. The order is fixed and asserted at import
(`features.py:373`) — the model's weights are positional, so reordering the list
silently changes what every weight means.

## Sessions

A session is a group of requests from one actor.
`group_into_sessions(entries, timeout_minutes=30, session_key=None)` sorts
entries by timestamp and starts a new session when a new actor appears or when
more than `timeout_minutes` pass between that actor's requests.

`session_key` defaults to `lambda e: e.ip`. Pass something else when the IP field
is not a usable identity — the organization-x dataset anonymizes it to about two
placeholder values, so the training pipeline uses `lambda e: (e.ip, e.user_agent)`
instead (see [training data](explanation-training-data.md)).

`Session` exposes `ip`, `user_agent`, `requests`, `start_time`, `end_time`,
`duration` (seconds), and `request_count`.

## Timing (1–5)

| # | Name | Value | Notes |
|---|---|---|---|
| 1 | `time_since_last_request` | Mean gap in seconds between consecutive requests | `0.0` for a single request |
| 2 | `requests_per_minute_1m` | **Count** of requests within 60s of the last one | `1` for a single request |
| 3 | `requests_per_minute_5m` | **Count** of requests within 300s of the last one | `1` for a single request |
| 4 | `inter_request_time_cv` | Coefficient of variation (sample std / mean) of the gaps | `0.0` with fewer than 2 gaps, or when the mean is 0 |
| 5 | `time_since_session_start` | Session duration in seconds (`end_time - start_time`) | `0.0` when a session spans one timestamp |

Features 2 and 3 are named like rates but are **counts**, not divided by
anything. A session of 40 requests inside one minute gives
`requests_per_minute_1m = 40`; the same 40 requests spread over an hour give a
much smaller number because most fall outside the 60-second window measured back
from the last request.

Feature 4 is the uniformity signal. A script firing on a timer has near-zero
variance in its gaps, so its CV approaches 0. A person reading pages produces
gaps that vary by an order of magnitude.

## Behavioral (6–9)

| # | Name | Value | Notes |
|---|---|---|---|
| 6 | `endpoint_count` | Number of distinct paths, query strings stripped | |
| 7 | `endpoint_sequence_entropy` | Shannon entropy (bits) of the path frequency distribution | `0.0` when every request hits one path |
| 8 | `unique_endpoint_ratio` | `endpoint_count / request_count` | `1.0` when every request is a different path |
| 9 | `method_mismatch_count` | Count of `POST` requests to `.css .js .png .jpg .gif .ico .svg` | A POST to a stylesheet is not a thing browsers do |

Features 6–8 separate browsing from harvesting. Someone reading a site touches
many paths a few times each: high entropy, high unique ratio. A scraper walks one
endpoint repeatedly: entropy near 0, ratio near `1/request_count`.

## Header (10–12)

| # | Name | Value | Notes |
|---|---|---|---|
| 10 | `header_consistency_score` | `1 / (number of distinct User-Agent strings)` | `1.0` for one consistent UA; `0.5` for two; lower as an actor rotates them |
| 11 | `has_accept_language` | `1.0` if any request's UA looks like a browser, else `0.0` | A **proxy**, see below |
| 12 | `ua_category` | `0.0` browser, `1.0` bot, `2.0` unknown | Categorical, not ordinal |

**Feature 11 does not read an Accept-Language header.** The combined log format
does not record one. The extractor approximates it by checking whether the UA
string matches a browser pattern, on the reasoning that clients sending browser
UAs generally also send Accept-Language. It is a proxy, and a bot that copies a
browser UA defeats it.

**Feature 12 is categorical.** `2.0` (unknown) is not "more bot" than `1.0`
(bot); the values are labels the network has to learn to separate, and the
min-max normalization maps them to 0.0, 0.5, 1.0. The patterns behind the
classification are `BOT_UA_PATTERNS` and `KNOWN_BROWSER_UA` in `features.py:20`.
An empty UA or `-` classifies as unknown.

## Payload and response (13–14)

| # | Name | Value | Notes |
|---|---|---|---|
| 13 | `payload_entropy` | Mean Shannon entropy of the request URL strings, character-wise | Generated or fuzzed paths score higher than hand-written ones |
| 14 | `status_code_entropy` | Shannon entropy of the session's status code sequence | Distinct from `error_rate`, see below |

Entropy and error rate answer different questions. A session that is 100% 404 has
a **high error rate** and **zero status entropy** — uniformly failing. A scanner
walking a site collects 200s, 301s, 403s, 404s and 500s: high error rate **and**
high entropy. Only the second pattern is a scanner sweeping a surface.

## Context (15)

| # | Name | Value |
|---|---|---|
| 15 | `same_endpoint_hits` | Hit count of the single most-requested path |

The absolute counterpart to feature 8's ratio. 500 requests to one endpoint and 5
requests to one endpoint both give `unique_endpoint_ratio = 1/n`, but only one of
them is a scraper.

## Additional (16–19)

| # | Name | Value | Notes |
|---|---|---|---|
| 16 | `error_rate` | Fraction of requests with status ≥ 400 | |
| 17 | `image_ratio` | Fraction of requests for `.png .jpg .jpeg .gif .svg .ico .webp` | Browsers pull images with pages; API clients and scrapers usually do not |
| 18 | `night_ratio` | Fraction of requests with local hour in `[2, 6)` | |
| 19 | `max_sustained_click_rate` | Densest 12-second window of HTML requests, divided by 12 | Requests per second, counting only URLs ending in `.html` or `/` |

Feature 19 counts page views, not subresources, which is what makes it a
navigation-speed signal: a person cannot click through six pages in twelve
seconds, and a crawler does it without noticing. It is `0.0` for a session with
fewer than two HTML-ish requests.

Feature 18 is weak on its own — plenty of people are awake at 3am — which is why
the heuristic rule built on it (`labeler.py` rule 13) needs both a night majority
and more than 30 requests before it fires at all, and only at 0.60 confidence.

## Normalization

The raw vector is **not** what the network sees. `BotDetector.predict()` applies
min-max scaling from `microguard/data/normalization.json`, per feature:

```
normalized_i = (raw_i - mins[i]) / (maxs[i] - mins[i])      when maxs[i] > mins[i]
normalized_i = 0.0                                          otherwise
```

Those ranges come from the training set (`training/train.py:58`) and are written
next to `model.json` at training time. Without them, `predict()` logs a warning
and feeds raw values into weights calibrated for 0–1 inputs — scores stay in
range but stop meaning anything. See [the model](reference-model.md).

This is also why a raw feature value in the scan output can be 1200 while another
is 0.5: the report shows raw values, and the dashboard's feature bars scale each
one against the largest in that session rather than implying a shared 0–1 scale.

## Known weaknesses

Stated plainly, because they bound what any score built on these can mean:

- **Only 9 of the 19 features vary meaningfully** in the human baseline the model
  was trained against. The rest are near-constant on that data, so the network
  had little signal to learn from them.
- **Features 10–12 are all User-Agent.** An actor that copies a real browser UA
  moves three features at once, and nothing else in the vector notices.
- **No TLS or HTTP/2 fingerprinting.** Everything here comes from a log line, so
  a bot that produces plausible log lines looks plausible.
- **Feature 11 infers a header it never sees.** See above.

## Related

- [The heuristic rules](reference-heuristic-rules.md) — what fires on these values
- [How detection works](explanation-how-detection-works.md) — how features, rules and the model combine
- [The model](reference-model.md) — the network these feed
- [CLI reference](reference-cli.md) — `--verbose` prints all 19 per session
