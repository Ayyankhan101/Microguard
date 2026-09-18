# Heuristic rules

`label_session(session)` returns `(label, confidence, reason)`. The label is
`bot`, `human`, or `automated-integration`; the confidence is a fixed number
attached to whichever rule fired; the reason is the plain-English string that
shows up in every report and in the dashboard.

```python
from microguard.labeler import label_session
label, confidence, reason = label_session(session)
# ('bot', 0.95, 'known bot/monitoring UA: curl/8.0')
```

**First match wins.** Rules are evaluated in the order below and the function
returns immediately, so a session matching both rule 1 and rule 16 is reported
only as rule 1. Reading a `reason` tells you which rule fired, not which rules
could have.

The confidence is not a probability. It is a hand-set weight that decides how
much of the blended score this rule can carry on its own — see
[how detection works](explanation-how-detection-works.md) and
[tuning blocking](howto-tune-blocking.md).

## Evaluation order

| # | Label | Conf | Fires when | Reason string |
|---|---|---|---|---|
| 0 | `automated-integration` | 0.90 | UA matches a known webhook or gRPC client | `known automated client (webhook/RPC): <ua>` |
| 1 | `bot` | 0.95 | UA matches a known bot, crawler, monitor or HTTP library | `known bot/monitoring UA: <ua>` |
| 2 | `bot` | 0.95 | Any URL hits a known scanner path | `vulnerability scanner pattern detected` |
| 3 | `bot` | 0.90 | ≥5 requests with near-zero timing variance, and not gRPC-shaped | `uniform timing (avg <x>s, near-zero variance)` |
| 4 | `bot` | 0.90 | >5 requests and every raw line is HTTP/1.0 | `all requests use HTTP/1.0 (not a modern browser)` |
| 5 | `bot` | 0.90 | CDN/WAF bypass UA, or protected-endpoint hits with no referrer anywhere | `Cloudflare WAF: <detail>` |
| 6 | `bot` | 0.90 | UA matches a known attack tool | `attack tool detected: <ua>` |
| 7 | `bot` | 0.88 | Botnet signature (see below) | varies |
| 8 | `bot` | 0.85 | More than 100 requests | `extremely high request count: <n>` |
| 9 | `bot` | 0.80 | >10 requests all to one path, and not a single-endpoint API | `all <n> requests to same endpoint: <path>` |
| 10 | `bot` | 0.75 | >50 req/min sustained (see floors below) | `high request rate: <x> req/min` |
| 11 | `bot` | 0.70 | >20 requests, none with a referrer | `no referrer on all <n> requests` |
| 12 | `bot` | 0.70 | >10 requests and more than half returned ≥400 | `high error rate: <n>/<m> failed requests` |
| 13 | `bot` | 0.70 | One path hit >20 times and >70% of the session, not a single-endpoint API | `repeated endpoint hit <n> times` |
| 14 | `bot` | 0.75 | API key scanning or credential brute force (see below) | varies |
| 15 | `bot` | 0.60 | >5 requests from a UA that is neither a known browser nor empty | `unknown user-agent: <ua>` |
| 16 | `bot` | 0.65 | >20 requests inside 5 seconds — in practice only under 1s, see rule 10 | `<n> requests in <x>s` |
| 17 | `bot` | 0.60 | >30 requests, more than half between 02:00 and 06:00 | `mostly night-time activity (<n>/<m> requests)` |
| 18 | `human` | 0.75 | Browser UA, <50 requests, session longer than 30s | `known browser, reasonable session (<n> req, <x>s)` |
| 19 | `human` | 0.70 | ≥3 requests, longest gap more than 3× the mean | `variable timing (max/avg ratio: <x>)` |
| 20 | `human` | 0.65 | ≥5 requests across ≥5 distinct paths | `exploring <n> different endpoints` |
| 21 | `human` | 0.60 | ≥3 requests, more than half carry a referrer | `natural navigation with <n> referrers` |
| 22 | `human` | 0.65 | CDN UA that is also a browser UA, <30 requests — **unreachable, see below** | `Cloudflare-protected site, normal browser` |
| 23 | `human` | 0.50 | Nothing matched | `no strong signals either way` |

The numbered comments in `labeler.py` do not match this order — several numbers
repeat in the source. This table is the evaluation order as the code runs.

## What counts as a match

**Rule 0 — known automated clients** (`KNOWN_AUTOMATED_CLIENT_PATTERNS`):
Stripe, GitHub-Hookshot, Shopify, Slack webhooks, PayPal IPN, Twilio, svix,
WhatsApp, Zapier, HubSpot, Mailgun, and the `grpc-<lang>` client libraries.

Checked first, on purpose. A Stripe webhook is automated by definition and would
trip rule 15 (unknown UA) or rule 3 (uniform timing) otherwise. It gets a
distinct label rather than being called a bot, and the live path never blocks it
regardless of threshold.

**Rule 1 — known bot UAs** (`HIGH_CONFIDENCE_BOT_PATTERNS`): HTTP libraries
(`curl`, `wget`, `python-requests`, `go-http-client`, `okhttp`, `java/`),
headless browsers (`headless`, `phantom`, `selenium`, `puppeteer`, `playwright`),
monitoring (`Uptime-Kuma`, `Pingdom`, `UptimeRobot`, `Nagios`, `Zabbix`,
`Prometheus`), SEO crawlers (`Semrush`, `Ahrefs`, `MJ12bot`), search and AI
crawlers (`Googlebot`, `Bingbot`, `GPTBot`, `CCBot`, `Bytespider`), and scanners
(`Masscan`, `Nmap`, `ZmEu`, `nikto`, `sqlmap`).

Note that this makes no distinction between Googlebot and sqlmap. Both are
automated; whether you want to block either is your policy, not the labeler's.

**Rule 2 — scanner paths**: `/wp-admin`, `/wp-login`, `/phpmyadmin`, `/.env`,
`/config.json`, `/admin/login`, `/xmlrpc.php`, `/wp-content`, `/wp-includes`,
`/cgi-bin`. One hit anywhere in the session is enough — there is no legitimate
reason for a visitor to your API to ask for `/.env`.

**Rule 3 — uniform timing**, with the gRPC exemption: fires when
`(max_gap - min_gap) / avg_gap < 0.05`, unless the session has 3 or more distinct
gRPC-shaped paths (`/package.Service/Method`, matched by `GRPC_PATH_RE`).
Multiplexed gRPC over one HTTP/2 connection produces genuinely uniform timing
from real clients, so the exemption prevents a whole class of legitimate traffic
being labeled by its transport.

**Rule 5 — CDN/WAF signals** (`_check_cloudflare_signals`): a UA matching
`cf-`, `cloudflare`, `incapsula`, `akamai`, `sucuri`; or one or more requests to
a WAF-protected endpoint (`/wp-admin`, `/.env`, `/.git`, `/admin`, `/console`,
`/api/v1/auth`, …) with **no referrer on any request in the session**.

**Rule 7 — botnet signatures** (`_check_botnet_signatures`), any of:

| Condition | Reason |
|---|---|
| UA matches an attack tool | `attack tool UA: <ua>` |
| >30% of URLs match IoT/router patterns (`/HNAP1`, `/boaform`, `/cgi-bin/luci`, `/shell.cgi`, `/tr069`) | `botnet scanning pattern (<n> IoT endpoint hits)` |
| >30 requests and >70% returned 4xx | `directory brute-force (<n>/<m> 4xx responses)` |
| ≥2 distinct UAs, and more than `min(10, request_count * 0.3)` of them | `UA rotation (<n> variants in <m> requests)` |

The UA-rotation check requires at least 2 variants explicitly. Without that
floor, the scaled threshold drops below 1 for sessions under 4 requests and a
single consistent UA would have counted as rotation.

**Rule 10 — sustained rate**, with floors: `MIN_RATE_WINDOW_S = 1.0` and
`MIN_RATE_REQUESTS = 5`. Below either, the rule does not run.

The floors exist because the same rule runs on both the batch and the live path,
and they carry different clocks. Nginx timestamps are second-granular, so a burst
in a log file has `duration == 0` and the rule is skipped. The live path uses
`time.time()` with microsecond precision, where a browser firing five subresource
requests over 1.5ms extrapolates to roughly 200,000 req/min — a real visitor
blocked by arithmetic. Any rate heuristic shared between the two paths needs
checking against microsecond timestamps, not log-file granularity.

**The two paths also disagree on the `Referer`.** `microguard/live/server.py`
(and the middleware) build every live `LogEntry` with `referer=""` — the
forwarded `Referer` header is never parsed. So on the **live** path rule 11
("no referrer on all requests") fires on any 20-plus-request session regardless
of what the client actually sent, and the human referer rule (rule 21) can never
fire. Offline `scan` reads the referer from the log line, so the same session can
be scored differently by `scan` and by `serve`. The
[benchmark](results/2026-09-benchmark.md) documents this; it inflates live recall
on high-volume clients and is a known gap, not a designed behaviour.

Rule 10's floor also makes **rule 16** mostly unreachable. A session of more than
20 requests spanning 1 to 5 seconds always exceeds 50 req/min, so rule 10 claims
it first at 0.75. Rule 16 only fires when the burst is shorter than
`MIN_RATE_WINDOW_S`, below which rule 10 declines to run at all.

**Rule 14 — credential and key scanning** (`_check_api_key_patterns`), any of:

| Condition | Reason |
|---|---|
| >50% of URLs carry a credential-ish parameter (`?key=`, `?token=`, `?api_key=`, `?password=`, `?secret=`, `?jwt=`) or hit an auth path | `API key parameter scanning (<n>/<m> requests)` |
| ≥5 hits to auth endpoints within 5 minutes, at more than 5/min | `credential brute-force (<n> auth attempts in <x>s)` |
| ≥10 POSTs to auth endpoints | `POST brute-force (<n> POST to auth endpoints)` |

## The single-endpoint API exemption

Rules 9 and 13 both say "everything goes to one path, that is a scraper". For a
REST API with a path per resource, it is. For GraphQL, SOAP, tRPC and RPC-style
APIs, routing every call through one path **is the design**, and without the
exemption every legitimate client of a GraphQL API would be labeled a bot.

`SINGLE_ENDPOINT_API_RE` matches `/graphql`, `/graphiql`, `/trpc/`, `/rpc`,
`/soap`, `/services/`, `.asmx`, `/ws`. When the repeated path matches, rules 9
and 13 are skipped and evaluation continues.

The exemption is path-based, so it only works when the API is reachable at a
recognizable path. A GraphQL endpoint mounted at `/v2/query` is not exempt.

## Rule 22 never fires

`Cloudflare-protected site, normal browser` exists to protect a real visitor
whose user agent carries a CDN marker. It cannot be reached: rule 5 returns
`bot` at 0.90 for **any** UA matching the same CDN pattern, seventeen rules
earlier. A visitor with `akamai` or `cloudflare` in their UA string is therefore
labeled a bot at high confidence.

The rule is marked `# pragma: no cover` in the source with this explanation, and
`tests/test_labeler_rules.py::test_cdn_ua_that_is_also_a_browser_is_labeled_bot`
pins the actual behavior so the eventual fix reads as a deliberate change.

## Human rules are weaker on purpose

The strongest human rule is 0.75; the strongest bot rule is 0.95. The default
when nothing matches is `human` at 0.50.

That asymmetry is a false-positive policy. Blocking a customer costs more than
missing a bot, so ambiguity resolves toward allowing. It also shapes the blend:
`compute_combined_score` floors a confident bot verdict at its own confidence but
caps a confident human verdict at `1 - confidence`, which means a 0.75 human rule
can hold the final score down to 0.25 no matter what the model says. See
[how detection works](explanation-how-detection-works.md).

## Adding or changing a rule

- Rules live in `label_session` in evaluation order. Position matters as much as
  the condition: a rule placed above rule 0 would start labeling webhooks as bots.
- Every rule returns a `reason` that a person will read in a report while asking
  why a customer was blocked. Write it for that moment: name the signal and the
  numbers, not the rule id.
- Rate, frequency, and duration rules need a floor. See rule 10.
- `tests/test_labeler_rules.py` covers rules individually;
  `tests/test_groundtruth.py` checks them against real labeled attack traffic.

## Related

- [The 19 features](reference-features.md) — the values these rules read
- [How detection works](explanation-how-detection-works.md) — how a rule's confidence becomes a score
- [How to tune blocking](howto-tune-blocking.md) — which rules block unaided at which threshold
- [Training data](explanation-training-data.md) — how these rules also generate training labels
