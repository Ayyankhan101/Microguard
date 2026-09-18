# How detection works

Microguard turns a pile of log lines into one number per visitor. This explains
how, and why it is built as two scorers rather than one.

## The problem

You want to know which of your traffic is automated and hostile. You have access
logs: an IP, a timestamp, a method, a path, a status, a size, a referrer, a user
agent. That is all. No TLS fingerprint, no JavaScript challenge, no mouse
movement, no cookies you can trust.

Two approaches suggest themselves, and both fail alone.

**Rules alone** are readable and explain themselves — "this UA says curl" is an
answer you can give a customer. But they are a fixed list. Anything that does
not match a pattern someone thought of is invisible, and a bot author reads the
same list you do.

**A model alone** generalizes to patterns nobody enumerated. But it cannot tell
you why, and when it is wrong it is confidently wrong. Worse, a model trained on
heuristic labels cannot be better than the heuristics at the thing the
heuristics already catch — it just launders them into something unexplainable.

So microguard runs both and blends them, with the rules holding a veto in both
directions.

## The path a request takes

```
  log lines  ──►  group into sessions  ──►  one session
                                                │
                          ┌─────────────────────┼─────────────────────┐
                          ▼                                           ▼
                   label_session()                            extract_features()
                   ~24 ordered rules                            19 floats
                          │                                           │
              (label, confidence, reason)                   min-max normalize
               'bot' 0.95 'known bot UA'                            │
                          │                                   BotDetector.predict()
                          │                                    logit → sigmoid
                          │                                           │
                          └──────────────┬────────────────────────────┘
                                         ▼
                            compute_combined_score()
                              0.6 × model + 0.4 × rules
                              floored / capped by the rules
                                         │
                                    score > threshold ?
                                    ┌────┴────┐
                                  bot        human
```

Every path through the product uses this same pipeline. `scan` runs it over a
log file, `watch` over a tail, and the live path over one request at a time with
the session history held in Redis. The only differences are where the session
comes from and which threshold the score is compared against.

## Sessions, not requests

Nothing here scores a single request, because a single request carries almost no
signal. One GET with a browser UA looks identical whether it came from a person
or a script.

A session — one actor's requests, grouped until a 30-minute gap — carries
behavior: the rhythm between requests, how many distinct paths, whether errors
cluster, whether images came along with pages. That is where bots differ from
people.

The consequence is that microguard is always late. The first request from a new
actor has no history, so it scores as an unknown visitor and is allowed. Blocking
begins once a pattern exists. This is a deliberate trade: the alternative is
blocking on first sight based on a UA string, which is both easy to spoof and
easy to get catastrophically wrong.

## Two scorers

**The rules** (`label_session`) are ~24 ordered checks, first match wins,
returning a label, a hand-set confidence, and a sentence. They catch the things
that are definitional rather than statistical: a UA that says `sqlmap`, a request
for `/.env`, five requests spaced exactly 200ms apart. Each carries a confidence
between 0.50 and 0.95, and those numbers are policy, not probability — they say
how much this rule is allowed to decide on its own.

**The model** (`BotDetector`) is a 19→4→1 network over the extracted features. It
has no access to the UA string as text, only to `ua_category` as a number, and no
access to paths as text, only to counts and entropies. It is looking for shape:
sessions whose timing, spread and error profile resemble sessions that were
labeled bot during training.

They fail differently, which is the point. The rules miss anything unlisted. The
model misses anything whose shape resembles normal traffic. A bot has to beat
both.

## The blend, and the veto

```python
combined = 0.6 * model_score + 0.4 * heuristic_confidence
if heuristic_label == 'bot':
    combined = max(combined, heuristic_confidence)      # floor
elif heuristic_label == 'human':
    combined = min(combined, 1.0 - heuristic_confidence) # cap
```

The 60/40 weighting is the ordinary case. The floor and the cap are what make it
work.

**The floor** stops a weak model diluting a strong rule. A session with a
`sqlmap` user agent gets heuristic confidence 0.95. Without the floor, a model
score of 0.1 would drag the blend to 0.44 and let it through. With it, the score
cannot fall below 0.95. A rule that is definitionally right should not need the
model's permission.

**The cap** is the same protection in the other direction, and it exists because
of a specific failure. A GraphQL client sends every request to `/graphql`. The
model sees `unique_endpoint_ratio` near zero and `same_endpoint_hits` high — the
shape of a scraper — and scores it 0.9. The rules recognize the single-endpoint
API and return human at 0.65. Without the cap, the blend is 0.80 and a legitimate
customer is blocked by a model that learned "one endpoint means scraper" from
REST traffic. With it, the score cannot exceed 0.35.

The cap was added after that exact case. The asymmetry between them — a confident
human rule caps at `1 - confidence`, so 0.75 confidence caps the score at 0.25 —
is deliberate: it takes less certainty to protect a customer than to block one.

## Thresholds, and why there are two

| Path | Threshold | Comparison |
|---|---|---|
| `scan`, `watch`, `probe` | 0.7 | `>=` |
| `serve`, middleware | 0.85 | strict `>` |

Batch analysis is advisory. Nobody is harmed by a report that flags a borderline
session, so it can afford to flag more.

Live blocking turns the number into a 403 for someone trying to use your site,
so it demands more agreement. At 0.85 only the 0.90–0.95 rules clear the bar
unaided — known bot UA, scanner paths, attack tools, uniform timing,
HTTP/1.0-only. Everything weaker, including "high request rate" at 0.75 and "all
requests to one endpoint" at 0.80, needs the model to agree. Those weaker rules
also describe a polling client and a single-endpoint app, which is exactly why
they do not get to block alone.

The [benchmark](results/2026-09-benchmark.md) measured what this costs. Because
the model is a near-constant ≈ 0.6 on the live path (it does not "agree" with
anything in particular), the weaker rules never get lifted over 0.85 — so the
blend at 0.85 catches materially fewer bots than the rule labeler alone. On the
evasion ladder the rule labeler flags 100% of browser-UA-spoofing bots while
the shipped blend flags 44%. That is the design working as intended (a weak
rule should not block a polling client), but the cost is real: if you trust
your rule set, the blend threshold is leaving recall on the table. See
[tune blocking](howto-tune-blocking.md).

The strict `>` on the live path matters at the edges. At threshold 0.5 the
neutral verdict — "no strong signals either way", human at 0.50 — produces
exactly 0.5, and a `>=` would block every unknown visitor. It also makes
threshold 1.0 a real never-block setting, which is the supported way to run in
observe-only mode while you watch scores on live traffic.

## Automated but not hostile

A Stripe webhook is automated by definition. So is a gRPC client, an uptime
monitor, and your own CI. Calling all of that "bot" and blocking it breaks
integrations while catching nothing.

Recognized senders get a third label, `automated-integration`, checked before
every bot rule. On the live path they short-circuit entirely: scored at 0.0,
never blocked, whatever the threshold. In a scan they are counted separately
from both bots and humans, so they do not inflate your bot rate.

This is a recognition list, not a capability check — it matches UA patterns for
Stripe, GitHub, Shopify, Slack, Twilio, the `grpc-<lang>` libraries and others.
Anything sending a webhook with a UA nobody listed still gets scored as traffic.

## What this cannot do

Being explicit, because the number this produces is only as good as its inputs:

- **Everything comes from a log line.** A bot that produces plausible log lines
  looks plausible. There is no TLS fingerprinting, no HTTP/2 frame analysis, no
  browser challenge.
- **User-Agent carries three of the 19 features.** An actor that copies a real
  browser string moves all three at once.
- **The model was trained on heuristic labels** for the human class, so it partly
  learned to imitate the rules rather than to see past them. See
  [training data](explanation-training-data.md).
- **Sessions key on IP by default.** Shared NAT merges many people into one
  session; a rotating residential proxy pool splits one bot into many, each too
  short to accumulate a pattern. The [benchmark](results/2026-09-benchmark.md)
  confirms this is the real blind spot: a distributed browser farm (one profile
  across ten IPs, low volume each) evades the rules entirely.
- **The live check server drops the `Referer`.** `microguard/live/server.py`
  builds every request with `referer=""`, so on the live path the referer-based
  rules and features are inert — the "no referrer on all requests" rule fires on
  any 20-plus-request session regardless of what the client sent. Offline `scan`
  reads the referer from the log; the live path does not.
- **Volume rules cannot tell a busy human from a scraper.** On a real
  image-heavy store, human shoppers make 100+ requests per session, so the
  `extremely high request count` rule flags them — the benchmark measured 57% of
  real human shoppers flagged by `microguard scan`.
- **Sophisticated bots: now measured, not assumed.** The
  [evasion-ladder benchmark](results/2026-09-benchmark.md) drives the same bots
  up to a real headless-browser farm. The rules hold against UA spoofing and
  human pacing but are blind to the distributed low-volume case, and the shipped
  0.85 blend catches far less than the rules alone.

Run it in observe-only mode against your own traffic before you let it block
anything. [Tuning blocking](howto-tune-blocking.md) covers how.

## Related

- [The 19 features](reference-features.md) · [The heuristic rules](reference-heuristic-rules.md)
- [The model](reference-model.md) · [Training data](explanation-training-data.md)
- [How blocking works](explanation-how-blocking-works.md) — the live path specifically
- [How to tune blocking](howto-tune-blocking.md)
