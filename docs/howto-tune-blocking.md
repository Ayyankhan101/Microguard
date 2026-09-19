# How to tune blocking

Diagnose why a specific request was blocked or allowed, and change the setting
that governs it. By the end you will be able to answer "why did this customer get
a 403?" from the response alone.

## Prerequisites

- A running deployment ([nginx](howto-deploy-behind-nginx.md) or [in-process](howto-deploy-in-process.md))
- Ability to reproduce the request, or its logged `X-Microguard-*` headers

## Diagnose first

Never change the threshold before you know which half of the score drove the
decision. Reproduce the request against the check server and read the whole
payload:

```bash
curl -s http://127.0.0.1:8400/check \
  -H "X-Real-IP: 203.0.113.9" \
  -H "User-Agent: <the client's user agent>" \
  -H "X-Original-URI: /the/path" | python -m json.tool
```

```json
{
    "label": "bot",
    "score": 0.95,
    "model_score": 0.7312190965985853,
    "heuristic_label": "bot",
    "heuristic_confidence": 0.95,
    "heuristic_reason": "vulnerability scanner pattern detected",
    "request_count": 3,
    "model_loaded": true
}
```

Read it in this order:

1. **`model_loaded`** — if `false`, the model is not contributing at all and every
   decision is coming from the rules. Fix that before tuning anything.
2. **`heuristic_reason`** — which rule fired, in plain English. This is usually
   the whole answer.
3. **`heuristic_confidence` vs `model_score`** — who was more sure. A high
   confidence with a low model score means a rule drove it; the reverse means the
   model did.
4. **`score`** — the blend that was compared against your threshold. If it equals
   `heuristic_confidence` exactly, a confident rule set a floor and the model was
   outvoted.

## Fix a false positive

### The rule that fired is wrong for your traffic

If `heuristic_reason` describes something normal for your site — "all N requests
to same endpoint" for a polling client, "high request rate" for a dashboard —
raising the threshold above that rule's confidence stops it blocking unaided:

| `heuristic_reason` | Confidence | Threshold that stops it blocking alone |
|---|---|---|
| known bot/monitoring UA | 0.95 | above 0.95 |
| vulnerability scanner pattern | 0.95 | above 0.95 |
| attack tool detected | 0.90 | above 0.90 |
| uniform timing | 0.90 | above 0.90 |
| all requests use HTTP/1.0 | 0.90 | above 0.90 |
| Cloudflare WAF signals | 0.90 | above 0.90 |
| extremely high request count | 0.85 | **0.85 (the default)** |
| all requests to same endpoint | 0.80 | 0.80 |
| high request rate | 0.75 | 0.75 |
| repeated endpoint hit / no referrer / high error rate | 0.70 | 0.70 |

A confident rule floors the score at its own confidence, so a rule can only block
unaided when its confidence exceeds your threshold. At the default 0.85, the
bottom four rows already need the model to agree.

> **High-volume sites, read this.** On a real image-heavy store, human shoppers
> legitimately make 100+ requests per session (thumbnails, filters, AJAX). The
> volume rules now count only page-like requests (not embedded assets), which on
> the [benchmark](results/2026-09-benchmark.md)'s Zanbil e-commerce log cut the
> `microguard scan` false-positive rate from 57% to 15%. The residual cases are
> genuinely high page counts. The live blocker at 0.85 spares them anyway (that
> rule sits at 0.85 and the block test is strict `>`), but if you run `scan` as
> an audit or lower the live threshold, raise it above 0.85 or exempt your busy
> AJAX paths first.

```bash
microguard serve --block-threshold 0.92
```

```python
app = MicroguardASGI(app, block_threshold=0.92)
```

Raise it in small steps and re-check. Going to 1.0 disables blocking entirely,
which is a legitimate way to run in observe-only mode while you watch the scores.

### Allow a known client

Recognized webhook and RPC user agents are labeled `automated-integration` and are
never blocked, whatever they do. Check whether yours is recognized:

```bash
curl -s http://127.0.0.1:8400/check \
  -H "X-Real-IP: 10.0.0.1" -H "User-Agent: YourBot/1.0" \
  -H "X-Original-URI: /api/hook" | python -c "import json,sys;print(json.load(sys.stdin)['heuristic_label'])"
```

A recognized sender returns `automated-integration`:

```
$ curl ... -H "User-Agent: Stripe/1.0 (+https://stripe.com/docs/webhooks)" ...
automated-integration

$ curl ... -H "User-Agent: YourBot/1.0" ...
bot
```

The recognized list covers webhook senders (Stripe, GitHub-Hookshot, Shopify,
Slack-Webhooks, PayPal-IPN, Twilio, svix, WhatsApp, Zapier, HubSpot, Mailgun) and
gRPC client libraries (`grpc-go`, `grpc-python`, and siblings). Anything else is
scored normally — note that `Slackbot` on its own is not recognized, only
`Slackbot-LinkExpanding` and `Slack-Webhooks`.

If your client is not recognized, the durable fix is to add its pattern to
`KNOWN_AUTOMATED_CLIENT_PATTERNS` in `microguard/labeler.py`. The quick fix is to
exempt its path at the proxy:

```nginx
location /api/webhooks/ {
    proxy_pass http://your-backend;   # no auth_request here
}
```

### Everyone is blocked at a low threshold

A client with no history scores exactly 0.5 — the neutral verdict. Thresholds
below 0.5 will block traffic that microguard has no opinion about. Do not run
below 0.5 unless you mean it.

## Fix a false negative

### Bots are getting through

Lower the threshold so the sequence rules can block on their own, using the table
above to pick the value. Dropping from 0.85 to 0.75 lets "all requests to same
endpoint" and "extremely high request count" block unaided.

The [benchmark](results/2026-09-benchmark.md) makes the case concrete: at the
default 0.85 the blend catches fewer evasive bots than the rule labeler alone
(44% vs 100% of browser-UA-spoofing bots in the pre-fix run), because the
near-constant model score never lifts a 0.70–0.85 rule over the bar. The clearest
of those — credential/API-key brute-force — has since been promoted to 0.90 so it
blocks at the default. The remaining gap is the medium rules (high request rate,
same-endpoint) that stay below the bar on purpose, since they also describe busy
humans; if you have watched your own traffic and trust the rule set, dropping the
threshold toward 0.75 recovers the rest — after confirming it does not also catch
the high-volume humans above.

Do this only after checking `model_loaded` is `true`. Without the model, lowering
the threshold is the only lever you have, and it is the blunt one.

### A bot rotates its IP

Sessions key on the client IP, so an attacker with a large address pool gets a
fresh session per request and never accumulates history. Confirm it by checking
whether `request_count` stays at 1 across an attack.

Microguard cannot fix this on its own — it needs a stable identifier. Rate-limit
by subnet at your proxy, or front the site with something that fingerprints
beyond the IP.

### Detection got weaker as an attack continued

Sessions retain the last 200 requests, and the session clock tracks that window,
so a long flood is judged on its recent shape rather than its whole life. That is
deliberate. If a flood is being missed, check `request_count` — if it is pinned at
200, the rules are seeing a full window and the issue is threshold, not memory.

## Verification

After any change, confirm both directions still hold. A known-bad path must
still be blocked:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8400/check \
  -H "X-Real-IP: 198.51.100.1" -H "X-Original-URI: /wp-admin/setup-config.php"
```

```
403
```

And the traffic you were fixing must now pass:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8400/check \
  -H "X-Real-IP: 198.51.100.2" -H "User-Agent: <the client>" -H "X-Original-URI: /the/path"
```

```
200
```

Use fresh IPs for these checks, or `redis-cli flushdb` first — a session from an
earlier test will change the answer.

## Troubleshooting

**Changing the threshold had no effect.** Confirm you restarted the process. Both
the CLI flag and the constructor argument are read once at startup.

**`score` never moves regardless of traffic.** Check `model_loaded`. If it is
`false`, every score is coming from the rules and will only take the discrete
values in the table above.

**Scores changed after a redeploy.** The model file may have been retrained.
`model_score` in the payload tells you what the model is contributing now.

## Related

- [How blocking works](explanation-how-blocking-works.md#how-the-score-is-built) — why a confident rule sets a floor
- [API reference](reference-live-api.md#decision-payload) — every field in the payload
- [Deploy behind nginx](howto-deploy-behind-nginx.md) · [Deploy in-process](howto-deploy-in-process.md)
