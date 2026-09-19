# How to scan log files

Analyze an access log for bot traffic, investigate what the verdicts were based
on, and turn the result into firewall rules. By the end you will have a scan you
can act on and a rule file you can paste into nginx or Cloudflare.

## Prerequisites

- `pip install microguard` (no extras needed — scanning is the base install)
- An access log in nginx combined format or JSON-per-line. `.gz` works directly.

## Run a scan

```bash
microguard scan /var/log/nginx/access.log
```

```
  Microguard Bot Traffic Report
  ─────────────────────────────

  🚨 Bot Traffic: 50.0%  CRITICAL

  Total sessions:  2
  Human sessions:  1
  Bot sessions:    1

  IP                 Score Bar          Risk      Label    Reqs    Dur Heuristic Rule
  ────────────────────────────────────────────────────────────────────────────────────
  10.0.0.50          0.95 █████████░ DANGER    bot         1   0.0s known bot/monitoring UA: python-req
  192.168.1.100      0.25 ██░░░░░░░░ SAFE      human       5  34.0s known browser, reasonable session (
```

The terminal report shows the **top 10 sessions only**. Use `--output json` or
`--output html` when you need all of them.

The `Heuristic Rule` column is the single most useful thing on screen. It names
which rule fired, so `known bot/monitoring UA: python-requests/2.28.0` is a
verdict you can explain to whoever asks.

## Handle other formats

```bash
microguard scan access.log.gz                  # gzip, decompressed transparently
microguard scan app.json --format json         # JSON-per-line
microguard scan access.log --format nginx      # skip auto-detection
```

Auto-detection reads up to 10 lines. It only recognizes nginx combined and
JSON-per-line; anything else parses as zero entries and returns the error
variant rather than a crash:

```bash
microguard scan /etc/hosts
# ❌ No valid log entries found
```

The JSON parser accepts several field spellings — `remote_addr` / `ip` /
`client_ip`, `http_user_agent` / `user_agent` / `ua`, and so on — so most
structured log shippers work without reformatting.

## Choose a threshold

The default is 0.7. Sessions scoring at or above it are labeled `bot`.

```bash
microguard scan access.log --threshold 0.85   # fewer, higher-confidence bots
microguard scan access.log --threshold 0.5    # more, including weaker signals
```

Which rules can flag a session on their own depends entirely on this number,
because a confident rule floors the blended score at its own confidence:

| Threshold | Rules that flag unaided |
|---|---|
| 0.85 | known bot UA, scanner paths, attack tools, uniform timing, HTTP/1.0-only |
| 0.7 | the above, plus request count, single endpoint, request rate |
| 0.5 | the above, plus unknown UA, short burst, night-time volume |

[The rule reference](reference-heuristic-rules.md) lists every rule with its
confidence. Start high and lower it while watching what gets caught.

## Investigate a verdict

```bash
microguard scan access.log --verbose
```

Prints every session with all 19 features and the rule breakdown. This is how you
answer "why was this session flagged?" when the one-line reason is not enough —
see [the feature reference](reference-features.md) for what each value means.

Note that `--verbose` overrides `--output`. Asking for `--verbose --output html`
gets you the verbose terminal dump.

## Get machine-readable output

```bash
microguard scan access.log --output json 2>/dev/null > scan.json
jq '.bot_rate' scan.json
jq '.sessions[] | select(.label=="bot") | {ip, score, heuristic_reason}' scan.json
```

The `2>/dev/null` is worth keeping: progress messages go to stderr and the report
to stdout, so without it your JSON is clean but your terminal is noisy.

**`--json-pretty` is not JSON.** It is ANSI-colored and shaped like JSON for
reading. Never pipe it to a parser.

Two things to handle in the output:

- `sessions` comes back unsorted. Sort it yourself.
- A failed scan returns a shorter object with an `error` key and no `summary`.
  Check `error` first. Full shape in the
  [CLI reference](reference-cli.md#scan-result-schema).

## Share a report

```bash
microguard scan access.log --output html --output-file report.html
```

A standalone document — no external assets, no scripts, opens anywhere.

**Do not serve that file from a domain you care about.** `format_html()` does not
escape its input, and user agents and URLs in your log are attacker-controlled.
Email it, open it locally, keep it off a trusted origin. The
[dashboard](howto-run-the-dashboard.md) is the safe way to browse a scan in a
browser.

## Generate firewall rules

Both formats emit rules for **DANGER-scored IPs only** — blended score above
0.79.

```bash
microguard scan access.log --output nginx
# deny 203.0.113.9;
# deny 192.0.2.44;

microguard scan access.log --output cloudflare
# (ip.src in {203.0.113.9 192.0.2.44})
```

To apply the nginx rules:

```bash
microguard scan access.log --output nginx --output-file /etc/nginx/blocked.conf
# then inside the relevant server block: include /etc/nginx/blocked.conf;
nginx -t && nginx -s reload
```

Read the list before you load it. An IP is a poor identifier for a person: shared
NAT puts many users behind one address, and a blocked mobile carrier IP takes out
more than the bot. For anything ongoing, block on behavior at request time with
[the live path](tutorial-real-time-blocking.md) rather than accumulating a
static deny list.

## Use it in CI

```bash
microguard scan access.log
echo $?    # 1 if the bot rate is above 10%, else 0
```

Exit code 1 also means the file was missing or unwritable, so it does not
distinguish "found bots" from "crashed". If that matters, check the output:

```bash
output=$(microguard scan access.log 2>&1)
if echo "$output" | grep -q "Traceback (most recent call last)"; then
  echo "microguard crashed"; exit 1
fi
```

## Verification

Confirm the tool works on a log you know:

```bash
microguard scan data/sample_access.log
```

Two sessions, one bot (`python-requests`), one human (a browser over 34 seconds).
If you see that, parsing, features, rules and the model are all working.

## Troubleshooting

**`❌ No valid log entries found`** — the format was not recognized. Check a line
against nginx combined format, or pass `--format json` explicitly. A custom
`log_format` in nginx is the usual cause.

**`📋 No pre-trained model found, using heuristic rules`** — `microguard/data/model.json` is
missing, so every score is rules-only and `model_score` is 0.00 throughout.
Scores are still produced; they are just weaker. See
[retraining](howto-retrain-the-model.md).

**Every session looks like one enormous session** — all your entries share an IP,
usually because the log is behind a proxy that did not set `X-Forwarded-For`, or
the dataset is anonymized. Sessions key on IP by default.

**Bot rate of 100% on an internal service** — health checks and monitoring agents
are bots by every definition here. Check the reasons; if they are
`Uptime-Kuma` or `Prometheus`, that is a correct answer to a question you did not
mean to ask.

**A GraphQL API flagged as scrapers** — the single-endpoint exemption is
path-based and matches `/graphql`, `/trpc/`, `/soap` and similar. An API at a
custom path is not exempt. See
[the rule reference](reference-heuristic-rules.md).

## Related

- [CLI reference](reference-cli.md) — every flag, exit code and output format
- [The heuristic rules](reference-heuristic-rules.md) — what fired and why
- [The 19 features](reference-features.md) — what `--verbose` prints
- [Monitor a log in real time](howto-monitor-a-log-in-real-time.md) — the streaming version
- [Run the dashboard](howto-run-the-dashboard.md) — browse a scan interactively
