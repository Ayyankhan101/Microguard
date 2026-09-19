# How to monitor a log in real time

Tail a live access log and print bot detections as they appear. By the end you
will have a terminal that reacts within a couple of seconds of a bot hitting
your site.

This is observation, not blocking. To actually stop requests, use
[the live path](tutorial-real-time-blocking.md).

## Prerequisites

- `pip install microguard`
- A log file that is being written to right now

## Start watching

```bash
microguard scan /var/log/nginx/access.log --watch
```

```
  Microguard Watch Mode
  Monitoring: /var/log/nginx/access.log
  Format:     nginx
  Threshold:  0.7
  Model:      heuristic only
  Polling:    every 2.0s
  Press Ctrl+C to stop
  ───────────────────────────────────────────────────────
```

Then, when something trips the threshold:

```
  🚨 Bot Detection — 14:22:07
  ───────────────────────────────────────────────────────
  IP:        203.0.113.9
  Score:     0.950 (DANGER)
  Label:     bot
  Request:   GET /wp-admin/setup-config.php → HTTP 404
  User-Agent: curl/8.0
  Heuristic: 0.95 — vulnerability scanner pattern detected
  ML Model:  0.731
  ───────────────────────────────────────────────────────
```

Every 30 seconds it prints a running tally, and Ctrl+C prints a final total.

## Understand what it does and does not see

Three behaviors worth knowing before you rely on it:

**It starts at the end of the file.** The offset is seeded from the current file
size, so existing content is skipped entirely. Watch mode reports what happens
from now on. To analyze what already happened, run a normal
[scan](howto-scan-log-files.md).

**Sessions do not persist across polls.** Each two-second batch is grouped on its
own with a 5-minute session timeout, so an actor's history does not accumulate
the way it does in a scan or on the live path. A slow scraper making one request
every ten seconds is a fresh one-request session every time and will never build
up a pattern.

**It does not handle log rotation.** The byte offset is never reset, so when
logrotate truncates or replaces the file, watch mode keeps seeking past the new
end and goes silent. Restart it after a rotation.

## Only show high-confidence detections

```bash
microguard scan /var/log/nginx/access.log --watch --threshold 0.9
```

Watch mode uses `>=` against the threshold and defaults to 0.7. Because sessions
are per-batch, the rules that need accumulated history — request count, sustained
rate, repeated endpoint — rarely fire here. What does fire is the per-request
evidence: bot user agents, scanner paths, attack tools. Raising the threshold
mostly filters to those.

## Use the model

```bash
microguard scan /var/log/nginx/access.log --watch --model microguard/data/model.json
```

Unlike `scan`, watch mode does **not** load the model by default —
`model_path` is `None` unless you pass `--model`. Without it, `Model: heuristic
only` appears in the banner and `ML Model` is omitted from every detection
block.

## Run it in the background

```bash
microguard scan /var/log/nginx/access.log --watch > /var/log/microguard-watch.log 2>&1 &
```

The output is ANSI-colored, which is fine in a file you will `less -R`, and
awkward in one you will grep. There is no JSON mode: watch mode prints for humans
only. For machine-readable live decisions, run
[the check server](howto-deploy-behind-nginx.md) and read
[its API](reference-live-api.md), or watch the
[dashboard](howto-run-the-dashboard.md).

## Verification

Prove the whole loop works without waiting for a real bot:

```bash
# terminal 1
microguard scan /tmp/test.log --watch

# terminal 2
printf '203.0.113.9 - - [24/Mar/2026:17:07:41 +0000] "GET /wp-admin/setup-config.php HTTP/1.1" 404 0 "-" "curl/8.0"\n' >> /tmp/test.log
```

Within two seconds terminal 1 prints a detection block naming
`vulnerability scanner pattern detected`. If the file did not exist when watch
started, create it first — watch mode tolerates a missing file but seeds its
offset at 0.

## Troubleshooting

**Nothing appears, ever** — check three things in order. Is the file actually
being appended to (`tail -f` it)? Did it rotate since watch started (restart)? Is
the format being parsed (run a plain `scan` on the same file and see whether it
finds entries)?

**It printed detections and then went quiet** — almost always log rotation.
Restart.

**A legitimate client keeps appearing** — watch mode's 5-minute per-batch
sessions mean the human-side rules that need duration or navigation history
cannot fire. The same traffic scanned as a file will often be labeled correctly.
Trust `scan` over `watch` for the verdict; `watch` is a tripwire, not an
adjudicator.

**`Could not load model`** — the path is wrong or the file is corrupt. Watch mode
warns once and continues on heuristics.

## Related

- [How to scan log files](howto-scan-log-files.md) — the full-history version
- [Tutorial: real-time blocking](tutorial-real-time-blocking.md) — actually stopping requests
- [Run the dashboard](howto-run-the-dashboard.md) — live decisions in a browser
- [CLI reference](reference-cli.md)
