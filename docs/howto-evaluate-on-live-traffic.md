# Evaluate on live traffic

How to find out how many real bots microguard catches and how many real people
it would block, without blocking anyone. It builds on
[howto-collect-real-sessions.md](howto-collect-real-sessions.md): do sections
1-3 there first (provision, bootstrap, TLS).

## Decide before you look

Fixed before any data exists, so the result cannot be argued with afterwards:

1. Fewer than 30 labeled humans or 30 labeled bots: **inconclusive**. Report
   counts, change nothing.
2. Blocking can be enabled at threshold T only if **humans flagged at T is 0/N**.
3. The model earns its place only if some threshold with 0 humans flagged
   catches more **honeypot-only** bots than the `heuristic label is bot` row.
4. Heuristic reasons that never appear are listed as removal candidates.

## 1. Build the page

Ground truth comes from the page, so its three parts are not optional. On the
instance:

```bash
sudo tee /usr/share/nginx/html/index.html >/dev/null <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microguard: end-semester project</title></head>
<body>
<h1>Microguard</h1>
<p>Bot detection built on micrograd. Read about <a href="/how.html">how it works</a>.</p>
<a href="/_hp/archive" style="display:none" tabindex="-1" aria-hidden="true" rel="nofollow">archive</a>
<script src="/microguard/fingerprint.js" defer></script>
</body></html>
HTML
sudo tee /usr/share/nginx/html/robots.txt >/dev/null <<'TXT'
User-agent: *
Disallow: /_hp/
TXT
```

Add a second page, `how.html`, with real content and the same `<script>` tag. A
visitor who clicks through produces a longer session, and the features need one.

## 2. Verify the three claims before sharing anything

**Fingerprints bind.** Open `https://<domain>/?ref=self` in a real browser, then:

```bash
sudo tail -n 5 /var/log/nginx/access.log | grep 'POST /microguard/fp'
redis6-cli --scan --pattern 'mg:v1:fp:*' | head
```

Both must show your IP. If the POST is missing, check TLS (`crypto.subtle`
needs HTTPS) and the `/microguard/` location. Stop here until it works: without
it nobody can be labeled human.

**Latency.** The check runs on every page request:

```bash
sudo dnf -y install httpd-tools
ab -n 2000 -c 10 -H 'X-Real-IP: 127.0.0.1' -H 'X-Original-URI: /' \
   http://127.0.0.1:8400/check | grep -E '^ +(50|99)%'
```

Write down p50 and p99. The target is p99 under 20 ms on a `t3.micro`; a miss is
a finding, not a blocker. Loopback traffic is excluded from the evaluation.

**Fail-open.**

```bash
sudo systemctl stop redis6
curl -sS -o /dev/null -w '%{http_code}\n' https://<domain>/   # must be 200
sudo systemctl start redis6
```

## 3. Share private invite links, one token per channel

Make a short random token for each place you share, and keep a list:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(4))"
```

Share `https://<domain>/?ref=<token>` in private channels only: class group,
friends, family. A link posted publicly gets followed by crawlers, and a
crawler that runs JavaScript would be labeled human. Use `?ref=self` for your
own devices.

## 4. Run for 72 hours, and check at 24

Bot traffic is diurnal, and 72 hours covers three cycles. At 24 hours, pull the
files and run the evaluation once, only to catch a broken setup:

Both files are root-owned on the instance, so copy them through `sudo tar`
rather than `scp`:

```bash
mkdir -p eval
ssh ec2-user@<ip> 'sudo tar -C / -czf - var/log/nginx var/lib/microguard/collected.jsonl' \
  | tar -C eval -xzf -
microguard evaluate --collected eval/var/lib/microguard/collected.jsonl \
  $(for f in eval/var/log/nginx/access.log*; do printf -- '--access-log %s ' "$f"; done) \
  --invite-token self --invite-token <token1> --invite-token <token2>
```

If `Invited actors that ran the fingerprint script` is near zero, fix the setup
now. Don't read the rates at 24 hours, and don't change anything because of them.

To watch live, use the dashboard over the tunnel described in
[howto-collect-real-sessions.md](howto-collect-real-sessions.md#watching-it-while-it-runs).

## 5. Final report

After 72 hours, pull the files again and run the same command, saving the
output:

```bash
microguard evaluate ... > docs/results/<yyyy-mm>-live-evaluation.md
```

Below the generated report, write the decision under each rule from "Decide
before you look", quoting the row it rests on. Then read at least ten of the
listed unlabeled-but-flagged IPs in the access log
(`zgrep -h '^<ip> ' eval/var/log/nginx/access.log*`) and note what each looked like.

## 6. Clean up

Terminate the instance once the files are copied off. It costs money while it
runs, and it is an internet-facing box you are no longer watching.

## What this cannot tell you

- **Recall is an upper bound.** Labeled bots are the ones that touched a trap.
  A careful headless browser does not, and stays unlabeled.
- **The human flag rate is a lower bound.** People who block JavaScript cannot
  be labeled human.
- **One IP is one actor.** A campus NAT merges people; the conflict count shows
  how often.
