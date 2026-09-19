# Collect real sessions on EC2

The model cannot be trained honestly without real human sessions extracted by
the same `extract_features` as the bot class — see
[explanation-training-data.md](explanation-training-data.md#the-suspicion-above-measured)
for why none exist in this repo. This is how to get them.

## The part people get backwards

**The gap is the human class, not the bot class.** The repo already holds real
bot traffic: 482 ground-truth attacks plus 2,098 heuristic-labeled sessions
from organization-x. Standing a server on the internet attracts more bots
within hours, for free, and solves the half that is already solved.

Real human sessions need real humans. The server is the easy part; **sharing
the link is the step that produces the data.**

## The fast, free path: a tunnel session

Before renting a server, run [`scripts/collect-session.sh`](../scripts/collect-session.sh)
— it does the whole loop on your laptop behind a free HTTPS tunnel:

```bash
redis-server &                       # any local Redis
bash scripts/collect-session.sh      # cloudflared (no account); --tunnel ngrok also works
```

It serves a small honest landing page with the fingerprint script, runs
`microguard serve` observe-only (`--block-threshold 1.0`, nothing is blocked),
opens a `https://…trycloudflare.com` tunnel, self-checks that the fingerprint
route works, and prints a `?ref=<token>` invite link. Share that link with ~30
people you know, let them browse for a minute, then press Ctrl-C — it prints the
exact `microguard evaluate …` command to label what you collected.

The HTTPS tunnel matters: the fingerprint script needs a secure context
(`SubtleCrypto` is HTTPS/localhost only), so a plain-HTTP LAN link would collect
visits that can never be labeled human. Keep the link to people you know — a
public link gets crawled, and a JS-running crawler would pollute the human
label. The EC2 path below is the internet-scale version of the same thing.

## Cost and constraints

- `t3.micro` in `ap-southeast-2`, the project's assigned Region. Regional
  resources cannot be created elsewhere.
- Free-tier eligible for 12 months; roughly $8-10/month after that. Check your
  spend limit in AWS Settings > Billing before starting — if a project is
  paused for exceeding one, resources return "Access Denied" on operations
  that worked yesterday.
- Terminate the instance when collection is done. The archive is a file; copy
  it off first.

## 1. Provision

```bash
aws login                                   # interactive; only you can do this
aws ec2 run-instances \
  --region ap-southeast-2 \
  --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --instance-type t3.micro \
  --key-name <your-key> \
  --security-group-ids <sg-id> \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=microguard-collector}]'
```

The security group opens **22, 80, 443 only**. Never publish 8400: `/check` is
an oracle, and the design assumes only nginx can reach it.

Point a domain's A record at the public IP. Any domain works; the fingerprint
script needs a hostname for TLS, not a reputation.

## 2. Bootstrap

```bash
scp scripts/provision-collector.sh ec2-user@<ip>:
ssh ec2-user@<ip> 'sudo bash provision-collector.sh collect.example.com'
```

Installs nginx (verifying `ngx_http_auth_request_module` is present and
failing loudly if not), Redis on loopback, Microguard, and systemd units for
`serve` and `signals`. It starts with `--block-threshold 1.0`, which with a
strict `>` comparison means **no score can ever exceed it** — every request is
scored and recorded, nothing is denied.

## 3. TLS — mandatory, not cosmetic

```bash
sudo dnf -y install certbot python3-certbot-nginx
sudo certbot --nginx -d collect.example.com
```

`crypto.subtle` requires a secure context. Over plain HTTP the fingerprint
script is inert, every visitor looks like one that refused to fingerprint, and
the absence rule then makes your whole site look bot-infested. Do not promote
the `fingerprint` signal until TLS is live.

Then add the script to your page, inside `<body>`:

```html
<script src="/microguard/fingerprint.js" defer></script>
```

## 4. Verify before sharing the link

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://collect.example.com/   # 200
systemctl is-active microguard-serve microguard-signals nginx redis6
```

A non-200 here means visitors get a 500, because nginx turns any
non-2xx/401/403 from `auth_request` into one. Check this before anyone else
sees the site.

## 5. Share it, and wait

Post the link to your cohort, class group, or socials. **Leave it at least 48
hours** — bot traffic is diurnal and a six-hour sample will mislead you.

Expect 30-100 human sessions from a shared link. That clears
`--min-examples 50` for a retrain, and more importantly it is enough for
`tests/test_dataset_integrity.py` to say whether the leak is gone.

## 6. Bring the archive home

```bash
scp ec2-user@<ip>:/var/lib/microguard/collected.jsonl .
wc -l collected.jsonl
```

Then follow
[howto-retrain-the-model.md](howto-retrain-the-model.md#collect-real-sessions-then-label-them):
review a sample with `microguard explain <ip>`, confirm labels through the
dashboard, and retrain.

**Collected rows are not labels.** They record what the tool guessed. Training
on them teaches the model to reproduce `labeler.py`, and
`compute_combined_score` blends the two — so one signal would be counted twice
while reading as two. A label exists only after a human looked.

## Watching it while it runs

The dashboard binds loopback and has no authentication. Reach it over a tunnel,
never by publishing the port:

```bash
ssh -L 8500:127.0.0.1:8500 ec2-user@<ip>
microguard dashboard          # on the instance
```

The shadow counter shows how many requests a candidate threshold *would* have
blocked. That number, on your own traffic, is the one worth staring at before
any threshold is ever lowered.

## If you cannot get an audience

Browse the site yourself across phone, laptop, and two browsers over a few
days. Maybe 10-30 sessions — below the retrain threshold, but the integrity
tests still work, and "the leak disappears once the human class comes from
real extraction" is the finding worth writing up. The model's accuracy is not.

## Related

- [howto-deploy-behind-nginx.md](howto-deploy-behind-nginx.md) — the nginx
  contract in detail, including why every failure mode is fail-open
- [explanation-training-data.md](explanation-training-data.md) — what the model
  actually learned, and why it needs this
- [howto-tune-blocking.md](howto-tune-blocking.md) — promoting signals one at a
  time once you have data
