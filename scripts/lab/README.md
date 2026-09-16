# Local realism lab

Answers two questions without a public server: does microguard tell bots from
humans on realistic traffic, and how much of that work the micrograd model
actually does versus the heuristic rules.

It runs the **real** production path — nginx `auth_request` → `microguard serve`
→ the real scorer, features, labeler, model, and Redis session store — and
drives it with real attack tools and realistic human sessions. Nothing is ever
blocked (`--block-threshold 1.0`); every decision is scored and archived.

## Run

```bash
brew install nginx nuclei ffuf sqlmap   # one-time; missing tools are skipped
redis-server &                          # or any local Redis; the lab uses db 15
bash scripts/lab/run.sh                 # HUMANS=45 SCRAPERS=22 CRED=14 to resize
```

It prints, and saves under `scripts/lab/.run/`:

- **`microguard evaluate`** — the field view, labeling actors the way the real
  tool would from honeypot and invite-link evidence.
- **scorecard** — the exact view, because the lab assigns every actor its class
  up front (bot IPs in `10.66.*`, human IPs in `10.99.*`, carried in
  `X-Forwarded-For`). It scores model-only, heuristic-only, and blend against
  that ground truth.

## How ground truth is made

- **Bots:** `ffuf`, `sqlmap`, `nuclei`, plus scripted scrapers and
  credential-probe loops. Each carries a distinct source IP.
- **Humans:** multi-page sessions with browser User-Agents, referer chains,
  human-scale gaps, an invite `?ref=` link, and a fingerprint POST.

## Honesty about the humans

The human sessions are scripted, not real people, so the human false-positive
rate is a property of what a plausible human request sequence looks like, not of
real visitors. For real humans you need the live EC2 run in
[../../docs/howto-evaluate-on-live-traffic.md](../../docs/howto-evaluate-on-live-traffic.md).
The bot traffic, by contrast, is genuine tool output.
