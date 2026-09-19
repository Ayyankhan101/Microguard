# Microguard documentation

Organized by what you are trying to do, following
[Diataxis](https://diataxis.fr): tutorials teach, how-tos solve a task,
references describe, explanations give the reasoning.

## Start here

| If you want to… | Read |
|---|---|
| Find bots in a log file, having never used this | [Your first scan](tutorial-first-scan.md) |
| Block bots in real time, having never used this | [Block your first bot](tutorial-real-time-blocking.md) |
| See decisions as they happen, in a browser | [Watch a bot get blocked](tutorial-the-dashboard.md) |

## Tutorials

Learning-oriented. Start from nothing, end with something working.

- [Your first scan](tutorial-first-scan.md) — install to firewall rules, using the bundled sample
- [Block your first bot](tutorial-real-time-blocking.md) — the live path end to end
- [Watch a bot get blocked](tutorial-the-dashboard.md) — the dashboard, including retuning without a restart

## How-to guides

Task-oriented. You know roughly what you are doing and want it done.

**Analysis**

- [Scan log files](howto-scan-log-files.md) — formats, thresholds, JSON output, firewall rules, CI
- [Monitor a log in real time](howto-monitor-a-log-in-real-time.md) — watch mode, and its three limits
- [Probe an endpoint](howto-probe-an-endpoint.md) — HTTP and WebSocket fingerprinting, and what it does not measure

**Blocking**

- [Deploy behind nginx](howto-deploy-behind-nginx.md) — `auth_request` against the check server
- [Deploy in-process](howto-deploy-in-process.md) — ASGI and WSGI middleware
- [Tune blocking](howto-tune-blocking.md) — diagnose a verdict, then change the setting behind it

**Operating and developing**

- [Operate it](howto-operate-microguard.md) — running it by hand: health checks, the three failure modes, restarting, housekeeping
- [Run the dashboard](howto-run-the-dashboard.md) — the web UI and its API
- [Collect real sessions on EC2](howto-collect-real-sessions.md) — observe-only collection, the only source of real human training data
- [Evaluate on live traffic](howto-evaluate-on-live-traffic.md) — honeypot and invite-link ground truth, decision rules fixed in advance
- [Retrain the model](howto-retrain-the-model.md) — the training pipeline and how to read its numbers
- [Work on the dashboard UI](howto-work-on-the-gui.md) — the TypeScript side, and the fixture contract

## Reference

Information-oriented. Complete and accurate; look things up here.

- [CLI reference](reference-cli.md) — every command, flag, exit code, output format, result schema
- [The 19 features](reference-features.md) — what each one measures and how it is computed
- [The heuristic rules](reference-heuristic-rules.md) — every rule in evaluation order, with confidences
- [The model](reference-model.md) — architecture, `BotDetector` API, file formats
- [Live API reference](reference-live-api.md) — the check server, the middleware, the dashboard API, Redis keys

## Explanation

Understanding-oriented. Why it works this way, and what it costs.

- [How detection works](explanation-how-detection-works.md) — two scorers, the blend, and the veto
- [How blocking works](explanation-how-blocking-works.md) — the live path's decisions and failure modes
- [Where the labels come from](explanation-training-data.md) — an honest account of the training data
- [Why the dashboard is built this way](explanation-dashboard-design.md) — recording as a tee, not a dependency

## Results

Evidence-oriented. What it actually caught, measured against baselines.

- [The real-world benchmark](results/2026-09-benchmark.md) — microguard vs a UA
  blocklist, a rate limit, a path blocklist, and CrowdSec, on the same bots at
  rising evasion levels and on real public logs. Rules fixed in advance in
  [`benchmarks/PREREGISTRATION.md`](../benchmarks/PREREGISTRATION.md).
- [A realistic model, trained on real human traffic](results/2026-09-realistic-model.md)
  — retraining the micrograd model on real human shopper sessions took it from
  ROC-AUC 0.34 to 0.97 on held-out real traffic, and made the dataset-integrity
  leakage guards pass.

## Reading paths

**"I want to block bots on my site."**
[Block your first bot](tutorial-real-time-blocking.md) →
[deploy behind nginx](howto-deploy-behind-nginx.md) or
[in-process](howto-deploy-in-process.md) →
[tune blocking](howto-tune-blocking.md) →
[run the dashboard](howto-run-the-dashboard.md) →
[operate it](howto-operate-microguard.md)

**"It's live and something looks wrong."**
[Operate it](howto-operate-microguard.md) tells the three failure modes apart →
[tune blocking](howto-tune-blocking.md) for a specific verdict

**"Why was this customer blocked?"**
[Tune blocking](howto-tune-blocking.md) has the diagnostic order →
[the heuristic rules](reference-heuristic-rules.md) names what fired →
[the 19 features](reference-features.md) explains the numbers behind it

**"Can I trust this model?"**
[Where the labels come from](explanation-training-data.md) →
[the model](reference-model.md) →
[retrain it](howto-retrain-the-model.md) on your own traffic

**"I'm contributing."**
[How detection works](explanation-how-detection-works.md) →
[CONTRIBUTING.md](../CONTRIBUTING.md) →
[work on the dashboard UI](howto-work-on-the-gui.md) if you are touching `gui/`

## Honest limits

Read these before relying on any of it for production blocking:

- [What detection cannot do](explanation-how-detection-works.md#what-this-cannot-do)
- [Reading the numbers honestly](explanation-training-data.md#reading-the-numbers-honestly)
- [Known limitations](../README.md#known-limitations-read-before-relying-on-this-for-production-blocking) in the README
