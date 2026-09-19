# A realistic model, trained on real human traffic

_Companion to [the real-world benchmark](2026-09-benchmark.md). This is the
follow-through on that benchmark's central finding: the "powered by micrograd"
model did nothing at ship thresholds because it had never seen a real human._

## The problem it fixes

The shipped model's human class came from one file (`harvard_training_data.json`),
so ~8 feature columns were constant across it — they identified the *source*, not
the *class*. The model learned to detect that file, which is why
[the benchmark](2026-09-benchmark.md) measured it at ROC-AUC **0.34 on real
traffic**: below 0.5, it ranked real humans *above* real bots. `collect.py` and
`explanation-training-data.md` both named the only fix — "real human sessions
extracted by the same `extract_features` as the bot class."

That data already existed. The **Zanbil** e-commerce log (the benchmark's public
dataset) is real production nginx traffic containing real human shoppers **and**
real bots (crawlers, scanners) **from the same site**, and this repo already held
real forensic attacks (organization-x). Training on same-site humans-and-bots is
what stops the model from learning "which dataset" instead of "human vs bot."

## What was built

`microguard/training/build_realistic_dataset.py` — combines, with per-session
features extracted the same way for every class:

| class | source | sessions |
|---|---|---|
| human | Zanbil `human_proxy` (browser UA + checkout + assets), 5 days | 3,266 |
| bot | Zanbil verified/unverified crawlers + probe bots (same site) | ~1,023 |
| bot | organization-x forensic attacks (ground-truth + heuristic) | ~2,510 |

Held out by **whole day**, not randomly: trained on Zanbil days 22–24 (+ the
org-x attacks), evaluated on days 25–26 — real humans and real bots the model
never saw.

## The leakage guards now pass

`tests/test_dataset_integrity.py` held three `xfail(strict=True)` guards, each
with the leak's numbers in its reason. On the realistic dataset all three now
**pass** (and are converted to normal tests):

- No feature column is constant within a class (was 8, all in the human class).
- No single feature separates the classes without overlap (was
  `header_consistency_score`: 0.7 for every synthetic human, 1.0 for every bot).
- The human class has more than one provenance (was one generated file; now five
  real collection days).

## The result (held-out real humans and bots, days 25–26)

1,139 real human sessions, 326 real bot sessions the model never saw:

| model | ROC-AUC | avg precision | recall @ 0 human false positives |
|---|---|---|---|
| **micrograd (retrained on real data)** | **0.97** | 0.96 | **70%** (228/326) |
| micrograd, UA features dropped | 0.94 | 0.88 | 43% |
| sklearn logistic regression (reference) | 0.95 | 0.90 | 5% |
| sklearn random forest (reference) | 1.00 | 0.99 | 90% |
| **the shipped model (before this)** | **0.34** | 0.21 | 2% |

Reading it honestly:

- **The retrained micrograd model went from actively wrong to genuinely good** —
  AUC 0.34 → 0.97, catching **70% of real bots at zero false positives on real
  humans**. That is a real, shippable operating point.
- **AUC 0.97 is realistic, not the lab's 1.000.** Real crawler-vs-shopper is not
  perfectly separable, and that is the point — this is an honest number on real
  traffic, not a measurement of a leak.
- **It is learning behaviour, not the user agent.** Dropping the three UA-derived
  features still gives AUC 0.94.
- **A random forest does better (AUC 1.00, 90% recall)** — the 85-parameter
  micrograd net leaves headroom on the table, honestly. It is small on purpose;
  the point of this project is that a 2 KB model can be genuinely useful, and now
  it is.

## Caveats (real, and stated plainly)

- **The human labels are a behavioural proxy** — a Zanbil actor is "human" if it
  used a browser UA, reached checkout, and loaded assets. Strong, but a careful
  bot could mimic it. This is not verified ground truth.
- **One site, one period.** Zanbil is a single Iranian e-commerce store in 2019.
  "Realistic" here means realistic for e-commerce-style human browsing, not
  internet-universal; a model trained here may not transfer to, say, an API
  backend.
- **The bots are crawlers, scanners, and forensic attacks** — real automated
  traffic, but not sophisticated evasive browser bots (those cannot be labelled
  from a log). The model learns real-human-vs-real-crawler/attacker, which is a
  real and useful distinction, not the full adversarial picture. The
  [evasion ladder](2026-09-benchmark.md) and the fingerprint signal remain how
  the hard cases are handled.
- **Complete-session training, live per-request serving.** The features are
  extracted from complete sessions, like `microguard scan`. The live check
  server scores each request as a session builds, a different distribution
  (issue #19), so this model most improves the **offline audit**. A live-calibrated
  model needs real *live* per-request data — which is exactly what the
  [tunnel collection](../howto-collect-real-sessions.md#the-fast-free-path-a-tunnel-session)
  (`scripts/collect-session.sh`) gathers. This pipeline is built so a live
  archive drops straight into the same builder.

## Reproduce

```bash
python -m benchmarks.public.zanbil split && python -m benchmarks.public.zanbil label
python -m microguard.training.build_realistic_dataset   # -> data/realistic_training_data.json
python -m benchmarks.model.realistic                    # the held-out table above
python -m microguard.training.train                     # -> data/model.json (realistic)
```
