# A realistic model, trained on real human traffic

> ## Correction, 2026-09-20
>
> **The 0.97 below is not a held-out number, and the model it describes was
> never saved.** An engineering review of this work found two things that
> invalidate the headline, both reproducible from this repo:
>
> 1. **The split leaked.** `benchmarks/model/realistic.py:29-30` declares
>    `TEST_DAYS = {"2019-01-25", "2019-01-26"}`, but `microguard/training/train.py`
>    ignores `days` and splits groups at random, so the shipped
>    `microguard/data/model.json` was trained on rows from both of those days
>    (355 from day 25, 539 from day 26). Measured directly, the shipped model
>    scores **AUC 0.9872 on the days it is reported as held out from** — a
>    trained-on-test number. The 0.97 in the table belongs to a *separate*
>    model trained inside `realistic.py` and never written to disk.
> 2. **The class labels are a user-agent predicate.** `benchmarks/public/zanbil.py:75`
>    defines `CRAWLER_TOKEN = bot|crawl|spider|slurp`; a `human_proxy` label
>    requires its absence and `verified_crawler` requires a crawler token. Feature
>    12, `ua_category`, is the same test. So the "zero human false positives"
>    result is definitional, not empirical, and a one-line check is a fair
>    baseline rather than a straw man. Measured on the same rows:
>
>    | detector | ROC-AUC | recall @ 0 human FP |
>    |---|---|---|
>    | `ua_category == 1` — one line | 0.8871 | **78.2%** (255/326), 0.00% FP (0/1139) |
>    | the retrained model, as published below | 0.9724 | 69.9% (228/326) |
>
>    A substring match on the user agent beats the 85-parameter network at the
>    operating point this document calls "a real, shippable operating point".
>
> Everything below is left as it was written, because the claims it makes are
> the finding. A corrected number is pending the day-based holdout the builder's
> own docstring already promises, with a recorded seed — nothing here is
> reproducible today, since neither the weight initialization nor the batch
> shuffle is seeded.

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

> **RETRACTED — do not cite this table.** "The model never saw" is false for the
> shipped artifact: it trained on rows from both of these days and scores 0.9872
> on them. The 0.97 row describes a model that was never saved. And the missing
> row is the one that matters — a one-line `ua_category == 1` check reaches
> **78.2%** (255/326) at 0.00% human FP, beating every micrograd row here. See
> the correction at the top of this document.

1,139 real human sessions, 326 real bot sessions the model never saw:

| model | ROC-AUC | avg precision | recall @ 0 human false positives |
|---|---|---|---|
| ~~**micrograd (retrained on real data)**~~ | ~~**0.97**~~ | ~~0.96~~ | ~~**70%** (228/326)~~ |
| ~~micrograd, UA features dropped~~ | ~~0.94~~ | ~~0.88~~ | ~~43%~~ |
| ~~sklearn logistic regression (reference)~~ | ~~0.95~~ | ~~0.90~~ | ~~5%~~ |
| ~~sklearn random forest (reference)~~ | ~~1.00~~ | ~~0.99~~ | ~~90%~~ |
| ~~**the shipped model (before this)**~~ | ~~**0.34**~~ | ~~0.21~~ | ~~2%~~ |
| `ua_category == 1` — one line, measured 2026-09-20 | 0.8871 | — | **78.2%** (255/326), 0.00% FP |
| the shipped model, on these same days | **0.9872** | — | — (it trained on them) |

Reading it honestly:

> Each of the four bullets below is wrong or unsupported. See the correction at
> the top of this document; they are kept verbatim because what they claim, and
> how confidently, is the finding.

- ~~**The retrained micrograd model went from actively wrong to genuinely good** —
  AUC 0.34 → 0.97, catching **70% of real bots at zero false positives on real
  humans**. That is a real, shippable operating point.~~ The 0.34 and the 0.97
  are not the same model, and the shipped one scores 0.9872 on these same
  "held-out" days because it trained on them.
- ~~**AUC 0.97 is realistic, not the lab's 1.000.** Real crawler-vs-shopper is not
  perfectly separable, and that is the point — this is an honest number on real
  traffic, not a measurement of a leak.~~ It is a measurement of a leak.
- ~~**It is learning behaviour, not the user agent.** Dropping the three UA-derived
  features still gives AUC 0.94.~~ The ablation drops the UA *columns* but not the
  UA-derived *label*, so it cannot support this. `ev.asset` is also a required
  conjunct of the human label (`zanbil.py:191`, `:211`), which forces human rows
  to be asset-burst shaped.
- ~~**A random forest does better (AUC 1.00, 90% recall)** — the 85-parameter
  micrograd net leaves headroom on the table, honestly.~~ The immediate cause is
  more likely preprocessing than capacity: `microguard/data/normalization.json`
  min-maxes against a maximum of 1,224,575 for `time_since_session_start` (a
  14-day session) and has one zero-range column, so most real values reach the
  network near zero. A random forest is scale-invariant and does not care.

## Caveats (real, and stated plainly)

- **The human labels are a behavioural proxy** — a Zanbil actor is "human" if it
  used a browser UA, reached checkout, and loaded assets. Strong, but a careful
  bot could mimic it. This is not verified ground truth. **And the proxy is
  narrow**: Zanbil labels 3,664 of 284,491 actors (1.29%), of which 2,268 (0.80%)
  are `human_proxy`, because the label requires a basket or checkout action. The
  human class is the ~1% who converted. The 280,827 discarded actors are where
  browsers-who-did-not-buy and browser-UA scrapers both live, which is the
  population a deployment actually has to decide about.
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
python -m microguard.training.train                     # -> microguard/data/model.json (realistic)
```
