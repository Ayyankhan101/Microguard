# Where the labels come from

The model is only as good as what it was trained on. This is an honest account
of that data: where each class came from, which parts are real, which are
synthetic, and which conclusions the numbers do not support.

> **Update — the shipped model now trains on real human traffic.** Most of this
> page describes the problem that motivated a fix, which has since landed: the
> human class is now real Zanbil shopper sessions extracted the same way as the
> bots, not a synthetic single-source file. On held-out real traffic the model
> went from ROC-AUC 0.34 to 0.97, and the three dataset-integrity guards that
> were `xfail(strict)` now pass. The full account, with caveats, is in
> [A realistic model, trained on real human traffic](results/2026-09-realistic-model.md).
> Read the rest of this page as the history that made that fix necessary.

## The problem

Supervised bot detection needs labeled sessions, and nobody has them. Real
access logs do not come with a column saying which visitor was a scraper. The
usual workarounds all have a catch:

- **Label by hand.** Accurate, and you get a few hundred sessions.
- **Label with heuristics.** Cheap and unlimited, but then the model can only
  learn to imitate the heuristics. It will never catch anything they miss, which
  is the entire reason you wanted a model.
- **Generate synthetic bots.** Unlimited and perfectly labeled, but you are
  training a classifier to separate two distributions you invented. It learns
  your `random.uniform()` calls, not bot behavior.

Microguard uses all three, weighted so the failure modes do not stack, and keeps
a record of which row came from where.

## The composition

`data/real_bot_training_data.json`, 3,580 sessions:

| Provenance | Rows | Class | What it is |
|---|---|---|---|
| `heuristic_real` | 2,098 | bot | Real Apache traffic, labeled by the heuristic rules |
| `harvard_human` | 1,000 | human | Real human sessions from the Harvard Dataverse shopping logs |
| `ground_truth` | 482 | bot | Real attack traffic with real forensic labels |
| `synthetic_augmentation` | 0 in the current build | bot | Generated, capped at 30% of the bot class |

Every row carries its provenance and a group id, so any split can be audited by
source afterwards.

## The ground truth is genuinely ground truth

The 482 `ground_truth` rows are the strongest data in the set. They come from
`data/zenodo_data/organization-x/` — real Apache logs from a production server —
with `organization-x.yaml` supplying forensic labeling rules written by the
people who investigated the incident. Each rule is a set of substrings that must
all appear in a line for it to count as an instance of a named attack:

| Category | Sessions |
|---|---|
| `dir_scan` | 467 |
| `remote_code` | 5 |
| `path_traversal` | 4 |
| `rce_shell` | 2 |
| `sql_injection_attempt` | 2 |
| `dir_scan_go`, `dir_scan_python` | 1 each |

That distribution is itself informative, and not in a flattering way: directory
scanning is 97% of the labeled attacks. The model has seen a great deal of one
attack shape and almost nothing of the others. Five RCE sessions do not teach a
network what RCE looks like.

The YAML is hand-parsed rather than read with a YAML library
(`training/groundtruth.py`), because the structure is a flat fixed shape and the
project keeps its "no dependencies beyond micrograd" property.

## The dataset quirk that shaped everything

The organization-x logs anonymize the client IP to roughly two placeholder values
across all 213,000+ lines. The normal IP-based sessionizer collapses the entire
dataset into a handful of enormous sessions.

Two consequences, both deliberate:

**Sessions are grouped by `(ip, user_agent)`** for this dataset, using
`group_into_sessions`'s `session_key` parameter. It is a best-effort proxy for
"one actor", not a correct one.

**This dataset is used for the bot class only.** A common desktop-browser UA
plausibly represents many distinct real people merged into a single training
"session". Trusting that as a human example would teach the model that humans
make thousands of requests from one IP. The human class comes entirely from the
Harvard sessions, which are genuinely distinct.

That asymmetry is why the mix is 2,580 bot to 1,000 human rather than balanced.

## The heuristic-labeled majority

The 2,098 `heuristic_real` rows are real traffic, labeled by
[the rules](reference-heuristic-rules.md). This is the circular part, and it
should be read as such: for anything the rules already catch, the model is
learning to reproduce a decision it could have looked up.

What it buys is generalization at the margins — sessions that resemble labeled
bots in feature space without matching any rule literally. What it cannot buy is
a category of bot the rules have never seen. A model trained this way has no
independent evidence.

The blend is designed around this. The rules keep a veto in both directions
precisely because the model is not an independent second opinion in the way the
60/40 weighting might suggest. See
[how detection works](explanation-how-detection-works.md).

## Synthetic data, and where it is not allowed

`training/generate.py` can synthesize sessions. Two rules govern its use:

**In training, capped at 30%** of the bot class (`MAX_SYNTHETIC_FRACTION`), and
only to top up attack categories the real data barely covers. The current build
needed none.

**The stealthy-bot generator is never trained on at all.**
`generate_stealthy_bot_session()` models a headless browser or
residential-proxy bot that spoofs a browser UA, jitters its own timing, and
browses several pages specifically to evade the timing, UA and endpoint-diversity
heuristics. It exists to measure a known blind spot, not to patch it.

Training on it would be worse than useless: a bot generator that close to the
human distribution would teach the model to draw an arbitrary line between two
synthetic distributions, which looks like progress in every metric and means
nothing. It lives in `data/adversarial_eval.json` instead — 200 synthetic
stealthy bots against 200 real held-out humans — and its own `note` field says
so:

> Bot rows are synthetic stealthy-bot vectors, never trained on. Human rows are
> real, from the held-out eval set. Measures a known blind spot, not a pass/fail
> bar.

## The holdout split

`data/eval_holdout.json`: 623 sessions, 423 bot and 200 human, carved out
**before** normalization or training.

The split is by group, not by row, and stratified by class
(`training/train.py:100`). Grouping matters: one actor's sessions produce highly
correlated feature vectors, so a row-level split would put near-duplicates on
both sides and report memorization as generalization. Stratifying matters
because the classes are imbalanced and a random split can produce a test set
with almost none of one.

Normalization is computed from the training side only. Computing it over
everything would leak the test distribution into the scaling.

## Reading the numbers honestly

The model scores near-perfectly on the holdout. That is a caution, not a result.

Three reasons to distrust it:

1. **Only 9 of the 19 features vary meaningfully** in the human baseline. The
   classes are separable on this data partly because the data is not very
   varied.
2. **97% of the labeled attacks are directory scanning**, which is the loudest,
   most obvious bot behavior there is. Separating a directory scanner from a
   shopper is not a hard problem.
3. **Most bot labels came from the rules**, so a perfect score partly measures
   agreement with the thing that generated the labels.

The adversarial set was built to be the harder test, and the current model scores
**200/200 on it as well**, with zero humans blocked.

Do not read that as evidence the model beats stealthy bots. The project's own
test suite says the number "should be read with real skepticism either way", and
the reason is in the data: the human baseline's non-timing dimensions are largely
constant placeholders rather than real per-session variation. A synthetic bot
vector and a real human vector therefore differ in dimensions that have nothing
to do with stealth, and the model may be separating *synthetic from real* rather
than *bot from human*. `tests/test_training_quality.py::TestAdversarialRobustness`
reports the number and deliberately does not gate on it.

So neither evaluation set is strong evidence. The holdout is easy for the reasons
above; the adversarial set is separable for reasons that are probably an artifact.
The dashboard's Model tab flags a perfect confusion matrix as a caution rather
than a win, which applies to both datasets.

The number that would mean something does not exist yet: labeled sessions from
real traffic that was actually trying to evade this detector. Until then, treat
every metric here as a smoke test.

## The suspicion above, measured

Everything in the previous section was a caution. It has since been measured,
and it was right. What follows is what the model actually learned.

### It reads one column, and that column is the label

`header_consistency_score` is **0.7 for all 1000 human rows and 1.0 for all
2580 bot rows**. Zero overlap.

`features.py` computes it as `1.0 / len(ua_variants)`, whose range is 1.0, 0.5,
0.333, 0.25... **0.7 is not reachable.** No session extracted by this codebase
can produce it. The value came from a data generator, not from the extractor,
and the model found it.

### The network is one live unit out of four

The output layer's weights are `[-1.3443, 0.0004, 0.0010, -0.1869]`. Two hidden
units are wired to the output at four ten-thousandths and are not participating.
Contribution to the logit, as `|w| x activation stdev` over the holdout:

```
h0: 0.732435
h1: 0.000259
h2: 0.000295
h3: 0.019288
```

h0 is 97% of the signal, and it fires on **200 of 200 humans and 0 of 423
bots**. When it is off, the logit is the output bias alone: `sigmoid(0.9981) =
0.7307`. That is why **413 of 623 held-out sessions score exactly 0.731** — not
a prediction, a bias term.

The 100% holdout accuracy is measuring the leak.

### The cause is structural, not one bad column

The human class comes from exactly one file, so *any* column constant within
that file identifies the file, and the file identifies the label. Eight columns
qualify: `endpoint_sequence_entropy`, `has_accept_language`, `ua_category`,
`payload_entropy`, `status_code_entropy`, `error_rate`, `image_ratio`,
`night_ratio`.

Patching columns does not fix it. Neutralizing all of them and retraining leaves
`max_sustained_click_rate`, which separates the classes at **99.75% with a
single threshold** — and the rule it learns is **"bot if clicking slowly"**,
backwards from every real bot. It is detecting which file the row came from.

### Why there is no fix inside this repo

Three routes to a real human class were checked:

| Route | Why it fails |
|---|---|
| Harvard Dataverse raw files | `data/dataverse/{basket,browse,product,static}` are **timestamp-only** — no IP, UA, URL, or status. Only the timing columns were ever real, which is why the generator filled the rest with class constants. |
| organization-x benign traffic | 21,617 of 21,629 lines share one IP. Per-actor sessionization is impossible; `(ip, user_agent)` merges many humans into one session. |
| Sessions the builder discards | `build_real_dataset.py` drops heuristic-human sessions: 363 of them, median 3 requests. But **344 are labeled "no strong signals either way"** — the fallback branch. Training on those teaches the model to reproduce `labeler.py`, and `compute_combined_score` blends the two, so one signal would be counted twice while reading as corroboration. A different bug, not a fix. |

**There is no human ground truth in this repo by any route.** The only source of
real human sessions extracted by the same `extract_features` as the bot class is
live traffic.

### What is guarded now

`tests/test_dataset_integrity.py` asserts that no column is constant within a
class, that no column separates the classes without overlap, and that the human
class has more than one provenance. All three are `xfail(strict=True)` today,
with the measured numbers in the reason — so the day real data makes them pass,
CI says so rather than staying quiet.

`microguard serve --collect-to <path>` archives every scored decision with its
19 features to durable JSONL. The Redis event list cannot serve this purpose: it
is capped at 1000 and LTRIMmed. Collected rows are **unlabeled** — they record
what the tool guessed, and a label only exists after a human confirms one
through the dashboard, for the reason in the third row of the table above.

### What the model is worth today

Nothing independent of the heuristic, at the thresholds the tool uses.
`compute_combined_score` weights it at 0.6, and in a batch `scan` that 0.6 is
reading a column that cannot occur in production traffic — in
`data/sample_access.log` both a Chrome session and a `python-requests` scraper
score 0.731, and only the heuristic chain separates them.

The [real-world benchmark](results/2026-09-benchmark.md) sharpened this, and
not entirely in the direction the "constant 0.731" story implies. On the **live
per-request path** the shipped model is *not* a flat constant: its score varies
(median ≈ 0.64) and it actually ranks bots above humans on the lab traffic
(actor-level ROC-AUC ≈ 0.77). The problem is calibration, not a dead network —
the scores all sit high, so at the `model_score > 0.5` cut it flags every bot
**and** every human, and inside the blend the heuristic floor/cap still drives
the verdict. So the practical conclusion holds: at the thresholds microguard
ships with, the model adds no usable independent verdict, and the rule chain in
`labeler.py` is the product.

The benchmark also measured the flip side. A model **retrained on the live
per-request distribution** recovers the one case the rules are blind to — the
distributed browser farm (one profile across many IPs) — with zero added human
false positives *on the lab's simulated humans*. Read that as an upper bound,
not a shipping result: those humans are cleanly separable from bots in feature
space (sklearn logistic regression and random forest hit the same perfect
score), and on real human traffic that separation does not hold — `microguard
scan` flagged 57% of real Zanbil shoppers as bots at the time of the benchmark
(since cut to 15% by counting page-like requests, but not to zero). Retraining
is a real lead; it is not yet a model that is safe to block with. Until
observe-only collection produces labeled *real* human sessions, that stays true.

## Rebuilding it

```bash
python -m microguard.training.build_real_dataset   # rebuild the dataset
python -m microguard.training.train                # train, eval, write model.json
```

The trainer picks the best dataset available, in priority order:
`real_bot_training_data.json`, then `harvard_training_data.json`, then
`real_training_data.json`, then a raw `data/access.log`, then fully synthetic
data as a last resort. It prints which one it chose. If you see "Generating
synthetic training data", the resulting model is a demo, not a detector.

See [how to retrain](howto-retrain-the-model.md).

## Related

- [The model](reference-model.md) — what gets trained
- [The 19 features](reference-features.md) — including which ones barely vary
- [The heuristic rules](reference-heuristic-rules.md) — which also generate most labels
- [How detection works](explanation-how-detection-works.md) — why the rules keep a veto
