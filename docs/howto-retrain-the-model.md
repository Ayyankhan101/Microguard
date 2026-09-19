# How to retrain the model

Rebuild `microguard/data/model.json` from the training data, with a held-out evaluation set
so the accuracy number means something. By the end you will have a retrained
model, its normalization file, a fresh holdout split, and a generalization
number you can trust more than the training accuracy.

## Prerequisites

- A source checkout (the training pipeline is not part of the wheel's CLI)
- `pip install -e ".[live,fastapi,flask,dashboard]"` — or just `pip install -e .`
  if you only want to train
- Training data in `data/`. `data/real_bot_training_data.json` ships with the
  repo; see [where the labels come from](explanation-training-data.md).

Training is pure Python on 85 parameters and needs no GPU. A full run over the
shipped dataset is roughly **2 to 3 minutes**: 100 epochs across ~2,400 training
rows at about 0.6ms per sample-epoch, plus a final scoring pass over the training,
holdout and adversarial sets.

## Train

```bash
python -m microguard.training.train
```

```
📂 Loading real bot-training data from: data/real_bot_training_data.json
   Samples: 3580 (Human: 1000, Bot: 2580)
   Source breakdown: {'heuristic_real': 2098, 'harvard_human': 1000, 'ground_truth': 482}

🔒 Held-out split: 623 test / 2957 train sessions (group-level, stratified — no actor appears in both)

🧠 Training model...
   Samples: 2957
   Bot: 2157 | Human: 800
   Epochs: 100 | LR: 0.05
   Normalization saved to: microguard/data/normalization.json

💾 Model saved to: microguard/data/model.json

📊 Final Evaluation:
   Accuracy: ...
   True Positives / True Negatives / False Positives / False Negatives

💾 Held-out eval set saved to: data/eval_holdout.json

📊 Held-Out Evaluation (never seen during training):
   ...
```

Three files are written: `microguard/data/model.json`, `microguard/data/normalization.json`, and
`data/eval_holdout.json`.

## Check which dataset it used

The first line of output is the one that matters. The trainer takes the best
available source, in priority order:

| Priority | File | What it is |
|---|---|---|
| 0 | `real_bot_training_data.json` | Real attack traffic + real human sessions. The intended input |
| 1 | `harvard_training_data.json` | Real human sessions, heuristic-labeled bots |
| 2 | `real_training_data.json` | Older combined set |
| 3 | `data/access.log` | Raw log, sessionized and heuristic-labeled on the fly |
| 4 | — | Fully synthetic fallback |

**If you see `📥 No dataset found. Generating synthetic training data`, stop.**
The resulting model is a demo: it learned to separate two distributions that
`random.uniform()` produced, and it will not generalize to your traffic. Restore
the data files before training.

## Read the two accuracy numbers differently

The run prints **Final Evaluation** and **Held-Out Evaluation**. They are not the
same claim.

Final Evaluation scores the training data. It measures fit, and a high number
there only says the model memorized what it saw.

Held-Out Evaluation scores 623 sessions carved out before normalization and
training, split by actor group and stratified by class, so no actor appears on
both sides. That is the number to quote.

Even then, read it sceptically. A near-perfect holdout score on this data is a
caution — 97% of the labeled attacks are directory scanning, and most bot labels
came from the heuristic rules the model is partly learning to imitate. The
[training data explanation](explanation-training-data.md) lays out why.

## Evaluate against the adversarial set

200 synthetic bots built specifically to evade the timing, UA and
endpoint-diversity heuristics, against 200 real humans. Those bots were **never
trained on**.

It was meant to be the harder test. The current model scores 200/200 on it, and
that result should be read with skepticism rather than satisfaction — see
[reading the numbers honestly](explanation-training-data.md#reading-the-numbers-honestly).
`tests/test_training_quality.py::TestAdversarialRobustness` reports this number
without gating on it, for the same reason.

```bash
python -c "
import json
from microguard.model import BotDetector

d = BotDetector('microguard/data/model.json')
data = json.load(open('data/adversarial_eval.json'))
scores = d.predict_batch(data['features'])
tp = sum(1 for s, y in zip(scores, data['labels']) if s > 0.5 and y > 0.5)
fn = sum(1 for s, y in zip(scores, data['labels']) if s <= 0.5 and y > 0.5)
fp = sum(1 for s, y in zip(scores, data['labels']) if s > 0.5 and y <= 0.5)
print(f'caught {tp}/{tp+fn} stealthy bots, blocked {fp} humans')
"
# caught 200/200 stealthy bots, blocked 0 humans
```

Or drag the threshold in the dashboard's Model tab and watch the confusion matrix
move: `microguard dashboard`, then the Model tab, then pick `adversarial`.

## Rebuild the dataset from raw logs

Only needed if you are changing how the dataset is assembled:

```bash
python -m microguard.training.build_real_dataset
```

This reads `data/zenodo_data/organization-x/`, applies the forensic ground-truth
rules from `organization-x.yaml`, sessionizes by `(ip, user_agent)` rather than
IP alone (that dataset anonymizes the IP field to about two values), takes the
human class from the Harvard sessions, and tops up thin attack categories with
synthetic sessions capped at 30% of the bot class.

It writes `data/real_bot_training_data.json` with per-row `provenance` and
`group_ids`, which is what makes the group-level holdout split possible.

## Train on your own traffic

```bash
cp /var/log/nginx/access.log data/access.log
python -m microguard.training.train
```

Priority 3 kicks in: your log is parsed, sessionized with a 30-minute timeout,
labeled by the heuristic rules, and sessions with fewer than 3 requests are
dropped.

Two things to understand before trusting the result:

**The labels are the heuristic rules.** The model can only learn to reproduce and
slightly generalize decisions the rules already make. It cannot discover a bot
category the rules have never seen.

**No holdout split is produced.** The split needs `group_ids`, which only the
dataset builder emits. Priority 3 trains on everything and reports training
accuracy only — a number that tells you nothing about generalization.

For a real deployment, label a sample of your own traffic by hand and evaluate
against that. The next section is how to gather it.

## Collect real sessions, then label them

This is the loop that produces a training set the model can honestly learn
from. It exists because there is no human ground truth in the repo by any
route — see
[explanation-training-data.md](explanation-training-data.md#the-suspicion-above-measured)
for the measurements.

**1. Run observe-only and archive every decision.**

```bash
microguard serve --block-threshold 1.0 --collect-to ~/mg-collected.jsonl
```

`--block-threshold 1.0` with a strict `>` comparison means no score can ever
exceed it: every request is scored and recorded, nothing is denied.

`--collect-to` is required for this and off by default. The Redis event list
cannot serve the purpose — `events.py` caps it at 1000 and `redis_events.py`
LTRIMs to it, so it holds the most recent 1000 decisions and drops the rest
without saying so. The archive is append-only JSONL, fsynced per row, and each
row carries the 19 features, the score, the deciding heuristic rule, and the
client IP. That last one is why collection is opt-in.

Let it run for **at least 48 hours**. Bot traffic is diurnal and a six-hour
sample will mislead you.

**2. Review a sample by hand.**

```bash
microguard explain <ip>
```

prints the session, the resolved signals with their promotion state, the
fingerprint state, and the rule that decided. Work through the sessions the
shadow counter says a candidate threshold *would* have blocked, until the
answers stop surprising you.

**3. Confirm labels through the dashboard.**

The feedback control writes confirmed labels via `record_correction`. This step
is not optional and cannot be automated away: **a collected row is what the
tool guessed, not a label.** Treating guesses as ground truth would train the
model to reproduce `labeler.py`, and `compute_combined_score` blends model and
heuristic — so one signal would be counted twice while reading as two
independent ones. That is the mistake the current dataset already makes in a
different form.

**4. Retrain on the confirmed corrections.**

```bash
microguard retrain --deployment-id prod-1 --min-examples 50
```

It refuses below 50 corrections and refuses on class imbalance. Both refusals
are correct: fifty hand-checked sessions cannot move an 85-parameter model
without overfitting to them, and a one-sided set teaches a constant.

**5. Check whether it actually moved.**

Re-run your hand-labeled sample against the retrained model. If precision on
your own traffic did not change, the corrections were not informative enough —
collect more, and prefer sessions you disagreed with over ones you did not.

## Verification

Check the model loads and both files are consistent:

```bash
python -c "
from microguard.model import BotDetector
d = BotDetector('microguard/data/model.json')
print('normalization loaded:', d.norm_mins is not None)
print('score on a zero vector:', d.predict([0.0] * 19))
"
```

If `normalization loaded` is `False`, `microguard/data/normalization.json` is missing and
every score from this model is meaningless — see below.

Then confirm end to end:

```bash
microguard scan data/sample_access.log
```

You should see `🧠 Loaded pre-trained model` and two sessions, one bot and one
human.

## Troubleshooting

**`no normalization.json beside microguard/data/model.json`** — the warning means
`predict()` is receiving raw features that the network was trained to see scaled
to 0–1. Nothing raises and scores stay in range; they just stop meaning anything.
This exact condition once dropped held-out bot recall from 100% to 2.4% silently.
Retrain, or restore the file from git.

**`ValueError: Model file has N weight tensors, but model expects M`** — the
model file was trained with a different architecture. Retrain; do not hand-edit
the file.

**Accuracy near 100% on the first try** — expected on this dataset, and not a
success signal. See "Read the two accuracy numbers differently" above.

**Training loss does not move** — with a symmetric batch and an unlucky random
init, every hidden ReLU can sit at zero and the only live gradient cancels.
Rerun; the init is random. On real training data this resolves itself, because
real data is not symmetric.

## Related

- [The model](reference-model.md) — architecture, file formats, the API
- [Where the labels come from](explanation-training-data.md) — what the data is worth
- [The 19 features](reference-features.md) — what gets normalized, and how
- [How detection works](explanation-how-detection-works.md) — how this score is used
