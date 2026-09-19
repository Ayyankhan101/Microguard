# The model

An 85-parameter multilayer perceptron built on
[micrograd](https://github.com/karpathy/micrograd). It takes the
[19 features](reference-features.md) of one session and returns a probability
that the session is a bot. It contributes 60% of every blended score; the
[heuristic rules](reference-heuristic-rules.md) contribute the rest.

```python
from microguard.model import BotDetector

detector = BotDetector("microguard/data/model.json")   # loads weights AND normalization
score = detector.predict(features)          # 0.0 .. 1.0
```

## Architecture

```
19 inputs  ──►  4 hidden (ReLU)  ──►  1 output (linear)  ──►  sigmoid  ──►  0..1
```

| Layer | Parameters | Count |
|---|---|---|
| Hidden | 4 neurons × (19 weights + 1 bias) | 80 |
| Output | 1 neuron × (4 weights + 1 bias) | 5 |
| **Total** | | **85** |

Roughly 1.8 KB on disk. It is small enough to read, which is the point: every
weight is inspectable, and the whole forward pass is pure Python.

The output neuron is linear, so the network emits a raw logit. `predict()`
clamps it to ±500 and applies a sigmoid, so a saturated logit returns 0.0 or 1.0
rather than raising an overflow.

## `BotDetector`

```python
class BotDetector:
    NUM_FEATURES = 19

    def __init__(self, model_path: str | None = None)
```

With a path that exists, the constructor loads it. With `None` or a missing path,
you get random weights — useful for training, useless for scoring.

| Method | Signature | Notes |
|---|---|---|
| `predict` | `(features: list[float]) -> float` | Raises `ValueError` unless `len(features) == 19` |
| `predict_batch` | `(batch: list[list[float]]) -> list[float]` | Loops `predict`; no vectorization |
| `train_step` | `(features_batch, labels, learning_rate=0.01) -> float` | One SGD step, returns mean loss |
| `train` | `(features, labels, epochs=100, batch_size=32, learning_rate=0.01, val_split=0.2, verbose=True) -> list[float]` | Returns the per-epoch loss history |
| `save` | `(filepath: str)` | Writes weights only |
| `load` | `(filepath: str)` | Loads weights **and** `normalization.json` beside them |
| `sigmoid` | `(x: float) -> float` static | Clamped to ±500 |

`DEFAULT_MODEL_PATH` resolves to `model.json` inside the installed package, via
`importlib.resources`, so it is present in a wheel and not only in a source
checkout. It previously pointed one directory *above* the package, which no
packaging metadata carried, so every `pip install` silently ran heuristics
only.

**`predict()` is read-only and thread-safe.** It only reads parameters — verified
with 40 concurrent predictions returning identical results with parameters and
gradients untouched — which is what lets the threaded check server
(`live/server.py`) share one detector across request threads.

**Labels in training are ±1, not 0/1.** `train_step` maps a `1.0` label to target
`+1.0` and a `0.0` label to target `-1.0`, then minimizes squared error against
the raw logit. The 0/1 convention only appears at the API boundary.

## `load()` loads normalization too, always

This is the one behavior worth knowing before you touch this class.

`predict()` applies min-max scaling only when `norm_mins` and `norm_maxs` are
populated, and silently skips it when they are not. The two were once loaded on
different paths: the constructor read `normalization.json`, a bare `load()` did
not. The live scorer used `load()`, so it fed raw features into a network trained
on `[0, 1]` inputs. Held-out bot recall was **2.4% instead of 100%**, and nothing
failed — no exception, no warning, scores still in range, just meaningless.

`load()` now reads both, and logs a warning when `normalization.json` is absent.
A half-loaded model is not a reachable state through the public API.

If you see that warning, the scores coming out are not trustworthy. Retrain, or
restore the file.

## File formats

### `model.json`

```json
{
  "num_features": 19,
  "architecture": [4, 1],
  "weights": [0.123, -0.456, "… 85 floats total …"]
}
```

`architecture` is the layer sizes **after** the input: `[4, 1]` means one hidden
layer of 4 and an output layer of 1. `weights` is a flat list in
`MLP.parameters()` order, which for micrograd is, per layer, per neuron: that
neuron's input weights followed by its bias.

So the first layer occupies `hidden × (inputs + 1) = 4 × 20 = 80` entries, and
the weight connecting input `i` to hidden neuron `n` is at index
`n * (inputs + 1) + i`. That layout is what the dashboard's feature-influence
chart sums over (`gui/src/tabs/logic.ts`).

`load()` raises `ValueError` if the weight count does not match the architecture,
so a model file from a different shape fails loudly instead of scoring nonsense.

### `normalization.json`

```json
{ "mins": ["… 19 floats …"], "maxs": ["… 19 floats …"] }
```

Per-feature min and max computed from the training split only, written next to
`model.json` at training time. See [the features](reference-features.md) for the
scaling formula and [retraining](howto-retrain-the-model.md) for how they are
produced.

### Evaluation sets

Both live in `data/` and are read by the dashboard's `/api/model/evaluate`.

| File | Samples | Contents |
|---|---|---|
| `eval_holdout.json` | 623 | `features`, `labels`, `provenance`, counts. A group-level stratified split carved out **before** normalization or training, so no actor appears on both sides |
| `adversarial_eval.json` | 400 | `features`, `labels`, counts, `note`. Bot sessions built to look human |

The holdout is the honest generalization number. It is easy to score well on —
see [training data](explanation-training-data.md) for why a perfect result there
is a caution rather than a win.

For a measurement that does *not* come from this project's own data, the
[real-world benchmark](results/2026-09-benchmark.md) scores the shipped model
against exact ground truth on the live per-request path (actor-level ROC-AUC
≈ 0.77 — it ranks bots above humans but is miscalibrated, so no fixed threshold
the tool uses exploits it) and tests a model retrained on the live distribution.
That benchmark supersedes the synthetic `adversarial_eval.json` number; treat it
as the reference for "does the model catch evasive bots".

## Evaluating

```bash
python -c "
import json
from microguard.model import BotDetector

d = BotDetector('microguard/data/model.json')
data = json.load(open('data/eval_holdout.json'))
scores = d.predict_batch(data['features'])
tp = sum(1 for s, y in zip(scores, data['labels']) if s > 0.5 and y > 0.5)
fn = sum(1 for s, y in zip(scores, data['labels']) if s <= 0.5 and y > 0.5)
print(f'recall {tp / (tp + fn):.3f}')
"
```

The dashboard's Model tab does the same thing with a threshold slider, a
confusion matrix and an ROC curve. See
[running the dashboard](howto-run-the-dashboard.md).

## Performance

Scoring is pure Python and GIL-bound. One `predict()` on a 200-request session
costs roughly 2ms, most of it in `extract_features` rather than the forward pass.
The check server is threaded for overlapping Redis I/O, not for CPU: measured on
a local Redis, threads took throughput from 728 to 894 req/s while median latency
rose. With a 15ms Redis round trip, 24 concurrent checks took 0.61s serialized
versus 0.11s threaded.

## Related

- [The 19 features](reference-features.md) — the input vector and its normalization
- [How to retrain](howto-retrain-the-model.md) — running the pipeline
- [Training data](explanation-training-data.md) — where the labels come from, and what they are worth
- [How detection works](explanation-how-detection-works.md) — how this score is blended with the rules
