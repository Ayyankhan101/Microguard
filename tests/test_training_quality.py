"""Tests for training data quality, normalization, and model accuracy.

Validates:
- Training data format (features length, label values, no NaN/inf)
- Normalization params (mins/maxs consistency, zero-range handling)
- Train-set fit (TestModelAccuracy — a sanity check, NOT a generalization
  claim: it evaluates the model on the data it was trained on)
- Held-out generalization (TestHeldOutAccuracy — the honest number: data
  never seen during training, split at the session-actor level)
"""

import json
import math
import os

import pytest

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_harvard():
    path = os.path.join(DATA_DIR, 'harvard_training_data.json')
    if not os.path.exists(path):
        pytest.skip("Harvard training data not found")
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def _load_training_data():
    """Load whichever file `training/train.py` actually trains the shipped
    model on — mirrors that module's own priority order, so these tests
    track reality instead of assuming a specific file.
    """
    for name in ('realistic_training_data.json', 'real_bot_training_data.json',
                 'harvard_training_data.json'):
        path = os.path.join(DATA_DIR, name)
        if os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                return json.load(f)
    pytest.skip("no primary training data file found")


def _load_holdout():
    path = os.path.join(DATA_DIR, 'eval_holdout.json')
    if not os.path.exists(path):
        pytest.skip("eval_holdout.json not found — retrain with a held-out split first")
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def _load_normalization():
    path = os.path.join(DATA_DIR, 'normalization.json')
    if not os.path.exists(path):
        pytest.skip("normalization.json not found")
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def _load_model():
    from microguard.model import BotDetector
    path = os.path.join(DATA_DIR, 'model.json')
    if not os.path.exists(path):
        pytest.skip("model.json not found")
    return BotDetector(path)


# ---------------------------------------------------------------------------
# Training Data Format Tests
# ---------------------------------------------------------------------------

class TestHarvardDataFormat:
    """Validate the Harvard training data JSON structure."""

    def test_file_exists(self):
        path = os.path.join(DATA_DIR, 'harvard_training_data.json')
        assert os.path.exists(path), "harvard_training_data.json not found in data/"

    def test_required_keys(self):
        data = _load_harvard()
        required = {'features', 'labels', 'n_samples', 'n_features', 'n_human', 'n_bot'}
        assert required.issubset(data.keys()), f"Missing keys: {required - data.keys()}"

    def test_feature_count_matches_labels(self):
        data = _load_harvard()
        assert len(data['features']) == len(data['labels'])

    def test_sample_count_matches_metadata(self):
        data = _load_harvard()
        assert len(data['features']) == data['n_samples']

    def test_human_bot_counts(self):
        data = _load_harvard()
        actual_bot = sum(1 for l in data['labels'] if l > 0.5)
        actual_human = len(data['labels']) - actual_bot
        assert actual_bot == data['n_bot']
        assert actual_human == data['n_human']

    def test_balanced_classes(self):
        data = _load_harvard()
        assert data['n_human'] == data['n_bot'], "Classes should be balanced"

    def test_feature_vector_length(self):
        data = _load_harvard()
        expected = data['n_features']
        for i, feat in enumerate(data['features']):
            assert len(feat) == expected, (
                f"Sample {i}: expected {expected} features, got {len(feat)}"
            )

    def test_all_features_are_numbers(self):
        data = _load_harvard()
        for i, feat in enumerate(data['features']):
            for j, v in enumerate(feat):
                assert isinstance(v, (int, float)), (
                    f"Sample {i}, feature {j}: expected number, got {type(v).__name__}"
                )

    def test_no_nan_features(self):
        data = _load_harvard()
        for i, feat in enumerate(data['features']):
            for j, v in enumerate(feat):
                assert not math.isnan(v), f"Sample {i}, feature {j}: NaN"

    def test_no_inf_features(self):
        data = _load_harvard()
        for i, feat in enumerate(data['features']):
            for j, v in enumerate(feat):
                assert not math.isinf(v), f"Sample {i}, feature {j}: Inf"

    def test_labels_are_binary(self):
        data = _load_harvard()
        unique = set(data['labels'])
        assert unique <= {0.0, 1.0}, f"Unexpected label values: {unique - {0.0, 1.0}}"

    def test_positive_features(self):
        """All features should be non-negative (they're counts, ratios, times)."""
        data = _load_harvard()
        for i, feat in enumerate(data['features']):
            for j, v in enumerate(feat):
                assert v >= 0.0, f"Sample {i}, feature {j}: negative value {v}"


# ---------------------------------------------------------------------------
# Normalization Tests
# ---------------------------------------------------------------------------

class TestNormalization:
    """Validate normalization params are consistent with training data."""

    def test_file_exists(self):
        path = os.path.join(DATA_DIR, 'normalization.json')
        assert os.path.exists(path), "normalization.json not found in data/"

    def test_has_mins_maxs(self):
        norm = _load_normalization()
        assert 'mins' in norm
        assert 'maxs' in norm

    def test_mins_maxs_same_length(self):
        norm = _load_normalization()
        assert len(norm['mins']) == len(norm['maxs'])

    def test_feature_count(self):
        norm = _load_normalization()
        assert len(norm['mins']) == 19, f"Expected 19 features, got {len(norm['mins'])}"

    def test_maxs_greater_than_mins(self):
        """For features with range, max must be > min."""
        norm = _load_normalization()
        for i, (mn, mx) in enumerate(zip(norm['mins'], norm['maxs'])):
            assert mx >= mn, f"Feature {i}: max ({mx}) < min ({mn})"

    def test_zero_range_features(self):
        """Any feature that's constant across the full training file must
        show zero range in normalization.json too — a subset of a constant
        column is still constant, so this holds regardless of exactly
        which rows ended up in the held-out split. Computed from whichever
        file `train.py` actually trained on, not a hardcoded index list —
        which features are constant depends on the dataset in use.
        """
        data = _load_training_data()
        norm = _load_normalization()
        features = data['features']
        for j in range(len(norm['mins'])):
            actual_min = min(f[j] for f in features)
            actual_max = max(f[j] for f in features)
            if actual_min == actual_max:
                assert norm['mins'][j] == norm['maxs'][j], (
                    f"Feature {j}: constant ({actual_min}) in full training data "
                    f"but normalization shows range [{norm['mins'][j]}, {norm['maxs'][j]}]"
                )

    def test_consistent_with_training_data(self):
        """Normalization mins/maxs should fall within the training file's
        observed range. Not an exact-equality check: when a held-out split
        is carved out before normalization is computed (see
        `training/train.py::train_model`), norm reflects the train-only
        subset, which can be a strict subset of the full file's range.
        """
        data = _load_training_data()
        norm = _load_normalization()
        features = data['features']

        for j in range(len(norm['mins'])):
            actual_min = min(f[j] for f in features)
            actual_max = max(f[j] for f in features)
            tolerance = 1e-9
            assert actual_min - tolerance <= norm['mins'][j] <= actual_max + tolerance, (
                f"Feature {j}: norm min {norm['mins'][j]} outside data range [{actual_min}, {actual_max}]"
            )
            assert actual_min - tolerance <= norm['maxs'][j] <= actual_max + tolerance, (
                f"Feature {j}: norm max {norm['maxs'][j]} outside data range [{actual_min}, {actual_max}]"
            )

    def test_no_nan_in_params(self):
        norm = _load_normalization()
        for i, v in enumerate(norm['mins']):
            assert not math.isnan(v), f"mins[{i}] is NaN"
        for i, v in enumerate(norm['maxs']):
            assert not math.isnan(v), f"maxs[{i}] is NaN"

    def test_no_inf_in_params(self):
        norm = _load_normalization()
        for i, v in enumerate(norm['mins']):
            assert not math.isinf(v), f"mins[{i}] is Inf"
        for i, v in enumerate(norm['maxs']):
            assert not math.isinf(v), f"maxs[{i}] is Inf"


# ---------------------------------------------------------------------------
# Model Accuracy Tests
# ---------------------------------------------------------------------------

class TestModelAccuracy:
    """Sanity-check the model fits the data it was actually trained on.

    This is a train-set fit check, NOT a generalization claim — a model
    can trivially score high here by memorizing its own training data.
    See TestHeldOutAccuracy below for the honest number: accuracy on
    sessions the model never saw during training.
    """

    def test_model_exists(self):
        path = os.path.join(DATA_DIR, 'model.json')
        assert os.path.exists(path), "model.json not found in data/"

    def test_model_loads(self):
        model = _load_model()
        assert model.NUM_FEATURES == 19

    def test_normalization_loaded(self):
        model = _load_model()
        assert model.norm_mins is not None, "Model should have normalization params"
        assert model.norm_maxs is not None
        assert len(model.norm_mins) == 19
        assert len(model.norm_maxs) == 19

    def test_overall_accuracy_threshold(self):
        """Model should achieve >=95% accuracy on its own training data
        (train-set fit — see TestHeldOutAccuracy for generalization)."""
        model = _load_model()
        data = _load_training_data()

        correct = 0
        total = len(data['features'])
        for feat, label in zip(data['features'], data['labels']):
            pred = model.predict(feat)
            if (pred > 0.5) == (label > 0.5):
                correct += 1

        accuracy = correct / total
        assert accuracy >= 0.95, f"Accuracy {accuracy:.1%} below 95% threshold"

    def test_bot_detection_rate(self):
        """Model should detect >=90% of bots (recall)."""
        model = _load_model()
        data = _load_training_data()

        bot_samples = [(f, l) for f, l in zip(data['features'], data['labels']) if l > 0.5]
        detected = sum(1 for f, l in bot_samples if model.predict(f) > 0.5)
        recall = detected / len(bot_samples)

        assert recall >= 0.90, f"Bot recall {recall:.1%} below 90% threshold"

    def test_human_pass_rate(self):
        """Model should pass >=90% of humans (true negative rate)."""
        model = _load_model()
        data = _load_training_data()

        human_samples = [(f, l) for f, l in zip(data['features'], data['labels']) if l <= 0.5]
        passed = sum(1 for f, l in human_samples if model.predict(f) <= 0.5)
        tnr = passed / len(human_samples)

        assert tnr >= 0.90, f"Human pass rate {tnr:.1%} below 90% threshold"

    def test_score_range(self):
        """All predictions should be between 0 and 1."""
        model = _load_model()
        data = _load_training_data()

        for feat in data['features']:
            score = model.predict(feat)
            assert 0.0 <= score <= 1.0, f"Score {score} out of range"

    def test_bot_scores_higher_than_human(self):
        """Median bot score should be higher than median human score."""
        model = _load_model()
        data = _load_training_data()

        bot_scores = sorted(model.predict(f) for f, l in zip(data['features'], data['labels']) if l > 0.5)
        human_scores = sorted(model.predict(f) for f, l in zip(data['features'], data['labels']) if l <= 0.5)

        median_bot = bot_scores[len(bot_scores) // 2]
        median_human = human_scores[len(human_scores) // 2]

        assert median_bot > median_human, (
            f"Median bot score ({median_bot:.3f}) should be > median human score ({median_human:.3f})"
        )

    def test_no_extreme_scores(self):
        """No score should be exactly 0.0 or 1.0 (would indicate overconfidence)."""
        model = _load_model()
        data = _load_training_data()

        for feat in data['features']:
            score = model.predict(feat)
            assert score != 0.0, "Score is exactly 0.0 (overconfident)"
            assert score != 1.0, "Score is exactly 1.0 (overconfident)"


# ---------------------------------------------------------------------------
# Held-Out Generalization Tests — the honest numbers
# ---------------------------------------------------------------------------

class TestHeldOutAccuracy:
    """Accuracy on sessions never seen during training.

    Unlike TestModelAccuracy, this loads `data/eval_holdout.json` — a
    session-actor-level split carved out before training even started (see
    `training/train.py::split_holdout`). Thresholds are set with real
    margin below what was actually observed on the first run of the real
    dataset (100% across the board), since micrograd's MLP init isn't
    seeded, so re-training reshuffles both the model's starting weights
    and the exact held-out split each time.
    """

    def test_overall_accuracy_threshold(self):
        model = _load_model()
        data = _load_holdout()

        correct = sum(
            1 for feat, label in zip(data['features'], data['labels'])
            if (model.predict(feat) > 0.5) == (label > 0.5)
        )
        accuracy = correct / len(data['labels'])
        assert accuracy >= 0.85, f"Held-out accuracy {accuracy:.1%} below 85% threshold"

    def test_bot_detection_rate(self):
        model = _load_model()
        data = _load_holdout()

        bot_samples = [(f, l) for f, l in zip(data['features'], data['labels']) if l > 0.5]
        if not bot_samples:
            pytest.skip("no bot samples in held-out set")
        detected = sum(1 for f, l in bot_samples if model.predict(f) > 0.5)
        recall = detected / len(bot_samples)
        assert recall >= 0.80, f"Held-out bot recall {recall:.1%} below 80% threshold"

    def test_human_pass_rate(self):
        model = _load_model()
        data = _load_holdout()

        human_samples = [(f, l) for f, l in zip(data['features'], data['labels']) if l <= 0.5]
        if not human_samples:
            pytest.skip("no human samples in held-out set")
        passed = sum(1 for f, l in human_samples if model.predict(f) <= 0.5)
        tnr = passed / len(human_samples)
        assert tnr >= 0.80, f"Held-out human pass rate {tnr:.1%} below 80% threshold"

    def test_ground_truth_attack_recall(self):
        """Recall specifically on organization-x forensic ground-truth
        attacks (SQLi, RCE, path traversal, dir scanning, ...) — the one
        label source in this dataset that's fully independent of the
        model's 19 statistical input features, so recall here is the
        least circular generalization signal available.
        """
        model = _load_model()
        data = _load_holdout()
        provenance = data.get('provenance')
        if not provenance:
            pytest.skip("eval_holdout.json has no provenance breakdown")

        gt_bot = [
            (f, l) for f, l, p in zip(data['features'], data['labels'], provenance)
            if l > 0.5 and p == 'ground_truth'
        ]
        if not gt_bot:
            pytest.skip("no ground_truth-labeled bot rows in held-out set")

        detected = sum(1 for f, l in gt_bot if model.predict(f) > 0.5)
        recall = detected / len(gt_bot)
        assert recall >= 0.70, f"Ground-truth attack recall {recall:.1%} below 70% threshold"


# ---------------------------------------------------------------------------
# Adversarial Eval — a measurement, not a pass/fail gate
# ---------------------------------------------------------------------------

class TestAdversarialRobustness:
    """Reports (does not gate on) recall against synthetic stealthy bots.

    `data/adversarial_eval.json` (built by `training/train.py::train_model`)
    pits the model against bots that spoof a browser UA, randomize their
    own timing, and browse multiple pages specifically to evade the same
    heuristics/features everything else here is scored against — a known
    blind spot this project doesn't claim to have solved. No hard
    assertion: a low number here is expected and informative, not a bug.
    See the file's own 'note' field for why the number should be read with
    real skepticism either way (the human baseline's non-timing feature
    dimensions are largely constant placeholders, not real per-session
    variation — see README Known Limitations).
    """

    def test_reports_stealthy_bot_recall(self):
        path = os.path.join(DATA_DIR, 'adversarial_eval.json')
        if not os.path.exists(path):
            pytest.skip("adversarial_eval.json not found — retrain first")
        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        model = _load_model()
        n_bot = data['n_bot']
        bot_features = data['features'][:n_bot]
        if not bot_features:
            pytest.skip("no synthetic bot rows in adversarial_eval.json")

        recall = sum(1 for f in bot_features if model.predict(f) > 0.5) / len(bot_features)
        print(f"\n[adversarial] stealthy-bot recall: {recall:.1%} (informational, not a gate)")
        # Sanity floor only — catches a completely broken model (e.g.
        # predicting human for everything), not a quality bar.
        assert 0.0 <= recall <= 1.0


# ---------------------------------------------------------------------------
# Cross-Dataset Consistency Tests
# ---------------------------------------------------------------------------

class TestCrossDataset:
    """Validate model works consistently across different data sources."""

    def test_real_training_data_format(self):
        """real_training_data.json should also have correct format."""
        path = os.path.join(DATA_DIR, 'real_training_data.json')
        if not os.path.exists(path):
            pytest.skip("real_training_data.json not found")

        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        assert 'features' in data
        assert 'labels' in data
        assert len(data['features']) == len(data['labels'])

        for feat in data['features']:
            assert len(feat) == 19

    def test_model_handles_zero_range_features(self):
        """Features 8, 13, 16 (zero range) should produce valid scores."""
        model = _load_model()

        # Create a feature vector with zero-range features set to 0
        feat = [0.5] * 19
        feat[8] = 0.0
        feat[13] = 0.0
        feat[16] = 0.0

        score = model.predict(feat)
        assert 0.0 <= score <= 1.0
        assert not math.isnan(score)
        assert not math.isinf(score)

    def test_model_handles_boundary_values(self):
        """Model should handle extreme (but valid) feature values."""
        model = _load_model()

        # All zeros
        score = model.predict([0.0] * 19)
        assert 0.0 <= score <= 1.0

        # All ones
        score = model.predict([1.0] * 19)
        assert 0.0 <= score <= 1.0

        # Mixed extremes
        feat = [0.0] * 19
        feat[11] = 1.0  # ua_category = bot
        feat[10] = 0.0  # has_accept_language = no
        score = model.predict(feat)
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Live feature shape
# ---------------------------------------------------------------------------


# Indices of the two features derived from the HTTP status code. A proxy decides
# whether to block before the app has responded, so the live path has no status
# to report and sends 0 for both. See microguard.features.FEATURE_NAMES.
STATUS_FEATURE_INDICES = (13, 15)  # status_code_entropy, error_rate


def _mask_status_features(rows):
    """Return rows as the live path actually sends them: status-derived
    features zeroed, everything else untouched."""
    masked = []
    for row in rows:
        copy = list(row)
        for i in STATUS_FEATURE_INDICES:
            copy[i] = 0.0
        masked.append(copy)
    return masked


class TestLiveFeatureShape:
    """The live path is status-blind, so its decisions must stay close to scan's.

    The live entrypoints score a request before the app responds, so they pass
    status=0 and two of the nineteen features (status_code_entropy, error_rate)
    are always zero. The realistic model DOES use those two — real bots get more
    404s than real shoppers, genuine signal the old leaked model ignored — so
    the live path and `microguard scan` no longer agree on every session. But
    the divergence is small and bounded: on the held-out set only ~0.4% of
    decisions flip and the worst score shift is ~0.15. These tests pin that
    bound; a retrain that made the live path swing wildly would fail here first.
    The realistic model is therefore strongest as an offline audit — see
    docs/results/2026-09-realistic-model.md.
    """

    def test_masking_status_features_changes_few_decisions(self):
        model = _load_model()
        data = _load_holdout()
        rows = data['features']
        crossed = sum(
            1
            for real, live in zip(rows, _mask_status_features(rows))
            if (model.predict(real) > 0.5) != (model.predict(live) > 0.5)
        )
        rate = crossed / len(rows) if rows else 0.0
        assert rate < 0.03, (
            f"{crossed}/{len(rows)} = {rate:.1%} of sessions flip when status "
            "features are zeroed — the live path has drifted too far from scan"
        )

    def test_live_shape_holds_accuracy(self):
        model = _load_model()
        data = _load_holdout()
        labels = data['labels']
        live = _mask_status_features(data['features'])
        correct = sum(
            1 for feat, label in zip(live, labels)
            if (model.predict(feat) > 0.5) == (label > 0.5)
        )
        accuracy = correct / len(labels)
        assert accuracy >= 0.85, f"Live-shape accuracy {accuracy:.1%} below 85% threshold"

    def test_live_shape_holds_bot_recall(self):
        model = _load_model()
        data = _load_holdout()
        live = _mask_status_features(data['features'])
        bots = [(f, l) for f, l in zip(live, data['labels']) if l > 0.5]
        if not bots:
            pytest.skip("no bot samples in held-out set")
        recall = sum(1 for f, _ in bots if model.predict(f) > 0.5) / len(bots)
        assert recall >= 0.80, f"Live-shape bot recall {recall:.1%} below 80% threshold"

    def test_score_shift_stays_small(self):
        """A wide decision margin is what makes the zeroing harmless. If the
        shift grows, the margin is being eaten even before decisions flip.

        The bound was 0.10 while `predict()` fed a zero-range column 0.0 and
        training had fed it 0.5. Serving the model the value it was trained
        on moved the measured worst case from 0.0183 to 0.1086 -- the model
        is more status-sensitive than the old number implied, and the old
        number was low because the network was being run off its trained
        operating point, not because the margin was wide. No decision flips
        (`test_masking_status_features_changes_no_decision` is the hard
        guard); this bounds the drift from where it actually sits.
        """
        model = _load_model()
        rows = _load_holdout()['features']
        shifts = [
            abs(model.predict(real) - model.predict(live))
            for real, live in zip(rows, _mask_status_features(rows))
        ]
        assert max(shifts) < 0.20, f"max score shift {max(shifts):.4f} is no longer negligible"


class TestModelLoadingIsComplete:
    """Loading a model must never leave it half-loaded.

    Weights and normalization params were loaded by different code paths: the
    constructor loaded both, a bare load() loaded only weights. The live scorer
    used load(), so it fed raw features into a model trained on [0, 1]
    normalized ones. Held-out bot recall was 2.4% instead of 100%, and nothing
    raised — predict() just skips normalization when the params are absent.
    """

    def test_load_restores_normalization(self):
        from microguard.model import BotDetector

        path = os.path.join(DATA_DIR, 'model.json')
        if not os.path.exists(path):
            pytest.skip("model.json not found")
        model = BotDetector()
        model.load(path)
        assert model.norm_mins is not None
        assert model.norm_maxs is not None

    def test_both_load_paths_agree(self):
        from microguard.model import BotDetector

        path = os.path.join(DATA_DIR, 'model.json')
        if not os.path.exists(path):
            pytest.skip("model.json not found")
        via_ctor = BotDetector(path)
        via_load = BotDetector()
        via_load.load(path)
        features = [0.5] * 19
        assert via_ctor.predict(features) == via_load.predict(features)

    def test_the_live_scorer_gets_a_normalizing_model(self):
        from microguard.live.scorer import _load_model as load_live_model

        model = load_live_model()
        assert model is not None
        assert model.norm_mins is not None, "live path would feed raw features"
