"""Training pipeline for the bot detection model.

Downloads Harvard Shopping Logs dataset, extracts features,
applies heuristic labels, and trains the micrograd MLP.
"""

import json
import os
import random
import sys
from typing import Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from micrograd.nn import MLP

from microguard.features import extract_features, group_into_sessions
from microguard.labeler import label_session
from microguard.model import BotDetector
from microguard.parser import LogEntry, parse_file
from microguard.training.generate import generate_stealthy_bot_session


def prepare_training_data(
    log_entries: list[LogEntry],
    timeout_minutes: int = 30,
) -> tuple[list[list[float]], list[float]]:
    """Convert log entries into training data.
    
    Args:
        log_entries: Parsed log entries
        timeout_minutes: Session timeout
    
    Returns:
        (features, labels) tuple
    """
    sessions = group_into_sessions(log_entries, timeout_minutes)
    
    features_list = []
    labels_list = []
    
    for session in sessions:
        # Skip very short sessions (< 3 requests)
        if session.request_count < 3:
            continue
        
        # Extract features
        features = extract_features(session)
        
        # Get label
        label_str, _confidence, _reason = label_session(session)
        label = 1.0 if label_str == 'bot' else 0.0
        
        features_list.append(features)
        labels_list.append(label)
    
    return features_list, labels_list


def compute_normalization(features: list[list[float]]) -> tuple[list[float], list[float]]:
    """Compute min/max normalization parameters from feature vectors.
    
    Args:
        features: List of feature vectors
    
    Returns:
        (mins, maxs) tuple
    """
    n_feat = len(features[0])
    mins = [float('inf')] * n_feat
    maxs = [float('-inf')] * n_feat
    
    for row in features:
        for i, v in enumerate(row):
            mins[i] = min(mins[i], v)
            maxs[i] = max(maxs[i], v)
    
    return mins, maxs


def normalize_features(
    features: list[list[float]],
    mins: list[float],
    maxs: list[float],
) -> list[list[float]]:
    """Normalize features to [0, 1] range.
    
    Features with zero range (min == max) map to 0.5.
    """
    normalized = []
    for row in features:
        norm_row = []
        for i, v in enumerate(row):
            if maxs[i] > mins[i]:
                norm_row.append((v - mins[i]) / (maxs[i] - mins[i]))
            else:
                norm_row.append(0.5)  # Zero-range feature
        normalized.append(norm_row)
    return normalized


def split_holdout(
    features: list[list[float]],
    labels: list[float],
    group_ids: list[str],
    test_frac: float = 0.2,
    seed: int = 42,
) -> tuple[list[int], list[int]]:
    """Session-group-level stratified train/held-out split.

    Splits by group_id (not row), so no single actor's session(s) can
    appear on both sides, then stratifies by label so both splits contain
    both classes. Returns (train_indices, test_indices).
    """
    rng = random.Random(seed)

    group_label: dict[str, float] = {}
    group_rows: dict[str, list[int]] = {}
    for i, (gid, label) in enumerate(zip(group_ids, labels)):
        group_label.setdefault(gid, label)
        group_rows.setdefault(gid, []).append(i)

    bot_groups = [g for g, lbl in group_label.items() if lbl > 0.5]
    human_groups = [g for g, lbl in group_label.items() if lbl <= 0.5]
    rng.shuffle(bot_groups)
    rng.shuffle(human_groups)

    def _split(groups: list[str]) -> tuple[list[str], list[str]]:
        if not groups:
            return [], []
        n_test = max(1, int(len(groups) * test_frac))
        return groups[n_test:], groups[:n_test]

    bot_train, bot_test = _split(bot_groups)
    human_train, human_test = _split(human_groups)

    train_idx = [i for g in bot_train + human_train for i in group_rows[g]]
    test_idx = [i for g in bot_test + human_test for i in group_rows[g]]
    return train_idx, test_idx


def train_model(
    features: list[list[float]],
    labels: list[float],
    model_path: str = "data/model.json",
    epochs: int = 100,
    learning_rate: float = 0.05,
    group_ids: list[str] | None = None,
    provenance: list[str] | None = None,
    holdout_frac: float = 0.2,
) -> tuple[BotDetector, dict[str, Any]]:
    """Train the bot detection model with normalization.

    Computes normalization from training data, normalizes features,
    saves normalization.json alongside model.json.

    Args:
        features: List of feature vectors
        labels: List of labels (0.0=human, 1.0=bot)
        model_path: Path to save trained model
        epochs: Number of training epochs
        learning_rate: Learning rate
        group_ids: Optional per-row actor/session identifiers. When given,
            a session-group-level stratified split is carved out BEFORE
            normalization or training and saved as eval_holdout.json next
            to the model — an honest, never-seen generalization check,
            not an in-sample accuracy number.
        holdout_frac: Fraction of groups (per class) held out for eval.

    Returns:
        (Trained BotDetector, metrics dict) tuple. Metrics dict contains:
        - accuracy, tp, tn, fp, fn, precision, recall
        - holdout_accuracy, holdout_precision, holdout_recall (if holdout used)
        - adversarial_recall (if adversarial eval run)
        - _artifacts: dict of file paths for MLflow logging
    """
    holdout_features: list[list[float]] | None = None
    holdout_labels: list[float] | None = None
    holdout_provenance: list[str] | None = None

    if group_ids is not None:
        train_idx, test_idx = split_holdout(features, labels, group_ids, test_frac=holdout_frac)
        holdout_features = [features[i] for i in test_idx]
        holdout_labels = [labels[i] for i in test_idx]
        if provenance is not None:
            holdout_provenance = [provenance[i] for i in test_idx]
        features = [features[i] for i in train_idx]
        labels = [labels[i] for i in train_idx]
        print(
            f"\n🔒 Held-out split: {len(holdout_features)} test / {len(features)} train "
            "sessions (group-level, stratified — no actor appears in both)"
        )

    print("\n🧠 Training model...")
    print(f"   Samples: {len(features)}")
    print(f"   Bot: {sum(labels):.0f} | Human: {len(labels) - sum(labels):.0f}")
    print(f"   Epochs: {epochs} | LR: {learning_rate}")

    # Compute normalization from training data
    mins, maxs = compute_normalization(features)
    
    # Save normalization params
    norm_path = os.path.join(os.path.dirname(model_path) or '.', 'normalization.json')
    os.makedirs(os.path.dirname(norm_path) or '.', exist_ok=True)
    with open(norm_path, 'w', encoding='utf-8') as f:
        json.dump({'mins': mins, 'maxs': maxs}, f, indent=2)
    print(f"   Normalization saved to: {norm_path}")
    
    # Keep raw features and labels for evaluation (predict() normalizes internally)
    raw_features = features[:]
    raw_labels = labels[:]
    
    # Normalize features for training
    features = normalize_features(features, mins, maxs)
    
    model = BotDetector()
    # Disable normalization in predict() — features are already normalized
    model.norm_mins = None
    model.norm_maxs = None
    
    # Shuffle data
    combined = list(zip(features, labels))
    random.shuffle(combined)
    shuffled_features, shuffled_labels = zip(*combined)
    features = list(shuffled_features)
    labels = list(shuffled_labels)

    # Train. Roughly a quarter of random initializations collapse to a
    # constant classifier and stay there -- a hidden unit whose weights sum
    # negative never fires on non-negative inputs, and a ReLU that never
    # fires has no gradient to learn from. Redraw and start over rather than
    # saving a model that scores every session the same.
    def redraw() -> None:
        model.model = MLP(BotDetector.NUM_FEATURES, [4, 1])
        model.norm_mins = None
        model.norm_maxs = None

    attempts = model.train_until_it_learns(
        features,
        labels,
        reset=redraw,
        epochs=epochs,
        batch_size=min(32, len(features)),
        learning_rate=learning_rate,
        val_split=0.2,
        verbose=True,
    )
    if attempts > 1:
        print(f"   (took {attempts} attempts — earlier ones collapsed)")
    
    # Restore normalization params so predict() works at inference time
    model.norm_mins = mins
    model.norm_maxs = maxs
    
    # Save model
    os.makedirs(os.path.dirname(model_path) or '.', exist_ok=True)
    model.save(model_path)
    print(f"\n💾 Model saved to: {model_path}")
    
    # Evaluate (predict_batch normalizes internally using restored params)
    print("\n📊 Final Evaluation:")
    all_preds = model.predict_batch(raw_features)
    correct = sum(1 for pred, label in zip(all_preds, raw_labels) 
                  if (pred > 0.5) == (label > 0.5))
    accuracy = correct / len(labels) if labels else 0.0
    print(f"   Accuracy: {accuracy:.1%}")
    
    # Confusion matrix
    tp = sum(1 for p, l in zip(all_preds, raw_labels) if p > 0.5 and l > 0.5)
    tn = sum(1 for p, l in zip(all_preds, raw_labels) if p <= 0.5 and l <= 0.5)
    fp = sum(1 for p, l in zip(all_preds, raw_labels) if p > 0.5 and l <= 0.5)
    fn = sum(1 for p, l in zip(all_preds, raw_labels) if p <= 0.5 and l > 0.5)
    
    print(f"   True Positives:  {tp} (correctly caught bots)")
    print(f"   True Negatives:  {tn} (correctly passed humans)")
    print(f"   False Positives: {fp} (humans blocked)")
    print(f"   False Negatives: {fn} (bots missed)")
    
    if tp + fp > 0:
        precision = tp / (tp + fp)
        print(f"   Precision: {precision:.1%}")
    
    if tp + fn > 0:
        recall = tp / (tp + fn)
        print(f"   Recall: {recall:.1%}")

    # Initialize for adversarial eval tracking
    real_human_holdout: list[list[float]] = []
    n_adv: int = 0

    # Held-out evaluation — the only honest generalization number. The
    # "Final Evaluation" above is train-set fit and will always look
    # better than this; that's expected, not a bug.
    if holdout_features is not None and holdout_labels is not None:
        holdout_path = os.path.join(os.path.dirname(model_path) or '.', 'eval_holdout.json')
        n_bot_h = sum(1 for lbl in holdout_labels if lbl > 0.5)
        with open(holdout_path, 'w', encoding='utf-8') as f:
            json.dump({
                'features': holdout_features,
                'labels': holdout_labels,
                'provenance': holdout_provenance,
                'n_samples': len(holdout_labels),
                'n_features': len(holdout_features[0]) if holdout_features else 0,
                'n_human': len(holdout_labels) - n_bot_h,
                'n_bot': n_bot_h,
            }, f, indent=2)
        print(f"\n💾 Held-out eval set saved to: {holdout_path}")

        print("\n📊 Held-Out Evaluation (never seen during training):")
        h_preds = model.predict_batch(holdout_features)
        h_correct = sum(
            1 for p, lbl in zip(h_preds, holdout_labels) if (p > 0.5) == (lbl > 0.5)
        )
        h_acc = h_correct / len(holdout_labels) if holdout_labels else 0.0
        h_tp = sum(1 for p, lbl in zip(h_preds, holdout_labels) if p > 0.5 and lbl > 0.5)
        h_tn = sum(1 for p, lbl in zip(h_preds, holdout_labels) if p <= 0.5 and lbl <= 0.5)
        h_fp = sum(1 for p, lbl in zip(h_preds, holdout_labels) if p > 0.5 and lbl <= 0.5)
        h_fn = sum(1 for p, lbl in zip(h_preds, holdout_labels) if p <= 0.5 and lbl > 0.5)
        print(f"   Accuracy: {h_acc:.1%}")
        print(f"   True Positives:  {h_tp}")
        print(f"   True Negatives:  {h_tn}")
        print(f"   False Positives: {h_fp}")
        print(f"   False Negatives: {h_fn}")
        if h_tp + h_fp > 0:
            print(f"   Precision: {h_tp / (h_tp + h_fp):.1%}")
        if h_tp + h_fn > 0:
            print(f"   Recall: {h_tp / (h_tp + h_fn):.1%}")

        # Breakdown by label provenance. This matters because
        # 'heuristic_real' bot labels come from the SAME rule-based logic
        # that some of the 19 model features also encode (e.g. a known-bot
        # user agent drives both the `ua_category` feature AND the
        # heuristic label) — recall on that subset is somewhat circular.
        # 'ground_truth' labels (real forensic attack-pattern matches:
        # SQLi, RCE, path traversal, ...) are an independent signal the
        # model was never told directly, so recall there is the honest
        # generalization number.
        if holdout_provenance is not None:
            print("\n   By label source (bot rows only):")
            sources = sorted(set(holdout_provenance))
            for source in sources:
                idx = [i for i, p in enumerate(holdout_provenance) if p == source]
                bot_idx = [i for i in idx if holdout_labels[i] > 0.5]
                if not bot_idx:
                    continue
                detected = sum(1 for i in bot_idx if h_preds[i] > 0.5)
                print(f"     {source:<20} recall: {detected}/{len(bot_idx)} ({detected / len(bot_idx):.1%})")

        # Adversarial eval — a known, honestly-measured blind spot, not a
        # pass/fail gate. `generate_stealthy_bot_session()` is SYNTHETIC: a
        # bot that spoofs a browser UA, randomizes its own timing, and
        # browses multiple pages specifically to evade the same heuristics
        # everything else in this file is scored against. It's never
        # trained on (a generator this close to the human distribution
        # would just teach the model an arbitrary synthetic boundary, not
        # anything real) — only used here to measure how the trained model
        # handles bots that deliberately don't look like the training
        # data's bots. Expect this number to be much lower than the
        # held-out numbers above; that's the honest point of running it.
        real_human_holdout = [f for f, lbl in zip(holdout_features, holdout_labels) if lbl <= 0.5]
        if real_human_holdout:
            n_adv = min(200, len(real_human_holdout))
            adv_bot_features = [generate_stealthy_bot_session() for _ in range(n_adv)]
            adv_human_features = real_human_holdout[:n_adv]
            adv_features = adv_bot_features + adv_human_features
            adv_labels = [1.0] * len(adv_bot_features) + [0.0] * len(adv_human_features)

            adv_path = os.path.join(os.path.dirname(model_path) or '.', 'adversarial_eval.json')
            with open(adv_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'features': adv_features,
                    'labels': adv_labels,
                    'n_samples': len(adv_features),
                    'n_bot': len(adv_bot_features),
                    'n_human': len(adv_human_features),
                    'note': (
                        'Bot rows are synthetic stealthy-bot vectors '
                        '(generate_stealthy_bot_session), never trained on. '
                        'Human rows are real, from the held-out eval set — '
                        'but caveat: 10 of 19 feature dimensions in the '
                        'Harvard human data (endpoint_sequence_entropy, '
                        'header_consistency_score, payload_entropy, '
                        'status_code_entropy, ua_category, and others — see '
                        'README Known Limitations) are constant placeholder '
                        'values, not per-session real variation, so this '
                        'result is easier to achieve than it would be '
                        'against fully-realistic diverse human traffic. '
                        'Measures a known blind spot; a high number here is '
                        'NOT strong evidence of adversarial robustness.'
                    ),
                }, f, indent=2)

            adv_preds = model.predict_batch(adv_features)
            adv_bot_preds = adv_preds[:len(adv_bot_features)]
            adv_recall = sum(1 for p in adv_bot_preds if p > 0.5) / len(adv_bot_preds)
            print(f"\n⚠️  Adversarial eval saved to: {adv_path}")
            print(f"   Stealthy-bot recall: {adv_recall:.1%} (see file's 'note' — this is an easier")
            print("   test than real diverse human traffic would be; not proof of robustness)")

    # Collect metrics for return
    norm_path = os.path.join(os.path.dirname(model_path) or '.', 'normalization.json')
    result_metrics: dict[str, Any] = {
        "accuracy": accuracy,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }
    if tp + fp > 0:
        result_metrics["precision"] = tp / (tp + fp)
    if tp + fn > 0:
        result_metrics["recall"] = tp / (tp + fn)

    # Held-out metrics
    if holdout_features is not None and holdout_labels is not None:
        result_metrics["holdout_accuracy"] = h_acc
        if h_tp + h_fp > 0:
            result_metrics["holdout_precision"] = h_tp / (h_tp + h_fp)
        if h_tp + h_fn > 0:
            result_metrics["holdout_recall"] = h_tp / (h_tp + h_fn)

    # Adversarial metric
    if holdout_features is not None and real_human_holdout and n_adv > 0:
        result_metrics["adversarial_recall"] = adv_recall

    # Artifact paths for MLflow logging
    result_metrics["_artifacts"] = {
        "model": model_path,
        "normalization": norm_path,
        "eval_holdout": holdout_path if holdout_features is not None else None,
        "adversarial_eval": adv_path if (holdout_features is not None and real_human_holdout and n_adv > 0) else None,
    }

    return model, result_metrics


def default_data_dir() -> str:
    """The repo's data/ directory, resolved from this file's location.

    Split out from main() so it can be checked without running a training
    pass against the real directory.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(os.path.dirname(here)), 'data')


def main(data_dir: str | None = None, epochs: int = 100, learning_rate: float = 0.05):
    """Main training entry point.

    Args:
        data_dir: Where to read datasets from and write the model to. Defaults
            to the repo's data/ directory. Parameterized so the dataset-priority
            dispatch below can be exercised against a temporary directory — a
            test that ran this against the real data/ would overwrite the
            shipped model.json, normalization.json and both eval sets.
        epochs: Training epochs. Lower it for a smoke run.
        learning_rate: SGD learning rate.
    """
    # Not exercised in tests on purpose: taking this branch means training
    # against the real data/ and overwriting the shipped model. The resolution
    # itself is covered via default_data_dir().
    if data_dir is None:  # pragma: no cover
        data_dir = default_data_dir()

    group_ids = None
    provenance = None
    data_source = "synthetic"

    # Priority -1: realistic data — REAL human shoppers AND real bots from the
    # same site (Zanbil) plus organization-x attacks. Built by
    # `microguard.training.build_realistic_dataset`. Preferred over everything
    # else because it is the first dataset whose *human* class is real sessions
    # extracted the same way as the bots, which is what removes the source-
    # fingerprint leak the older sets carry. See docs/results/2026-09-realistic-model.md.
    realistic_path = os.path.join(data_dir, 'realistic_training_data.json')
    real_bot_path = os.path.join(data_dir, 'real_bot_training_data.json')
    if os.path.exists(realistic_path):
        data_source = "realistic"
        print(f"📂 Loading realistic training data from: {realistic_path}")
        with open(realistic_path, encoding='utf-8') as f:
            data = json.load(f)
        features = data['features']
        labels = data['labels']
        group_ids = data.get('group_ids')
        provenance = data.get('provenance')
        print(f"   Samples: {len(features)} (Human: {data.get('n_human', '?')}, Bot: {data.get('n_bot', '?')})")
        print(f"   Source breakdown: {data.get('source_counts', {})}")

    elif os.path.exists(real_bot_path):
        data_source = "real_bot_training_data"
        print(f"📂 Loading real bot-training data from: {real_bot_path}")
        with open(real_bot_path, encoding='utf-8') as f:
            data = json.load(f)
        features = data['features']
        labels = data['labels']
        group_ids = data.get('group_ids')
        provenance = data.get('provenance')
        print(f"   Samples: {len(features)} (Human: {data.get('n_human', '?')}, Bot: {data.get('n_bot', '?')})")
        print(f"   Source breakdown: {data.get('source_counts', {})}")

    # Priority 1: Harvard training data (pre-processed from Dataverse)
    elif os.path.exists(harvard_path := os.path.join(data_dir, 'harvard_training_data.json')):
        data_source = "harvard"
        print(f"📂 Loading Harvard training data from: {harvard_path}")
        with open(harvard_path, encoding='utf-8') as f:
            data = json.load(f)
        features = data['features']
        labels = data['labels']
        print(f"   Samples: {len(features)} (Human: {data.get('n_human', '?')}, Bot: {data.get('n_bot', '?')})")
    
    # Priority 2: Real training data (Zenodo + synthetic combined)
    elif os.path.exists(os.path.join(data_dir, 'real_training_data.json')):
        data_source = "real_training"
        real_path = os.path.join(data_dir, 'real_training_data.json')
        print(f"📂 Loading real training data from: {real_path}")
        with open(real_path, encoding='utf-8') as f:
            data = json.load(f)
        features = data['features']
        labels = data['labels']
        print(f"   Samples: {len(features)}")
    
    # Priority 3: Raw logs (Zenodo Apache logs)
    elif os.path.exists(os.path.join(data_dir, 'access.log')):
        data_source = "access_log"
        dataset_path = os.path.join(data_dir, 'access.log')
        print(f"📂 Loading dataset from: {dataset_path}")
        entries = list(parse_file(dataset_path))
        print(f"   Parsed {len(entries)} log entries")
        features, labels = prepare_training_data(entries)
        print(f"   Extracted {len(features)} sessions")
    
    # Priority 4: Synthetic fallback
    else:
        print("📥 No dataset found. Generating synthetic training data...")
        features, labels = generate_synthetic_data(n_samples=500)
        print(f"   Generated {len(features)} synthetic samples")
    
    # Train model
    model_path = os.path.join(data_dir, 'model.json')

    model, _ = train_model(
        features=features,
        labels=labels,
        model_path=model_path,
        epochs=epochs,
        learning_rate=learning_rate,
        group_ids=group_ids,
        provenance=provenance,
    )

    print("\n✅ Training complete!")
    print(f"   Dataset: {data_source}")
    print(f"   Model: {model}")
    print("   Ready to use: microguard scan <logfile>")


def generate_synthetic_data(n_samples: int = 500) -> tuple[list[list[float]], list[float]]:
    """Generate synthetic training data for initial model training.
    
    Creates realistic feature vectors for bots and humans based on
    known patterns from the Nescio98 research.
    """
    features = []
    labels = []
    
    for _ in range(n_samples // 2):
        # Generate HUMAN-like session features
        # Humans: variable timing, multiple endpoints, browser UA, low error rate
        human_features = [
            random.uniform(2.0, 30.0),      # time_since_last_request (variable)
            random.uniform(1.0, 15.0),      # requests_per_minute_1m
            random.uniform(1.0, 10.0),      # requests_per_minute_5m
            random.uniform(0.4, 1.5),       # inter_request_time_cv (high = variable)
            random.uniform(30.0, 600.0),    # time_since_session_start
            random.uniform(3.0, 20.0),      # endpoint_count (multiple)
            random.uniform(1.5, 3.5),       # endpoint_sequence_entropy
            random.uniform(0.5, 1.0),       # unique_endpoint_ratio
            random.uniform(0.0, 0.1),       # method_mismatch_count
            random.uniform(0.7, 1.0),       # header_consistency_score
            1.0,                            # has_accept_language (browser)
            0.0,                            # ua_category (browser)
            random.uniform(2.0, 4.0),       # payload_entropy
            random.uniform(0.0, 0.3),       # status_code_entropy (mostly 200s)
            random.uniform(1.0, 5.0),       # same_endpoint_hits
            random.uniform(0.0, 0.1),       # error_rate
            random.uniform(0.1, 0.4),       # image_ratio
            random.uniform(0.0, 0.2),       # night_ratio
            random.uniform(0.0, 2.0),       # max_sustained_click_rate
        ]
        features.append(human_features)
        labels.append(0.0)
    
    for _ in range(n_samples // 2):
        # Generate BOT-like session features
        # Bots: uniform timing, repetitive endpoints, bot UA, high error rate
        bot_type = random.choice(['scraper', 'scanner', 'crawler'])
        
        if bot_type == 'scraper':
            bot_features = [
                random.uniform(0.01, 0.1),   # time_since_last_request (very fast)
                random.uniform(50.0, 200.0), # requests_per_minute_1m (high)
                random.uniform(50.0, 200.0), # requests_per_minute_5m (high)
                random.uniform(0.0, 0.1),    # inter_request_time_cv (low = uniform)
                random.uniform(1.0, 60.0),   # time_since_session_start
                random.uniform(1.0, 5.0),    # endpoint_count (few)
                random.uniform(0.0, 1.5),    # endpoint_sequence_entropy (low)
                random.uniform(0.1, 0.5),    # unique_endpoint_ratio (low)
                random.uniform(0.0, 0.2),    # method_mismatch_count
                random.uniform(0.0, 0.3),    # header_consistency_score
                0.0,                         # has_accept_language (missing)
                1.0,                         # ua_category (bot)
                random.uniform(1.0, 3.0),    # payload_entropy
                random.uniform(0.0, 0.3),    # status_code_entropy (mostly 200s)
                random.uniform(10.0, 100.0), # same_endpoint_hits (high)
                random.uniform(0.0, 0.05),   # error_rate
                random.uniform(0.0, 0.1),    # image_ratio
                random.uniform(0.0, 0.3),    # night_ratio
                random.uniform(5.0, 20.0),   # max_sustained_click_rate (high)
            ]
        elif bot_type == 'scanner':
            bot_features = [
                random.uniform(0.0, 0.05),   # time_since_last_request
                random.uniform(100.0, 500.0),# requests_per_minute_1m
                random.uniform(100.0, 500.0),# requests_per_minute_5m
                random.uniform(0.0, 0.05),   # inter_request_time_cv
                random.uniform(0.5, 10.0),   # time_since_session_start
                random.uniform(10.0, 50.0),  # endpoint_count (many)
                random.uniform(2.0, 4.0),    # endpoint_sequence_entropy
                random.uniform(0.8, 1.0),    # unique_endpoint_ratio (high)
                random.uniform(0.1, 0.5),    # method_mismatch_count
                random.uniform(0.0, 0.2),    # header_consistency_score
                0.0,                         # has_accept_language
                1.0,                         # ua_category (bot)
                random.uniform(2.0, 4.0),    # payload_entropy
                random.uniform(1.0, 2.0),    # status_code_entropy (mixed 200/403/404/500)
                random.uniform(1.0, 3.0),    # same_endpoint_hits
                random.uniform(0.3, 0.8),    # error_rate (high - probing)
                random.uniform(0.0, 0.05),   # image_ratio
                random.uniform(0.0, 0.5),    # night_ratio (scanning at night)
                random.uniform(10.0, 50.0),  # max_sustained_click_rate
            ]
        else:  # crawler
            bot_features = [
                random.uniform(0.5, 3.0),    # time_since_last_request
                random.uniform(5.0, 30.0),   # requests_per_minute_1m
                random.uniform(5.0, 30.0),   # requests_per_minute_5m
                random.uniform(0.1, 0.3),    # inter_request_time_cv (somewhat uniform)
                random.uniform(60.0, 300.0), # time_since_session_start
                random.uniform(20.0, 100.0), # endpoint_count (many pages)
                random.uniform(2.5, 4.0),    # endpoint_sequence_entropy
                random.uniform(0.7, 1.0),    # unique_endpoint_ratio
                random.uniform(0.0, 0.1),    # method_mismatch_count
                random.uniform(0.3, 0.7),    # header_consistency_score
                0.5,                         # has_accept_language (maybe)
                1.0,                         # ua_category (bot)
                random.uniform(2.5, 3.5),    # payload_entropy
                random.uniform(0.0, 0.4),    # status_code_entropy (mostly 200s)
                random.uniform(1.0, 5.0),    # same_endpoint_hits
                random.uniform(0.02, 0.1),   # error_rate
                random.uniform(0.2, 0.6),    # image_ratio (crawling images)
                random.uniform(0.0, 0.1),    # night_ratio
                random.uniform(2.0, 8.0),    # max_sustained_click_rate
            ]
        
        features.append(bot_features)
        labels.append(1.0)
    
    return features, labels


if __name__ == '__main__':
    main()
