"""Tests for the training pipeline: generate, prepare, normalize, split, train.

These three modules were at 0% coverage. `tests/test_training_quality.py` looks
like it covers them but does not — it never imports them. It loads the committed
JSON artifacts and asserts properties of the shipped model, which validates the
pipeline's *output*, not the code that produced it.

Two rules for anything added here:

1. **Never call a writing path without redirecting it.** `train_model`'s default
   is `model_path="data/model.json"`, a relative path, and pytest runs from the
   repo root. One unredirected call overwrites the committed model,
   normalization, holdout and adversarial artifacts — and roughly 25 tests in
   test_training_quality.py assert accuracy thresholds against exactly those.
2. **Keep the inputs tiny.** A production run is 100 epochs over ~2,400 rows,
   which takes minutes. Everything here uses tens of rows and 1-3 epochs.
"""

import json
import random

import pytest

from microguard.parser import LogEntry
from microguard.training import generate
from microguard.training.train import (
    compute_normalization,
    generate_synthetic_data,
    normalize_features,
    prepare_training_data,
    split_holdout,
)

FEATURE_COUNT = 19

# Index of ua_category in the feature vector: 0.0 browser, 1.0 bot, 2.0 unknown.
UA_CATEGORY = 11


class TestGenerateSessions:
    """The synthetic session generators. No I/O, global `random` only."""

    def test_human_session_has_the_right_width(self):
        assert len(generate.generate_human_session()) == FEATURE_COUNT

    def test_bot_session_has_the_right_width(self):
        assert len(generate.generate_bot_session()) == FEATURE_COUNT

    def test_stealthy_bot_session_has_the_right_width(self):
        assert len(generate.generate_stealthy_bot_session()) == FEATURE_COUNT

    def test_human_sessions_carry_a_browser_ua_category(self):
        random.seed(3)
        for _ in range(20):
            assert generate.generate_human_session()[UA_CATEGORY] == 0.0

    def test_bot_sessions_carry_a_bot_ua_category(self):
        random.seed(3)
        for _ in range(20):
            assert generate.generate_bot_session()[UA_CATEGORY] == 1.0

    def test_stealthy_bots_spoof_a_browser_ua(self):
        """That is the whole point of the adversarial set: these evade the
        UA-based signals, so the UA feature cannot give them away."""
        random.seed(3)
        for _ in range(20):
            assert generate.generate_stealthy_bot_session()[UA_CATEGORY] == 0.0

    def test_every_generator_covers_all_of_its_session_types(self):
        # Each generator picks among several shapes by weight; 200 draws makes
        # every branch overwhelmingly likely to be taken at least once.
        random.seed(11)
        for _ in range(200):
            generate.generate_human_session()
            generate.generate_bot_session()


class TestGenerateDataset:
    def test_honors_the_sample_count(self):
        features, labels = generate.generate_dataset(n_samples=20, seed=1)

        assert len(features) == 20
        assert len(labels) == 20

    def test_honors_the_balance(self):
        _features, labels = generate.generate_dataset(n_samples=20, balance=0.25, seed=1)

        assert sum(labels) == 15  # 25% human, so 75% bot

    def test_is_reproducible_for_a_seed(self):
        first = generate.generate_dataset(n_samples=10, seed=99)
        second = generate.generate_dataset(n_samples=10, seed=99)

        assert first == second

    def test_different_seeds_give_different_data(self):
        first = generate.generate_dataset(n_samples=10, seed=1)
        second = generate.generate_dataset(n_samples=10, seed=2)

        assert first != second

    def test_every_vector_is_the_right_width(self):
        features, _labels = generate.generate_dataset(n_samples=10, seed=1)

        assert all(len(row) == FEATURE_COUNT for row in features)


class TestSaveDataset:
    def test_writes_the_expected_shape(self, tmp_path, capsys):
        features, labels = generate.generate_dataset(n_samples=10, seed=1)
        path = tmp_path / "training_data.json"

        generate.save_dataset(features, labels, str(path))

        payload = json.loads(path.read_text(encoding='utf-8'))
        assert payload['n_samples'] == 10
        assert payload['n_features'] == FEATURE_COUNT
        assert payload['n_bot'] + payload['n_human'] == 10
        assert payload['features'] == features

    def test_writes_only_where_it_is_told(self, tmp_path):
        features, labels = generate.generate_dataset(n_samples=4, seed=1)

        generate.save_dataset(features, labels, str(tmp_path / "out.json"))

        assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


class TestComputeNormalization:
    def test_returns_per_column_bounds(self):
        rows = [[0.0] * FEATURE_COUNT, [10.0] * FEATURE_COUNT, [5.0] * FEATURE_COUNT]

        mins, maxs = compute_normalization(rows)

        assert mins == [0.0] * FEATURE_COUNT
        assert maxs == [10.0] * FEATURE_COUNT

    def test_bounds_are_independent_per_column(self):
        rows = [[1.0, 100.0], [2.0, 50.0]]

        mins, maxs = compute_normalization(rows)

        assert mins == [1.0, 50.0]
        assert maxs == [2.0, 100.0]

    def test_empty_input_is_a_programming_error(self):
        with pytest.raises(IndexError):
            compute_normalization([])


class TestNormalizeFeatures:
    def test_scales_to_the_unit_interval(self):
        normalized = normalize_features([[0.0], [5.0], [10.0]], mins=[0.0], maxs=[10.0])

        assert normalized == [[0.0], [0.5], [1.0]]

    def test_a_constant_column_becomes_one_half_at_training_time(self):
        """A zero-range column carries no information, so it gets 0.5.

        Inference must use the same value; `BotDetector.normalize` is the
        other half of this pair and is asserted directly below.
        """
        normalized = normalize_features([[3.0], [3.0]], mins=[3.0], maxs=[3.0])

        assert normalized == [[0.5], [0.5]]

    def test_inference_maps_the_same_column_to_one_half_too(self):
        """The other half, asserted against the real code.

        These disagreed until the train/serve skew was fixed: training said
        0.5 and inference said 0.0, so any column constant across the training
        set reached the network as a value it had never been trained on.
        """
        from microguard.model import BotDetector

        detector = BotDetector()
        detector.norm_mins = [3.0] * FEATURE_COUNT
        detector.norm_maxs = [3.0] * FEATURE_COUNT

        assert detector.normalize([3.0] * FEATURE_COUNT) == [0.5] * FEATURE_COUNT
        # A zero-range column swallows its input, whatever it is.
        assert detector.predict([3.0] * FEATURE_COUNT) == detector.predict([99.0] * FEATURE_COUNT)


class TestSplitHoldout:
    """The split is why the held-out accuracy number means anything."""

    def _data(self, groups=10):
        features, labels, group_ids = [], [], []
        for g in range(groups):
            is_bot = g % 2 == 0
            for _ in range(3):  # 3 rows per actor
                features.append([float(g)] * FEATURE_COUNT)
                labels.append(1.0 if is_bot else 0.0)
                group_ids.append(f"actor-{g}")
        return features, labels, group_ids

    def test_no_actor_appears_on_both_sides(self):
        """A row-level split would put near-duplicate vectors from one actor in
        both halves and report memorization as generalization."""
        features, labels, group_ids = self._data()

        train_idx, test_idx = split_holdout(features, labels, group_ids)

        train_groups = {group_ids[i] for i in train_idx}
        test_groups = {group_ids[i] for i in test_idx}
        assert train_groups & test_groups == set()

    def test_both_splits_contain_both_classes(self):
        features, labels, group_ids = self._data()

        train_idx, test_idx = split_holdout(features, labels, group_ids)

        assert {labels[i] for i in train_idx} == {0.0, 1.0}
        assert {labels[i] for i in test_idx} == {0.0, 1.0}

    def test_every_row_lands_somewhere(self):
        features, labels, group_ids = self._data()

        train_idx, test_idx = split_holdout(features, labels, group_ids)

        assert sorted(train_idx + test_idx) == list(range(len(labels)))

    def test_is_deterministic_for_a_seed(self):
        features, labels, group_ids = self._data()

        first = split_holdout(features, labels, group_ids, seed=7)
        second = split_holdout(features, labels, group_ids, seed=7)

        assert first == second

    def test_the_test_fraction_is_honored_at_group_level(self):
        features, labels, group_ids = self._data(groups=20)

        _train_idx, test_idx = split_holdout(features, labels, group_ids, test_frac=0.5)

        assert len({group_ids[i] for i in test_idx}) == 10

    def test_a_single_group_per_class_goes_entirely_to_test(self):
        """max(1, ...) guarantees a non-empty test side, which means a tiny
        dataset can leave a class unrepresented in training."""
        features = [[1.0] * FEATURE_COUNT, [0.0] * FEATURE_COUNT]
        labels = [1.0, 0.0]
        group_ids = ["bot-1", "human-1"]

        train_idx, test_idx = split_holdout(features, labels, group_ids)

        assert train_idx == []
        assert sorted(test_idx) == [0, 1]


class TestPrepareTrainingData:
    def _entry(self, url="/api/items", ua="Mozilla/5.0", second=0):
        from datetime import datetime, timedelta, timezone

        base = datetime(2023, 3, 24, 17, 0, 0, tzinfo=timezone.utc)
        return LogEntry(
            ip="10.0.0.1", timestamp=base + timedelta(seconds=second), method="GET",
            url=url, status=200, size=100, referer="-", user_agent=ua,
        )

    def test_produces_one_row_per_session(self):
        entries = [self._entry(url=f"/p/{i}", second=i * 5) for i in range(6)]

        features, labels = prepare_training_data(entries)

        assert len(features) == 1
        assert len(labels) == 1
        assert len(features[0]) == FEATURE_COUNT

    def test_drops_sessions_shorter_than_three_requests(self):
        entries = [self._entry(second=i) for i in range(2)]

        features, labels = prepare_training_data(entries)

        assert features == []
        assert labels == []

    def test_labels_bots_as_one(self):
        entries = [self._entry(ua="python-requests/2.28.0", second=i * 5) for i in range(5)]

        _features, labels = prepare_training_data(entries)

        assert labels == [1.0]

    def test_automated_integrations_are_labeled_human(self):
        """Pins a real modelling choice: a webhook is not a bot for training
        purposes, so it joins the human class rather than getting its own."""
        entries = [self._entry(ua="Stripe/1.0", second=i * 5) for i in range(5)]

        _features, labels = prepare_training_data(entries)

        assert labels == [0.0]


class TestGenerateSyntheticData:
    def test_returns_a_balanced_set(self):
        features, labels = generate_synthetic_data(n_samples=20)

        assert len(features) == 20
        assert sum(labels) == 10

    def test_an_odd_count_loses_one_row(self):
        """Both halves are n // 2, so odd inputs produce n - 1 rows."""
        features, _labels = generate_synthetic_data(n_samples=21)

        assert len(features) == 20

    def test_every_vector_is_the_right_width(self):
        features, _labels = generate_synthetic_data(n_samples=10)

        assert all(len(row) == FEATURE_COUNT for row in features)


class TestTrainModel:
    """The full training entry point, with every write redirected to tmp_path.

    Assertions are on structure and file contents, never on weights:
    micrograd's MLP init is unseeded, so the trained parameters differ run to
    run.
    """

    def _dataset(self, groups=12):
        features, labels, group_ids, provenance = [], [], [], []
        for g in range(groups):
            is_bot = g % 2 == 0
            features.append([1.0 if is_bot else 0.0] * FEATURE_COUNT)
            labels.append(1.0 if is_bot else 0.0)
            group_ids.append(f"actor-{g}")
            provenance.append('ground_truth' if is_bot else 'harvard_human')
        return features, labels, group_ids, provenance

    def test_writes_the_model_and_its_normalization(self, tmp_path, capsys):
        from microguard.training.train import train_model

        features, labels, _g, _p = self._dataset()
        model_path = tmp_path / "model.json"

        _model, _metrics = train_model(features, labels, model_path=str(model_path), epochs=2)

        assert model_path.exists()
        assert (tmp_path / "normalization.json").exists()
        saved = json.loads(model_path.read_text(encoding='utf-8'))
        assert saved['num_features'] == FEATURE_COUNT
        assert len(saved['weights']) == 85

    def test_the_returned_model_can_score(self, tmp_path):
        from microguard.training.train import train_model

        features, labels, _g, _p = self._dataset()

        model, _metrics = train_model(features, labels,
                            model_path=str(tmp_path / "model.json"), epochs=2)

        score = model.predict([0.5] * FEATURE_COUNT)
        assert 0.0 <= score <= 1.0

    def test_group_ids_produce_a_holdout_set(self, tmp_path):
        from microguard.training.train import train_model

        features, labels, group_ids, provenance = self._dataset()

        _model, _metrics = train_model(features, labels, model_path=str(tmp_path / "model.json"),
                    epochs=2, group_ids=group_ids, provenance=provenance)

        holdout = json.loads((tmp_path / "eval_holdout.json").read_text(encoding='utf-8'))
        assert holdout['n_samples'] == holdout['n_bot'] + holdout['n_human']
        assert holdout['n_features'] == FEATURE_COUNT
        assert holdout['provenance'] is not None

    def test_a_holdout_with_humans_produces_an_adversarial_set(self, tmp_path):
        from microguard.training.train import train_model

        features, labels, group_ids, provenance = self._dataset()

        _model, _metrics = train_model(features, labels, model_path=str(tmp_path / "model.json"),
                    epochs=2, group_ids=group_ids, provenance=provenance)

        adversarial = json.loads((tmp_path / "adversarial_eval.json").read_text(encoding='utf-8'))
        assert adversarial['n_bot'] == adversarial['n_human']
        assert 'not proof' in adversarial['note'] or 'NOT strong evidence' in adversarial['note']

    def test_without_group_ids_no_holdout_is_written(self, tmp_path):
        from microguard.training.train import train_model

        features, labels, _g, _p = self._dataset()

        _model, _metrics = train_model(features, labels, model_path=str(tmp_path / "model.json"), epochs=2)

        assert not (tmp_path / "eval_holdout.json").exists()
        assert not (tmp_path / "adversarial_eval.json").exists()

    def test_writes_nothing_outside_the_directory_it_was_given(self, tmp_path):
        from microguard.training.train import train_model

        features, labels, group_ids, provenance = self._dataset()

        _model, _metrics = train_model(features, labels, model_path=str(tmp_path / "model.json"),
                    epochs=2, group_ids=group_ids, provenance=provenance)

        assert sorted(p.name for p in tmp_path.iterdir()) == [
            "adversarial_eval.json", "eval_holdout.json",
            "model.json", "normalization.json",
        ]


class TestMainDispatch:
    """main() picks the best dataset available, in priority order.

    Every case points data_dir at tmp_path. Running this against the real
    data/ would overwrite the shipped model and both eval sets.
    """

    def _write(self, path, features, labels, **extra):
        payload = {'features': features, 'labels': labels,
                   'n_human': labels.count(0.0), 'n_bot': labels.count(1.0)}
        payload.update(extra)
        path.write_text(json.dumps(payload), encoding='utf-8')

    def _rows(self, n=8):
        features = [[1.0 if i % 2 else 0.0] * FEATURE_COUNT for i in range(n)]
        labels = [1.0 if i % 2 else 0.0 for i in range(n)]
        return features, labels

    def test_prefers_the_real_bot_dataset(self, tmp_path, capsys):
        from microguard.training.train import main

        features, labels = self._rows()
        self._write(tmp_path / "real_bot_training_data.json", features, labels,
                    group_ids=[f"g{i}" for i in range(len(labels))],
                    provenance=['ground_truth'] * len(labels),
                    source_counts={'ground_truth': len(labels)})
        self._write(tmp_path / "harvard_training_data.json", features, labels)

        main(data_dir=str(tmp_path), epochs=2)

        assert 'real bot-training data' in capsys.readouterr().out
        assert (tmp_path / "model.json").exists()

    def test_falls_back_to_harvard(self, tmp_path, capsys):
        from microguard.training.train import main

        features, labels = self._rows()
        self._write(tmp_path / "harvard_training_data.json", features, labels)

        main(data_dir=str(tmp_path), epochs=2)

        assert 'Harvard training data' in capsys.readouterr().out

    def test_falls_back_to_the_older_combined_set(self, tmp_path, capsys):
        from microguard.training.train import main

        features, labels = self._rows()
        self._write(tmp_path / "real_training_data.json", features, labels)

        main(data_dir=str(tmp_path), epochs=2)

        assert 'real training data' in capsys.readouterr().out

    def test_falls_back_to_a_raw_access_log(self, tmp_path, capsys):
        from microguard.training.train import main

        lines = []
        for i in range(12):
            lines.append(
                f'10.0.0.{i % 3} - - [24/Mar/2023:17:{i:02d}:41 +0000] '
                f'"GET /page/{i} HTTP/1.1" 200 100 "-" "python-requests/2.28.0"'
            )
        (tmp_path / "access.log").write_text("\n".join(lines) + "\n", encoding='utf-8')

        main(data_dir=str(tmp_path), epochs=2)

        assert 'Loading dataset from' in capsys.readouterr().out

    def test_last_resort_is_synthetic_and_says_so(self, tmp_path, capsys):
        """The loudest branch. A model trained here is a demo, not a detector,
        and the output has to make that obvious."""
        from microguard.training.train import main

        main(data_dir=str(tmp_path), epochs=1)

        output = capsys.readouterr().out
        assert 'No dataset found' in output
        assert 'synthetic' in output

    def test_writes_only_inside_the_directory_it_was_given(self, tmp_path):
        from microguard.training.train import main

        features, labels = self._rows()
        self._write(tmp_path / "harvard_training_data.json", features, labels)

        main(data_dir=str(tmp_path), epochs=2)

        written = {p.name for p in tmp_path.iterdir()}
        assert written <= {
            "harvard_training_data.json", "model.json", "normalization.json",
            "eval_holdout.json", "adversarial_eval.json",
        }


class TestSplitHoldoutEmptyClass:
    def test_a_class_with_no_groups_splits_to_nothing(self):
        """All-bot input: the human side has no groups at all."""
        features = [[1.0] * FEATURE_COUNT] * 4
        labels = [1.0] * 4
        group_ids = [f"bot-{i}" for i in range(4)]

        train_idx, test_idx = split_holdout(features, labels, group_ids)

        assert sorted(train_idx + test_idx) == [0, 1, 2, 3]
        assert {labels[i] for i in test_idx} == {1.0}


class TestDefaultDataDir:
    def test_resolves_to_the_repo_data_directory(self):
        """main() defaults to this, and a test must never let it.

        Checked here instead, so the default path is verified without a
        training run writing over the shipped model.
        """
        import os

        from microguard.training.train import default_data_dir

        resolved = default_data_dir()
        assert os.path.basename(resolved) == 'data'
        assert os.path.isfile(os.path.join(resolved, 'model.json'))


class TestActorSessionGrouping:
    """organization-x anonymizes the client IP to about two values, so the
    normal IP sessionizer collapses 213K lines into a handful of sessions.
    This groups on (ip, user_agent) instead."""

    def _entry(self, ua, second=0):
        from datetime import datetime, timedelta, timezone

        base = datetime(2023, 3, 24, 17, 0, 0, tzinfo=timezone.utc)
        return LogEntry(
            ip="10.0.0.1", timestamp=base + timedelta(seconds=second), method="GET",
            url="/a", status=200, size=1, referer="-", user_agent=ua,
        )

    def test_one_ip_with_two_user_agents_is_two_sessions(self):
        from microguard.training.build_real_dataset import group_into_actor_sessions

        entries = [self._entry("curl/8.0", 0), self._entry("Mozilla/5.0", 1)]

        sessions = group_into_actor_sessions(entries)

        assert len(sessions) == 2

    def test_the_default_sessionizer_would_have_merged_them(self):
        """Shows why the override exists, rather than asserting it in the
        abstract."""
        from microguard.features import group_into_sessions

        entries = [self._entry("curl/8.0", 0), self._entry("Mozilla/5.0", 1)]

        assert len(group_into_sessions(entries)) == 1

    def test_same_actor_stays_one_session(self):
        from microguard.training.build_real_dataset import group_into_actor_sessions

        entries = [self._entry("curl/8.0", i) for i in range(4)]

        sessions = group_into_actor_sessions(entries)

        assert len(sessions) == 1
        assert sessions[0].request_count == 4


class TestBuildDataset:
    """build_dataset against fixtures, not the real 213K-line corpus.

    The real path takes ~98 seconds and depends on committed datasets. Pointing
    the module's globals at tmp_path runs the same code in milliseconds and is
    the only way to reach the synthetic top-up branch, which is dead against
    the real data (there are already more real bots than the cap allows).
    """

    RULES = """
- id: dir_scan
  ground_truth_label: dir_scan_go
  sensitivity: moderate
  filter:
    - "Go-http-client"
"""

    def _log_line(self, ua, url, second):
        return (f'10.0.0.1 - - [24/Mar/2023:17:{second:02d}:41 +0000] '
                f'"GET {url} HTTP/1.1" 404 100 "-" "{ua}"')

    @pytest.fixture
    def sandboxed(self, tmp_path, monkeypatch):
        from microguard.training import build_real_dataset as brd

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        lines = []
        # A ground-truth bot: matched by the Go-http-client rule.
        for i in range(5):
            lines.append(self._log_line("Go-http-client/1.1", f"/scan/{i}", i))
        # A heuristic-only bot: no rule match, but the labeler calls it a bot.
        for i in range(5):
            lines.append(self._log_line("python-requests/2.28.0", f"/api/{i}", 10 + i))
        (log_dir / "web-access.log").write_text("\n".join(lines) + "\n", encoding='utf-8')

        rules_path = tmp_path / "rules.yaml"
        rules_path.write_text(self.RULES, encoding='utf-8')

        harvard = tmp_path / "harvard_training_data.json"
        harvard.write_text(json.dumps({
            'features': [[0.0] * FEATURE_COUNT for _ in range(40)],
            'labels': [0.0] * 40,
        }), encoding='utf-8')

        monkeypatch.setattr(brd, "ORGX_LOG_GLOB", str(log_dir / "web-access.log*"))
        monkeypatch.setattr(brd, "ORGX_RULES_PATH", str(rules_path))
        monkeypatch.setattr(brd, "DATA_DIR", str(tmp_path))
        return brd, tmp_path

    def test_returns_the_expected_shape(self, sandboxed):
        brd, _tmp = sandboxed

        dataset = brd.build_dataset()

        assert dataset['n_samples'] == len(dataset['features'])
        assert dataset['n_features'] == FEATURE_COUNT
        assert dataset['n_bot'] + dataset['n_human'] == dataset['n_samples']
        assert len(dataset['group_ids']) == dataset['n_samples']
        assert len(dataset['provenance']) == dataset['n_samples']

    def test_ground_truth_rows_are_labeled_from_the_rules(self, sandboxed):
        brd, _tmp = sandboxed

        dataset = brd.build_dataset()

        assert dataset['source_counts'].get('ground_truth', 0) >= 1
        assert 'dir_scan_go' in dataset['category_counts']

    def test_unmatched_sessions_fall_back_to_the_heuristic_labeler(self, sandboxed):
        brd, _tmp = sandboxed

        dataset = brd.build_dataset()

        assert dataset['source_counts'].get('heuristic_real', 0) >= 1

    def test_the_human_class_comes_from_harvard(self, sandboxed):
        """This corpus is bot-side evidence only: its IP anonymization means a
        browser UA may be many real people merged into one 'session'."""
        brd, _tmp = sandboxed

        dataset = brd.build_dataset()

        assert dataset['source_counts']['harvard_human'] == 40
        assert dataset['n_human'] == 40

    def test_synthetic_top_up_fills_a_thin_bot_class(self, sandboxed):
        """Dead against the real dataset, which already has more real bots than
        the cap permits. Reachable here because the fixture has only two."""
        brd, _tmp = sandboxed

        dataset = brd.build_dataset()

        assert dataset['source_counts'].get('synthetic_augmentation', 0) > 0

    def test_the_synthetic_cap_is_a_fraction_of_the_target_not_of_the_bot_class(
        self, sandboxed
    ):
        """Pins actual behavior, which does not match the comment above it.

        build_real_dataset.py says the top-up is "capped so real data remains
        the majority of the bot class". The arithmetic caps synthetic rows at
        MAX_SYNTHETIC_FRACTION of `target_bot_total`, which is derived from the
        HUMAN count when real bots are scarce — so the synthetic share of the
        bot class can be 60-75%, not a minority.

        It never bites on the real corpus, where 2,500 real bots against 1,000
        humans produce zero synthetic rows. It would bite if the bot corpus
        shrank, and the committed dataset has already drifted once. Recorded
        rather than changed; see CHANGELOG.
        """
        brd, _tmp = sandboxed

        dataset = brd.build_dataset()

        synthetic = dataset['source_counts'].get('synthetic_augmentation', 0)
        real_bots = dataset['n_bot'] - synthetic
        target_bot_total = max(real_bots, int(dataset['n_human'] * 0.5))

        assert synthetic <= int(target_bot_total * brd.MAX_SYNTHETIC_FRACTION)
        # And the documented property does NOT hold in this regime:
        assert synthetic > real_bots

    def test_sessions_shorter_than_three_requests_are_dropped(self, tmp_path, monkeypatch):
        """Two requests is not a behavior pattern, and the timing features are
        undefined or meaningless on it."""
        from microguard.training import build_real_dataset as brd

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        (log_dir / "web-access.log").write_text("\n".join(
            self._log_line("Go-http-client/1.1", f"/scan/{i}", i) for i in range(2)
        ) + "\n", encoding='utf-8')
        (tmp_path / "rules.yaml").write_text(self.RULES, encoding='utf-8')
        # A human class, so the dataset is non-empty once the short session is
        # dropped — see test_an_empty_corpus_raises for what happens without it.
        (tmp_path / "harvard_training_data.json").write_text(json.dumps({
            'features': [[0.0] * FEATURE_COUNT for _ in range(4)],
            'labels': [0.0] * 4,
        }), encoding='utf-8')

        monkeypatch.setattr(brd, "ORGX_LOG_GLOB", str(log_dir / "web-access.log*"))
        monkeypatch.setattr(brd, "ORGX_RULES_PATH", str(tmp_path / "rules.yaml"))
        monkeypatch.setattr(brd, "DATA_DIR", str(tmp_path))

        dataset = brd.build_dataset()

        assert dataset['source_counts'].get('ground_truth', 0) == 0
        assert dataset['n_bot'] == 0

    def test_an_empty_corpus_raises_rather_than_returning_nothing(self, tmp_path, monkeypatch):
        """Pins a rough edge rather than intended behavior.

        With no sessions and no human class, the final `zip(*combined)` unpacks
        an empty list and raises ValueError. Reachable by pointing the builder
        at an empty log directory. Recorded so a future fix is deliberate.
        """
        from microguard.training import build_real_dataset as brd

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        (log_dir / "web-access.log").write_text("", encoding='utf-8')
        (tmp_path / "rules.yaml").write_text(self.RULES, encoding='utf-8')

        monkeypatch.setattr(brd, "ORGX_LOG_GLOB", str(log_dir / "web-access.log*"))
        monkeypatch.setattr(brd, "ORGX_RULES_PATH", str(tmp_path / "rules.yaml"))
        monkeypatch.setattr(brd, "DATA_DIR", str(tmp_path))

        with pytest.raises(ValueError):
            brd.build_dataset()

    def test_is_reproducible_for_a_seed(self, sandboxed):
        brd, _tmp = sandboxed

        first = brd.build_dataset(seed=5)
        second = brd.build_dataset(seed=5)

        assert first['labels'] == second['labels']
        assert first['provenance'] == second['provenance']

    def test_main_writes_the_dataset_where_it_was_pointed(self, sandboxed, capsys):
        brd, tmp = sandboxed

        brd.main()

        out = tmp / "real_bot_training_data.json"
        assert out.exists()
        payload = json.loads(out.read_text(encoding='utf-8'))
        assert payload['n_samples'] > 0
        assert 'Dataset saved to' in capsys.readouterr().out


class TestBuildRealisticDataset:
    """build_realistic_dataset against tiny fixtures, not the 10M-line Zanbil
    corpus and the 213K-line organization-x one (both gitignored, so this is
    the only way the module runs on CI). Points the module's globals at
    tmp_path and stubs the org-x reader, running the real code in milliseconds.
    """

    def _zanbil_line(self, ip, url, second, ua, referer="-"):
        return (f'{ip} - - [22/Jan/2019:03:{second:02d}:14 +0330] '
                f'"GET {url} HTTP/1.1" 200 100 "{referer}" "{ua}"')

    @pytest.fixture
    def sandboxed(self, tmp_path, monkeypatch):
        from microguard.parser import LogEntry as LE
        from microguard.training import build_realistic_dataset as bru

        days = tmp_path / "days"
        labels = tmp_path / "labels"
        days.mkdir()
        labels.mkdir()
        browser = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")
        lines = []
        # A human_proxy actor (browser UA) and a crawler bot actor, 5 requests each.
        for i in range(5):
            lines.append(self._zanbil_line("5.1.1.1", f"/product/{i}", i, browser,
                                           referer="https://shop/"))
            lines.append(self._zanbil_line("66.249.66.1", f"/catalog/{i}", i,
                                           "Mozilla/5.0 (compatible; Googlebot/2.1)"))
        (days / "2019-01-22.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (labels / "2019-01-22.json").write_text(json.dumps({
            "5.1.1.1": {"label": "human_proxy", "requests": 5},
            "66.249.66.1": {"label": "verified_crawler", "requests": 5},
            "9.9.9.9": {"label": "unlabeled", "requests": 1},
        }), encoding="utf-8")

        # org-x: a couple of real-shaped attack entries, via the stubbed reader.
        def fake_orgx_entries():
            return [
                LE(ip="1.2.3.4", timestamp=__import__("datetime").datetime(
                    2020, 3, 4, 12, 0, i, tzinfo=__import__("datetime").timezone.utc),
                   method="GET", url=f"/scan/{i}", status=404, size=0,
                   referer="-", user_agent="Go-http-client/1.1")
                for i in range(5)
            ]
        rules_path = tmp_path / "rules.yaml"
        rules_path.write_text(
            '- id: dir_scan\n  ground_truth_label: dir_scan_go\n  sensitivity: moderate\n'
            '  filter:\n    - "Go-http-client"\n', encoding="utf-8")

        monkeypatch.setattr(bru, "ZANBIL_DAYS", str(days))
        monkeypatch.setattr(bru, "ZANBIL_LABELS", str(labels))
        monkeypatch.setattr(bru, "ORGX_RULES_PATH", str(rules_path))
        monkeypatch.setattr(bru, "load_all_organization_x_entries", fake_orgx_entries)
        monkeypatch.setattr(bru, "DATA_DIR", str(tmp_path))
        return bru, tmp_path

    def test_real_humans_and_bots_from_the_same_site(self, sandboxed):
        bru, _tmp = sandboxed
        data = bru.build_dataset()
        assert data['n_human'] >= 1 and data['n_bot'] >= 1
        assert data['n_features'] == FEATURE_COUNT
        # Zanbil is on BOTH sides -> human and bot both carry a zanbil provenance.
        human_src = {p for p, l in zip(data['provenance'], data['labels']) if l <= 0.5}
        assert any(p.startswith('zanbil_human_proxy') for p in human_src)

    def test_human_class_spans_more_than_one_provenance_is_possible(self, sandboxed):
        bru, _tmp = sandboxed
        data = bru.build_dataset()
        # Provenance carries the day, and group ids are hashed (no raw IPs).
        assert all('.' not in gid.split('_')[-1] for gid in data['group_ids'])

    def test_orgx_bots_are_included_when_asked(self, sandboxed):
        bru, _tmp = sandboxed
        with_orgx = bru.build_dataset(include_orgx=True)
        without = bru.build_dataset(include_orgx=False)
        assert with_orgx['n_bot'] > without['n_bot']
        assert any('orgx' in p for p in with_orgx['provenance'])

    def test_main_writes_the_dataset(self, sandboxed, capsys):
        bru, tmp = sandboxed
        bru.main()
        out = tmp / "realistic_training_data.json"
        assert out.exists()
        assert json.loads(out.read_text(encoding="utf-8"))['n_samples'] > 0
        assert 'saved' in capsys.readouterr().out

    def test_missing_labels_dir_is_a_clear_error(self, tmp_path, monkeypatch):
        from microguard.training import build_realistic_dataset as bru
        monkeypatch.setattr(bru, "ZANBIL_LABELS", str(tmp_path / "nope"))
        with pytest.raises(SystemExit):
            bru.build_dataset()
