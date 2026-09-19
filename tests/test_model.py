"""Tests for the micrograd model wrapper."""

import json
import logging
import random
from pathlib import Path

import pytest

from microguard.model import DEFAULT_MODEL_PATH, BotDetector

DATA_MODEL = Path(DEFAULT_MODEL_PATH)


class TestBotDetector:
    """Tests for the BotDetector model."""
    
    def test_init(self):
        model = BotDetector()
        assert model.NUM_FEATURES == 19
        assert repr(model).startswith("BotDetector")
    
    def test_predict_random(self):
        """Random model should give roughly 50% for any input."""
        model = BotDetector()
        
        # Random features
        features = [0.5] * 19
        score = model.predict(features)
        
        # Should be between 0 and 1
        assert 0.0 <= score <= 1.0
    
    def test_predict_batch(self):
        model = BotDetector()
        batch = [[0.5] * 19 for _ in range(10)]
        scores = model.predict_batch(batch)
        assert len(scores) == 10
        assert all(0.0 <= s <= 1.0 for s in scores)
    
    def test_predict_wrong_features(self):
        model = BotDetector()
        with pytest.raises(ValueError, match="Expected 19 features"):
            model.predict([0.5] * 10)
    
    def test_save_load(self, tmp_path):
        """Test saving and loading model weights."""
        model = BotDetector()
        filepath = str(tmp_path / "test_model.json")
        
        # Save
        model.save(filepath)
        
        # Load into new model
        model2 = BotDetector(filepath)
        
        # Predictions should be identical
        features = [0.5] * 19
        assert model.predict(features) == model2.predict(features)
    
    def test_train_step(self):
        """A training step moves the model.

        Seeded, and not for tidiness. micrograd initializes weights with
        random.uniform, and on roughly 2% of inits every hidden ReLU sits at
        zero for both input patterns below. The only live gradient left is the
        output bias, and this batch is symmetric — ten targets at +1, ten at
        -1 — so that gradient cancels exactly and nothing moves. Unseeded, the
        assertion fails about 2% of the time through no fault of the code,
        which across a 12-job CI matrix is close to a coin flip per run.
        """
        random.seed(1234)
        model = BotDetector()
        
        # Simple training data
        features = [[1.0] * 19] * 10 + [[0.0] * 19] * 10
        labels = [1.0] * 10 + [0.0] * 10
        
        # Get initial predictions
        initial_scores = model.predict_batch(features)
        
        # Train
        model.train_step(features, labels, learning_rate=0.1)
        
        # Predictions should have changed
        new_scores = model.predict_batch(features)
        assert initial_scores != new_scores
    
    def test_sigmoid(self):
        """Test sigmoid function."""
        assert BotDetector.sigmoid(0) == 0.5
        assert BotDetector.sigmoid(100) > 0.99
        assert BotDetector.sigmoid(-100) < 0.01
        assert 0.0 < BotDetector.sigmoid(1) < 1.0


class TestTrain:
    """`BotDetector.train` had no test at all.

    Its only production caller is training/train.py, which was itself at 0%.
    Everything here uses tiny inputs and a seed: the epoch loop is pure Python
    over 85 parameters, and the shuffle inside train() is unseeded.
    """

    def _dataset(self, n=10):
        # Separable by construction, so a couple of epochs move in the right
        # direction. n >= 5 so val_split=0.2 yields a non-empty validation set.
        features = [[1.0] * 19] * (n // 2) + [[0.0] * 19] * (n // 2)
        labels = [1.0] * (n // 2) + [0.0] * (n // 2)
        return features, labels

    def test_returns_one_loss_per_epoch(self):
        random.seed(7)
        model = BotDetector()
        features, labels = self._dataset()

        losses = model.train(features, labels, epochs=3, batch_size=4, verbose=False)

        assert len(losses) == 3
        assert all(isinstance(loss, float) for loss in losses)

    def test_check_not_degenerate_is_a_no_op_without_labels(self):
        # No labels means nothing to be degenerate about — returns early rather
        # than deciding a model is constant on an empty set.
        BotDetector().check_not_degenerate([], [])

    def test_training_changes_the_parameters(self):
        random.seed(7)
        model = BotDetector()
        features, labels = self._dataset()
        before = [p.data for p in model.model.parameters()]

        model.train(features, labels, epochs=2, batch_size=4, verbose=False)

        assert [p.data for p in model.model.parameters()] != before

    def test_verbose_reports_progress(self, capsys):
        random.seed(7)
        model = BotDetector()
        features, labels = self._dataset()

        model.train(features, labels, epochs=1, batch_size=4, verbose=True)

        output = capsys.readouterr().out
        assert 'Epoch' in output
        assert 'Val Acc' in output

    def test_quiet_by_request(self, capsys):
        random.seed(7)
        model = BotDetector()
        features, labels = self._dataset()

        model.train(features, labels, epochs=1, batch_size=4, verbose=False)

        assert capsys.readouterr().out == ''

    def test_an_all_validation_split_yields_no_batches(self):
        """val_split=1.0 leaves nothing to train on.

        It does not raise — the batch count guard substitutes a zero loss —
        which is worth pinning so the guard is not removed as dead.
        """
        random.seed(7)
        model = BotDetector()
        features, labels = self._dataset()

        losses = model.train(features, labels, epochs=1, val_split=1.0, verbose=False)

        assert losses == [0.0]

    def test_writes_no_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        random.seed(7)
        model = BotDetector()
        features, labels = self._dataset()

        model.train(features, labels, epochs=1, batch_size=4, verbose=False)

        assert list(tmp_path.iterdir()) == []


class TestLoadErrors:
    def test_a_weight_count_mismatch_is_rejected(self, tmp_path):
        """Loading a model of a different shape must fail loudly.

        Silently accepting it would produce scores from a network whose
        weights mean something else.
        """
        path = tmp_path / "model.json"
        path.write_text(json.dumps({
            "num_features": 19, "architecture": [4, 1], "weights": [0.1, 0.2],
        }), encoding='utf-8')
        model = BotDetector()

        with pytest.raises(ValueError, match="weight tensors"):
            model.load(str(path))

    def test_the_constructor_surfaces_the_same_error(self, tmp_path):
        path = tmp_path / "model.json"
        path.write_text(json.dumps({
            "num_features": 19, "architecture": [4, 1], "weights": [0.1],
        }), encoding='utf-8')

        with pytest.raises(ValueError, match="weight tensors"):
            BotDetector(str(path))

    def test_a_model_without_normalization_beside_it_warns(self, tmp_path, caplog):
        """predict() silently skips scaling when the params are absent, which
        once dropped held-out recall from 100% to 2.4% without failing."""
        source = json.loads((DATA_MODEL).read_text(encoding='utf-8'))
        path = tmp_path / "model.json"
        path.write_text(json.dumps(source), encoding='utf-8')

        with caplog.at_level(logging.WARNING):
            model = BotDetector()
            model.load(str(path))

        assert 'normalization' in caplog.text
        assert model.norm_mins is None
