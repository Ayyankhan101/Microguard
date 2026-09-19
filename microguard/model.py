"""Micrograd model wrapper for bot detection.

MLP architecture: 19 → 16 → 8 → 1
Input: 19 features
Output: 0.0 (human) to 1.0 (bot)
"""

from __future__ import annotations

import json
import logging
import math
import os
from importlib import resources

# Import micrograd
try:
    from micrograd.engine import Value
    from micrograd.nn import MLP
except ImportError:  # pragma: no cover - install-time guard, needs micrograd absent
    raise ImportError(
        "micrograd is required. Install with: pip install micrograd\n"
        "Or from source: pip install git+https://github.com/karpathy/micrograd.git"
    )


# The trained model artifact. Defined here, next to BotDetector, because both
# the batch CLI and the live scorer need it — a second copy in either one is how
# the live path ended up looking for a file that never existed.
#
# It lives INSIDE the package. It used to resolve to `<package>/../data/`, which
# escapes the package root, and Python packaging only carries files that live
# inside a package: `setup.py`'s package_data named `dashboard/static` and
# nothing else, there is no MANIFEST.in, and the built SOURCES.txt had no
# `data/` entry. So every `pip install microguard` shipped without a model,
# resolved this path to nothing, and `live/scorer.py` logged "live scoring will
# run on heuristics only" and carried on. The whole retraining effort reached
# editable checkouts and nobody else.
#
# `online_update.py:default_feedback_dir` already documented the arrangement
# this restores -- "data/ ships in the wheel and is read-only on a normal
# install" -- which was the intended design all along, just never true.
DEFAULT_MODEL_PATH = str(resources.files('microguard') / 'data' / 'model.json')

# Where `microguard.training.train` writes a retrained baseline. Same directory,
# because a retrained baseline IS the shipped artifact; the training DATASETS
# stay in the repo's data/ and are not shipped.
SHIPPED_MODEL_DIR = str(resources.files('microguard') / 'data')


logger = logging.getLogger(__name__)


class DegenerateModelError(RuntimeError):
    """Training produced a constant classifier rather than a model."""



class BotDetector:
    """Bot detection model using micrograd MLP.
    
    Architecture:
        Input: 19 features
        Hidden: 4 neurons (ReLU)
        Output: 1 neuron (logit → sigmoid)
    
    Parameters: 85 total (19×4 + 4) + (4×1 + 1) = 76 + 5
    """
    
    NUM_FEATURES = 19
    
    def __init__(self, model_path: str | None = None):
        """Initialize the bot detector.
        
        Args:
            model_path: Path to pre-trained model weights (JSON).
                       If None, uses random initialization.
        """
        # MLP: 19 inputs → 4 hidden → 1 output (lightweight for speed)
        self.model = MLP(self.NUM_FEATURES, [4, 1])
        
        # Normalization parameters, populated by load() alongside the weights.
        self.norm_mins: list[float] | None = None
        self.norm_maxs: list[float] | None = None
        
        if model_path and os.path.exists(model_path):
            self.load(model_path)
    
    def predict(self, features: list[float]) -> float:
        """Predict bot probability for a single feature vector.
        
        Args:
            features: List of 19 floats (feature values)
        
        Returns:
            Float between 0.0 (human) and 1.0 (bot)
        """
        if len(features) != self.NUM_FEATURES:
            raise ValueError(
                f"Expected {self.NUM_FEATURES} features, got {len(features)}"
            )
        
        features = self.normalize(features)
        
        # Convert to micrograd Values
        x = [Value(f) for f in features]
        
        # Forward pass
        output = self.model(x)
        
        # Handle both list and single Value returns. The final layer has one
        # neuron, so micrograd returns a bare Value and this never fires with
        # the shipped architecture; kept in case the shape changes.
        if isinstance(output, list):  # pragma: no cover
            output = output[0]
        
        # Model outputs raw logit: positive = bot, negative = human
        # Convert to probability using sigmoid
        logit = max(-500, min(500, output.data))
        score = 1.0 / (1.0 + math.exp(-logit))
        
        return max(0.0, min(1.0, score))
    
    def normalize(self, features: list[float]) -> list[float]:
        """Min-max the way training does, or pass the values through untouched.

        The zero-range branch returns 0.5, matching
        `training.train.normalize_features`. It used to return 0.0 here and
        0.5 there, so any column that was constant across the training set
        reached the network as a value it had never been trained on. One
        column is constant in the shipped dataset (method_mismatch_count);
        the divergence scales with however many there are.
        """
        if self.norm_mins is None or self.norm_maxs is None:
            return list(features)

        normalized = []
        for i, value in enumerate(features):
            min_val = self.norm_mins[i]
            max_val = self.norm_maxs[i]
            if max_val > min_val:
                normalized.append((value - min_val) / (max_val - min_val))
            else:
                normalized.append(0.5)
        return normalized

    def has_live_hidden_units(self, features: list[list[float]]) -> bool:
        """Can any hidden unit fire on any of these inputs?

        A ReLU that never fires has zero gradient, so a network whose whole
        hidden layer is silent on the training set is frozen: the weights
        come back unchanged however long it runs. Worth asking before
        fine-tuning, because fine-tuning reloads the same starting weights
        on every retry and would otherwise fail identically five times.
        """
        for neuron in self.model.layers[0].neurons:
            for row in features:
                total = sum(w.data * x for w, x in zip(neuron.w, row)) + neuron.b.data
                if total > 0:
                    return True
        return False

    def train_until_it_learns(
        self,
        features: list[list[float]],
        labels: list[float],
        reset,
        attempts: int = 5,
        **train_kwargs,
    ) -> int:
        """Train, and start over if the result is a constant classifier.

        Roughly a quarter of random initializations of this network collapse
        on a 50-row correction set: with non-negative inputs and zero biases,
        a hidden unit whose weights sum negative can never fire, and a ReLU
        that never fires has no gradient, so the weights come back bit-for-bit
        unchanged. More epochs do not help -- nothing is learning. Redrawing
        does: 15/24 seeds succeed on the first try, 23/24 within five.

        `reset` restores the starting point for the next attempt. Fresh
        training redraws the network; fine-tuning reloads the baseline it is
        supposed to be adapting.

        Returns the attempt number that succeeded. Raises
        DegenerateModelError if every attempt collapsed.
        """
        last: DegenerateModelError | None = None
        for attempt in range(1, attempts + 1):
            self.train(features, labels, **train_kwargs)
            try:
                self.check_not_degenerate(features, labels)
            except DegenerateModelError as exc:
                last = exc
                if attempt < attempts:
                    logger.warning(
                        "training attempt %d/%d collapsed to a constant "
                        "classifier; starting over", attempt, attempts,
                    )
                    reset()
                continue
            return attempt
        assert last is not None
        raise DegenerateModelError(
            f"{attempts} training attempts all collapsed to a constant "
            f"classifier. Last: {last}"
        )

    def check_not_degenerate(
        self, features: list[list[float]], labels: list[float]
    ) -> None:
        """Raise unless the model separates the classes it was shown at all.

        The bar is deliberately the lowest one that means anything: given
        labels of both kinds, the predictions must also be of both kinds.
        A model that answers every input identically has learned a constant,
        and saving it produces in-range, meaningless scores with nothing
        anywhere reporting a failure.
        """
        if not labels:
            return
        wanted_bot = any(label > 0.5 for label in labels)
        wanted_human = any(label <= 0.5 for label in labels)
        if not (wanted_bot and wanted_human):
            return

        predictions = self.predict_batch(features)
        said_bot = sum(1 for p in predictions if p > 0.5)
        if said_bot == 0 or said_bot == len(predictions):
            verdict = "bot" if said_bot else "human"
            raise DegenerateModelError(
                f"training collapsed: the model labels all {len(predictions)} "
                f"training sessions {verdict!r} while the labels contain both "
                f"classes. Refusing to publish a constant classifier."
            )

    def predict_batch(self, batch: list[list[float]]) -> list[float]:
        """Predict bot probability for a batch of feature vectors.
        
        Args:
            batch: List of feature vectors (each 19 floats)
        
        Returns:
            List of probabilities
        """
        return [self.predict(features) for features in batch]
    
    def train_step(
        self,
        features_batch: list[list[float]],
        labels: list[float],
        learning_rate: float = 0.01
    ) -> float:
        """Perform one training step.
        
        Uses MSE loss compatible with micrograd's operations (+, *, **).
        Target: 1.0 for bot, -1.0 for human.
        
        Args:
            features_batch: Batch of feature vectors
            labels: Batch of labels (0.0 for human, 1.0 for bot)
            learning_rate: Learning rate for SGD
        
        Returns:
            Loss value
        """
        total_loss = Value(0.0)
        
        for features, label in zip(features_batch, labels):
            # Convert to micrograd Values
            x = [Value(f) for f in features]
            
            # Forward pass
            output = self.model(x)
            
            # Same unreachable unwrap as in predict() - see the note there.
            if isinstance(output, list):  # pragma: no cover
                output = output[0]
            
            # MSE loss: target is 1.0 for bot, -1.0 for human
            target = Value(1.0 if label > 0.5 else -1.0)
            loss = (output - target) ** 2
            
            total_loss = total_loss + loss
        
        # Average loss
        avg_loss = total_loss / Value(len(features_batch))
        
        # Backward pass
        self.model.zero_grad()
        avg_loss.backward()
        
        # Update weights
        for param in self.model.parameters():
            param.data -= learning_rate * param.grad
        
        return avg_loss.data
    
    def train(
        self,
        features: list[list[float]],
        labels: list[float],
        epochs: int = 100,
        batch_size: int = 32,
        learning_rate: float = 0.01,
        val_split: float = 0.2,
        verbose: bool = True
    ) -> list[float]:
        """Train the model.
        
        Args:
            features: List of feature vectors
            labels: List of labels (0.0 or 1.0)
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            val_split: Fraction of data for validation
            verbose: Print progress
        
        Returns:
            List of training losses per epoch
        """
        # Split into train/val
        n = len(features)
        n_val = int(n * val_split)
        n_train = n - n_val
        
        # Shuffle
        indices = list(range(n))
        import random
        random.shuffle(indices)
        
        train_idx = indices[:n_train]
        val_idx = indices[n_train:]
        
        train_features = [features[i] for i in train_idx]
        train_labels = [labels[i] for i in train_idx]
        val_features = [features[i] for i in val_idx]
        val_labels = [labels[i] for i in val_idx]
        
        losses = []
        
        for epoch in range(epochs):
            # Mini-batch training
            epoch_loss = 0.0
            n_batches = 0
            
            for i in range(0, n_train, batch_size):
                batch_features = train_features[i:i+batch_size]
                batch_labels = train_labels[i:i+batch_size]
                
                loss = self.train_step(
                    batch_features, batch_labels, learning_rate
                )
                epoch_loss += loss
                n_batches += 1
            
            avg_loss = epoch_loss / n_batches if n_batches > 0 else 0.0
            losses.append(avg_loss)
            
            if verbose and (epoch % 10 == 0 or epoch == epochs - 1):
                # Calculate validation accuracy
                val_preds = self.predict_batch(val_features)
                val_correct = sum(
                    1 for pred, label in zip(val_preds, val_labels)
                    if (pred > 0.5) == (label > 0.5)
                )
                val_acc = val_correct / len(val_labels) if val_labels else 0.0
                
                print(
                    f"Epoch {epoch:3d}/{epochs} | "
                    f"Loss: {avg_loss:.4f} | "
                    f"Val Acc: {val_acc:.1%}"
                )
        
        return losses
    
    def save(self, filepath: str):
        """Save model weights to JSON file.

        encoding='utf-8' explicit here and on every other open() in the
        package: without it Python falls back to the OS locale encoding
        (cp1252 on Windows), so the same file round-trips differently per
        platform. See parser.py::_open_text for where this first bit.
        """
        weights = []
        for param in self.model.parameters():
            weights.append(param.data)
        
        data = {
            'num_features': self.NUM_FEATURES,
            'architecture': [4, 1],
            'weights': weights,
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def load(self, filepath: str):
        """Load model weights AND the normalization params beside them.

        Both, always. These were split once — the constructor loaded
        normalization, bare load() loaded only weights — and the live scorer
        happened to use load(), so it fed raw features into a model trained on
        [0, 1] normalized ones. Held-out bot recall was 2.4% instead of 100%,
        and nothing failed: predict() simply skips normalization when the
        params are absent. A half-loaded model must not be a reachable state.
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        weights = data['weights']
        params = self.model.parameters()
        
        if len(weights) != len(params):
            raise ValueError(
                f"Model file has {len(weights)} weight tensors, "
                f"but model expects {len(params)}"
            )
        
        for param, weight in zip(params, weights):
            param.data = weight

        norm_path = os.path.join(os.path.dirname(filepath), 'normalization.json')
        if os.path.exists(norm_path):
            with open(norm_path, encoding='utf-8') as f:
                norm_data = json.load(f)
            self.norm_mins = norm_data['mins']
            self.norm_maxs = norm_data['maxs']
        else:
            logger.warning(
                "no normalization.json beside %s - predict() will receive raw "
                "features, which the model was not trained on",
                filepath,
            )
    
    @staticmethod
    def sigmoid(x: float) -> float:
        """Sigmoid activation function."""
        return 1.0 / (1.0 + math.exp(-max(-500, min(500, x))))
    
    def __repr__(self):
        return (
            f"BotDetector(features={self.NUM_FEATURES}, "
            f"params={len(self.model.parameters())})"
        )
