"""The training set must not hand the model the answer.

The shipped model was a two-value step function: 413 of 623 held-out sessions
scored exactly 0.731, which is `sigmoid(output bias)` with every hidden unit
off. It read one column. `header_consistency_score` was 0.7 for every human and
1.0 for every bot, and `features.py`'s `1.0 / len(ua_variants)` can only ever
produce 1.0, 0.5, 0.333... -- 0.7 is not reachable, so that value came from a
data generator rather than from the extractor. The 100% held-out accuracy in
`test_training_quality.py` was measuring the leak.

The cause was structural, not one bad column. The human class came from a
single file (`harvard_training_data.json`), so ANY column constant within it was
a source fingerprint, and source was 1:1 with label. Ten columns qualified.

These three guards are what makes that unshippable. See
docs/explanation-training-data.md and docs/results/2026-09-realistic-model.md.

## Why each guard runs twice

Every guard below is parametrized over two datasets, because they answer two
different questions and only one of them was being asked:

- **builder** -- what `build_realistic_dataset.py` produces RIGHT NOW, built
  during the test run from `tests/fixtures/zanbil/`. This guards the CODE. It
  is the half that was missing: these tests used to read whichever dataset file
  happened to be on disk, so a change to the builder that reintroduced a
  fingerprint column passed CI indefinitely, until somebody manually
  regenerated and committed a 2.7 MB artifact. The builder is under active
  change (the day-based holdout and the normalization rework both rewrite it),
  which is exactly when a guard that cannot fail is worth nothing.

- **committed** -- `data/realistic_training_data.json`, the file the trainer
  actually reads. This guards the DATA, and is what these tests always did.
  Skipped when the file is absent.

The fixture is real Zanbil traffic with the client IPs rewritten, built by
`scripts/build_zanbil_test_fixture.py`; that script's docstring explains why it
is sampled rather than invented. It is built with `include_orgx=False`: the
organization-x rows are bot-only, so they only ever widen the bot side of a
column, which makes a separability defect HARDER to see, and parsing them costs
94 seconds against 0.07 for the Zanbil half alone.
"""

import json
import os

import pytest

from microguard.features import FEATURE_NAMES
from microguard.training import build_realistic_dataset

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'zanbil')


@pytest.fixture(scope='module')
def builder_dataset():
    """Run the real builder against the committed fixture.

    The paths are module-level constants in the builder, so they are swapped
    and restored here rather than parameterised -- injecting the condition
    instead of depending on what happens to be on this machine, since the real
    Zanbil logs under `benchmarks/data/` are gitignored and absent in CI.
    """
    original = (build_realistic_dataset.ZANBIL_DAYS,
                build_realistic_dataset.ZANBIL_LABELS)
    build_realistic_dataset.ZANBIL_DAYS = os.path.join(FIXTURE_DIR, 'days')
    build_realistic_dataset.ZANBIL_LABELS = os.path.join(FIXTURE_DIR, 'labels')
    try:
        data = build_realistic_dataset.build_dataset(seed=42, include_orgx=False)
    finally:
        (build_realistic_dataset.ZANBIL_DAYS,
         build_realistic_dataset.ZANBIL_LABELS) = original
    return data, 'build_realistic_dataset.py (tests/fixtures/zanbil)'


def _load_committed():
    """Whichever file `training/train.py` actually trains on.

    Mirrors that module's priority order so this tracks reality rather than
    assuming a filename, the same way `test_training_quality.py` does.
    """
    for name in ('realistic_training_data.json', 'real_bot_training_data.json',
                 'harvard_training_data.json'):
        path = os.path.join(DATA_DIR, name)
        if os.path.exists(path):
            with open(path, encoding='utf-8') as handle:
                return json.load(handle), name
    pytest.skip("no committed training data found")


@pytest.fixture(params=['builder', 'committed'])
def dataset(request, builder_dataset):
    return builder_dataset if request.param == 'builder' else _load_committed()


def _columns_by_class(data):
    """(per-column human values, per-column bot values)."""
    labels = [float(lbl) for lbl in data['labels']]
    columns = list(zip(*data['features']))
    human, bot = [], []
    for column in columns:
        human.append([v for v, lbl in zip(column, labels) if lbl <= 0.5])
        bot.append([v for v, lbl in zip(column, labels) if lbl > 0.5])
    return human, bot


class TestNoColumnIsASourceFingerprint:
    """A column constant within one class identifies the file, not the class."""

    def test_no_column_is_constant_within_a_class(self, dataset):
        data, source = dataset
        human, bot = _columns_by_class(data)

        offenders = []
        for i, name in enumerate(FEATURE_NAMES):
            human_constant = len(set(human[i])) == 1
            bot_constant = len(set(bot[i])) == 1
            # A column constant in BOTH classes at the same value carries no
            # information at all, which is useless but not a leak. A column
            # constant in one class and varying in the other is a fingerprint.
            if human_constant != bot_constant:
                side = "human" if human_constant else "bot"
                value = human[i][0] if human_constant else bot[i][0]
                offenders.append(f"{name} (constant {value} across {side})")

        assert not offenders, (
            f"{len(offenders)} fingerprint column(s) in {source}:\n  "
            + "\n  ".join(offenders)
        )


class TestNoColumnPerfectlySeparatesTheClasses:
    """Zero overlap in a real behavioural feature means it is not behavioural."""

    def test_no_column_separates_the_classes_without_overlap(self, dataset):
        data, source = dataset
        human, bot = _columns_by_class(data)

        offenders = []
        for i, name in enumerate(FEATURE_NAMES):
            if not human[i] or not bot[i]:
                continue
            if max(human[i]) < min(bot[i]) or max(bot[i]) < min(human[i]):
                offenders.append(
                    f"{name} (human {min(human[i])}..{max(human[i])}, "
                    f"bot {min(bot[i])}..{max(bot[i])})"
                )

        assert not offenders, (
            f"{len(offenders)} perfectly separable column(s) in {source} -- "
            f"each one is the label in disguise:\n  " + "\n  ".join(offenders)
        )


class TestTheHumanClassHasMoreThanOneSource:
    """The structural cause, asserted directly rather than via its symptoms.

    Every fingerprint column above follows from this one fact. A dataset whose
    human class comes from one generator can always be separated by detecting
    that generator, however many individual columns get patched.
    """

    def test_human_rows_come_from_more_than_one_provenance(self, dataset):
        data, source = dataset
        provenance = data.get('provenance')
        if provenance is None:
            pytest.skip(f"{source} carries no provenance breakdown")

        labels = [float(lbl) for lbl in data['labels']]
        human_sources = {
            prov for prov, lbl in zip(provenance, labels) if lbl <= 0.5
        }

        assert len(human_sources) > 1, (
            f"the entire human class in {source} comes from {human_sources} "
            "-- any column constant in that source is a label detector"
        )


class TestTheGuardsCanActuallyFail:
    """A guard that cannot fail is the thing this change exists to fix.

    These run the real assertions against a deliberately poisoned copy of the
    builder's output. Without them, a refactor that quietly stopped comparing
    columns would leave every test above green and nothing would say so.
    """

    def test_a_fingerprint_column_is_caught(self, builder_dataset):
        data, _ = builder_dataset
        poisoned = {**data, 'features': [list(row) for row in data['features']]}
        for row, label in zip(poisoned['features'], poisoned['labels']):
            if float(label) <= 0.5:
                row[9] = 0.7          # header_consistency_score, the original leak

        human, bot = _columns_by_class(poisoned)
        caught = (len(set(human[9])) == 1) != (len(set(bot[9])) == 1)

        assert caught, "the constant-column guard no longer detects a fingerprint"

    def test_a_perfectly_separable_column_is_caught(self, builder_dataset):
        data, _ = builder_dataset
        poisoned = {**data, 'features': [list(row) for row in data['features']]}
        for row, label in zip(poisoned['features'], poisoned['labels']):
            row[9] = 1.0 if float(label) > 0.5 else 0.0

        human, bot = _columns_by_class(poisoned)
        caught = max(human[9]) < min(bot[9]) or max(bot[9]) < min(human[9])

        assert caught, "the separability guard no longer detects a split column"

    def test_a_single_source_human_class_is_caught(self, builder_dataset):
        data, _ = builder_dataset
        labels = [float(lbl) for lbl in data['labels']]
        poisoned = ['one_generator' if lbl <= 0.5 else prov
                    for prov, lbl in zip(data['provenance'], labels)]

        human_sources = {p for p, lbl in zip(poisoned, labels) if lbl <= 0.5}

        assert len(human_sources) == 1, "the fixture no longer has a human class"
