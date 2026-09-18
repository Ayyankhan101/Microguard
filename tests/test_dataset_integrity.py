"""The training set must not hand the model the answer.

The shipped model is a two-value step function: 413 of 623 held-out sessions
score exactly 0.731, which is `sigmoid(output bias)` with every hidden unit
off. It reads one column. `header_consistency_score` is 0.7 for every human
and 1.0 for every bot, and `features.py`'s `1.0 / len(ua_variants)` can only
ever produce 1.0, 0.5, 0.333... -- 0.7 is not reachable, so that value came
from a data generator rather than from the extractor. The 100% held-out
accuracy in `test_training_quality.py` is measuring the leak.

The cause is structural, not one bad column. The human class comes from a
single file (`harvard_training_data.json`), so ANY column constant within it
is a source fingerprint, and source is 1:1 with label. Ten columns qualify.

These two tests are the guard that makes that unshippable, whatever dataset is
used later. Both are `xfail(strict=True)` rather than skipped or deleted: they
describe the state the dataset must reach, and `strict` means CI reports it the
day real data makes them pass. See docs/explanation-training-data.md.
"""

import json
import os

import pytest

from microguard.features import FEATURE_NAMES

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')


def _load_training_data():
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
    pytest.skip("no training data found")


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

    # Passes since realistic_training_data.json: the human class is now real
    # Zanbil sessions extracted the same way as the bots, so no column is a
    # single constant across it. Was xfail(strict) while the human class came
    # from one generated file. See docs/results/2026-09-realistic-model.md.
    def test_no_column_is_constant_within_a_class(self):
        data, source = _load_training_data()
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

    # Passes since realistic_training_data.json: no single feature separates
    # real humans from real bots without overlap. Was xfail(strict) while
    # header_consistency_score was 0.7 for every synthetic human and 1.0 for
    # every bot -- the column the shipped model learned.
    def test_no_column_separates_the_classes_without_overlap(self):
        data, source = _load_training_data()
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

    # Passes since realistic_training_data.json: the human class is real Zanbil
    # shopper sessions spread across five distinct collection days, not one
    # generated file. Was xfail(strict) while every human row was 'harvard_human'.
    def test_human_rows_come_from_more_than_one_provenance(self):
        data, source = _load_training_data()
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
