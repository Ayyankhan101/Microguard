"""The numbers in the report are only as right as these functions."""

import random

import pytest

from benchmarks.metrics import (
    Confusion,
    DetectionDelay,
    Rate,
    average_precision,
    bootstrap_interval,
    clearly_above,
    quantile,
    roc_auc,
    wilson_interval,
)


class TestWilson:
    # Reference values from the closed form (Newcombe 1998, method 3).
    @pytest.mark.parametrize(
        "k,n,lo,hi",
        [
            (0, 10, 0.0, 0.2775),
            (10, 10, 0.7225, 1.0),
            (5, 10, 0.2366, 0.7634),
            (43, 43, 0.9180, 1.0),
            (1, 50, 0.0035, 0.1050),
        ],
    )
    def test_known_values(self, k, n, lo, hi):
        got_lo, got_hi = wilson_interval(k, n)
        assert got_lo == pytest.approx(lo, abs=5e-4)
        assert got_hi == pytest.approx(hi, abs=5e-4)

    def test_no_observations_rule_nothing_out(self):
        assert wilson_interval(0, 0) == (0.0, 1.0)

    def test_rejects_impossible_counts(self):
        with pytest.raises(ValueError):
            wilson_interval(11, 10)


class TestRate:
    def test_format_carries_counts_and_interval(self):
        assert Rate(12, 30).fmt() == "40% (12/30, CI 25-58%)"
        assert Rate(0, 0).fmt() == "n/a (0/0)"

    def test_pooling_adds_counts(self):
        assert Rate(3, 10) + Rate(4, 10) == Rate(7, 20)

    def test_clearly_above_needs_disjoint_intervals(self):
        assert clearly_above(Rate(40, 40), Rate(0, 40))
        assert not clearly_above(Rate(6, 10), Rate(4, 10))
        assert not clearly_above(Rate(1, 1), Rate(0, 0))


class TestConfusion:
    def test_unflagged_and_missing_actors_are_not_caught(self):
        truth = {"b1": True, "b2": True, "h1": False, "h2": False}
        c = Confusion.from_verdicts(truth, {"b1": True, "h2": True})
        assert (c.tp, c.fp, c.fn, c.tn) == (1, 1, 1, 1)
        assert c.recall == Rate(1, 2)
        assert c.fpr == Rate(1, 2)
        assert c.precision == Rate(1, 2)

    def test_flags_for_unlabeled_actors_are_ignored(self):
        c = Confusion.from_verdicts({"b": True}, {"b": True, "stranger": True})
        assert (c.tp, c.fp, c.fn, c.tn) == (1, 0, 0, 0)


class TestRanking:
    def test_perfect_and_inverted(self):
        labels = [True, True, False, False]
        assert average_precision([0.9, 0.8, 0.2, 0.1], labels) == 1.0
        assert roc_auc([0.9, 0.8, 0.2, 0.1], labels) == 1.0
        assert roc_auc([0.1, 0.2, 0.8, 0.9], labels) == 0.0

    def test_constant_score_earns_nothing_from_list_order(self):
        # The shipped model's failure mode: one value for every actor.
        labels = [True, False, True, False, False]
        assert average_precision([0.731] * 5, labels) == pytest.approx(2 / 5)
        assert roc_auc([0.731] * 5, labels) == 0.5

    def test_undefined_without_both_classes(self):
        assert average_precision([0.5], [False]) is None
        assert roc_auc([0.5, 0.6], [True, True]) is None

    def test_matches_sklearn_on_random_tied_data(self):
        sk = pytest.importorskip("sklearn.metrics")
        rng = random.Random(7)
        for _ in range(50):
            n = rng.randint(5, 60)
            labels = [rng.random() < 0.4 for _ in range(n)]
            if not any(labels) or all(labels):
                continue
            scores = [round(rng.random(), 1) for _ in range(n)]  # heavy ties
            assert average_precision(scores, labels) == pytest.approx(
                sk.average_precision_score(labels, scores)
            )
            assert roc_auc(scores, labels) == pytest.approx(sk.roc_auc_score(labels, scores))

    def test_bootstrap_brackets_the_point_estimate(self):
        rng = random.Random(3)
        labels = [i % 2 == 0 for i in range(80)]
        scores = [(0.7 if lbl else 0.4) + rng.uniform(-0.3, 0.3) for lbl in labels]
        point = roc_auc(scores, labels)
        lo, hi = bootstrap_interval(roc_auc, scores, labels, n_boot=500)
        assert lo <= point <= hi
        assert hi - lo < 0.3

    def test_bootstrap_is_deterministic_per_seed(self):
        labels = [True, False] * 10
        scores = [i / 20 for i in range(20)]
        assert bootstrap_interval(roc_auc, scores, labels, n_boot=200, seed=1) == (
            bootstrap_interval(roc_auc, scores, labels, n_boot=200, seed=1)
        )


class TestDelay:
    def test_quantile_interpolates(self):
        assert quantile([1, 2, 3, 4], 0.5) == 2.5
        assert quantile([5], 0.9) == 5

    def test_missed_actors_are_counted_not_averaged(self):
        d = DetectionDelay(first_flags=(1, 3, 20), missed=7)
        assert d.median == 3
        assert d.as_dict()["missed"] == 7
        assert DetectionDelay((), 4).median is None
