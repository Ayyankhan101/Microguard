"""The statistics every benchmark result is reported with.

Stdlib only, so a number in the report depends on this file and nothing that
can change underneath it.

Rates are counts first. A recall of 100% on 3 actors and on 300 actors are
different claims, and the Wilson interval is what keeps them apart in a table:
it stays honest at 0/n and n/n, where the textbook normal interval collapses to
a width of zero and reports certainty that 3 actors cannot give.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass

Z95 = 1.959963984540054


def wilson_interval(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials.

    n == 0 returns the whole unit interval: no observations rule nothing out.
    """
    if n == 0:
        return (0.0, 1.0)
    if not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n, got k={k} n={n}")
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass(frozen=True)
class Rate:
    """k of n, with the interval that n can support."""

    k: int
    n: int

    @property
    def value(self) -> float | None:
        return self.k / self.n if self.n else None

    @property
    def ci(self) -> tuple[float, float]:
        return wilson_interval(self.k, self.n)

    def __add__(self, other: Rate) -> Rate:
        return Rate(self.k + other.k, self.n + other.n)

    def fmt(self) -> str:
        """'40% (12/30, CI 25-58%)', or 'n/a (0/0)' when nothing was measured."""
        if not self.n:
            return "n/a (0/0)"
        lo, hi = self.ci
        return f"{self.value:.0%} ({self.k}/{self.n}, CI {lo * 100:.0f}-{hi:.0%})"

    def as_dict(self) -> dict:
        lo, hi = self.ci
        return {"k": self.k, "n": self.n, "value": self.value, "ci_low": lo, "ci_high": hi}


def clearly_above(a: Rate, b: Rate) -> bool:
    """Whether a beats b with non-overlapping 95% intervals.

    Deliberately conservative (PREREGISTRATION.md, rule 2). Overlapping
    intervals can still hide a real difference; they cannot support a claim.
    """
    return a.n > 0 and b.n > 0 and a.ci[0] > b.ci[1]


@dataclass(frozen=True)
class Confusion:
    tp: int
    fp: int
    fn: int
    tn: int

    @classmethod
    def from_verdicts(cls, truth: dict[str, bool], flagged: dict[str, bool]) -> Confusion:
        """truth: actor -> is_bot. flagged: actor -> detector flagged it.

        An actor missing from `flagged` was never flagged; a detector that saw
        no evidence for an actor did not catch it.
        """
        tp = fp = fn = tn = 0
        for actor, is_bot in truth.items():
            hit = flagged.get(actor, False)
            if is_bot and hit:
                tp += 1
            elif is_bot:
                fn += 1
            elif hit:
                fp += 1
            else:
                tn += 1
        return cls(tp, fp, fn, tn)

    @property
    def recall(self) -> Rate:
        return Rate(self.tp, self.tp + self.fn)

    @property
    def fpr(self) -> Rate:
        return Rate(self.fp, self.fp + self.tn)

    @property
    def precision(self) -> Rate:
        return Rate(self.tp, self.tp + self.fp)


def _check_scored(scores: Sequence[float], labels: Sequence[bool]) -> None:
    if len(scores) != len(labels):
        raise ValueError("scores and labels differ in length")


def average_precision(scores: Sequence[float], labels: Sequence[bool]) -> float | None:
    """Area under the precision-recall curve, step-wise, as sklearn computes it.

    Tied scores are one threshold, not an arbitrary order: a detector that
    gives every actor the same score must not earn precision from the order
    the actors happened to be listed in. None when there are no positives.
    """
    _check_scored(scores, labels)
    positives = sum(labels)
    if positives == 0:
        return None
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    ap = 0.0
    tp = fp = 0
    prev_recall = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            if pairs[j][1]:
                tp += 1
            else:
                fp += 1
            j += 1
        recall = tp / positives
        ap += (recall - prev_recall) * (tp / (tp + fp))
        prev_recall = recall
        i = j
    return ap


def roc_auc(scores: Sequence[float], labels: Sequence[bool]) -> float | None:
    """Probability a random bot outscores a random human; ties count half.

    None unless both classes are present.
    """
    _check_scored(scores, labels)
    pos = [s for s, lbl in zip(scores, labels) if lbl]
    neg = [s for s, lbl in zip(scores, labels) if not lbl]
    if not pos or not neg:
        return None
    # Rank-sum form: O(n log n) and exact with ties via average ranks.
    ordered = sorted(scores)
    rank_of: dict[float, float] = {}
    i = 0
    while i < len(ordered):
        j = i
        while j < len(ordered) and ordered[j] == ordered[i]:
            j += 1
        rank_of[ordered[i]] = (i + 1 + j) / 2  # mean of 1-based ranks i+1..j
        i = j
    rank_sum = sum(rank_of[s] for s in pos)
    u = rank_sum - len(pos) * (len(pos) + 1) / 2
    return u / (len(pos) * len(neg))


def bootstrap_interval(
    stat: Callable[[Sequence[float], Sequence[bool]], float | None],
    scores: Sequence[float],
    labels: Sequence[bool],
    n_boot: int = 2000,
    seed: int = 0,
) -> tuple[float, float] | None:
    """Percentile 95% interval for a ranking statistic, resampling actors.

    Actors, not requests, are the unit: requests from one actor are not
    independent evidence, and resampling them would narrow the interval with
    information that is not there. Resamples where the statistic is undefined
    (one class only) are dropped; None if too few survive to mean anything.
    """
    _check_scored(scores, labels)
    rng = random.Random(seed)
    n = len(scores)
    values: list[float] = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        v = stat([scores[i] for i in idx], [labels[i] for i in idx])
        if v is not None:
            values.append(v)
    if len(values) < n_boot // 2:
        return None
    values.sort()
    lo = values[int(0.025 * (len(values) - 1))]
    hi = values[math.ceil(0.975 * (len(values) - 1))]
    return (lo, hi)


def quantile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated quantile, q in [0, 1]."""
    if not values:
        raise ValueError("quantile of nothing")
    ordered = sorted(values)
    pos = q * (len(ordered) - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


@dataclass(frozen=True)
class DetectionDelay:
    """How far into an actor's traffic the first flag came.

    `first_flags` are 1-based request indexes for the actors that were caught.
    Actors never caught are counted in `missed`, not folded in as infinity,
    so a detector cannot look fast by catching only the easy ones.
    """

    first_flags: tuple[int, ...]
    missed: int

    @property
    def median(self) -> float | None:
        return quantile(self.first_flags, 0.5) if self.first_flags else None

    @property
    def p90(self) -> float | None:
        return quantile(self.first_flags, 0.9) if self.first_flags else None

    def as_dict(self) -> dict:
        return {
            "caught": len(self.first_flags),
            "missed": self.missed,
            "median_request": self.median,
            "p90_request": self.p90,
        }
