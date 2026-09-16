"""Durable archive of scored decisions, for building a real training set.

Stdlib only, and deliberately outside `live/`: `live/__init__.py` raises
ImportError without redis-py, and nothing here needs Redis. Same split as
`events.py` vs `live/redis_events.py`.

Why this exists. `mg:v1:events` is a ring buffer -- `events.py` caps it at
DEFAULT_CAPACITY and `live/redis_events.py` LTRIMs to it -- so it holds the
most recent 1000 decisions and drops the rest without saying so. That is right
for a dashboard and wrong for collecting data, which is the one thing this
project actually needs: there is no real human ground truth in the repo by any
route, and observe-only live traffic is the only source of it.

What a collected row is NOT: a labeled example. It records what the tool
guessed. Treating that as ground truth would train the model to reproduce
`labeler.py`, and `scoring.compute_combined_score` blends model and heuristic
-- so one signal would be counted twice while reading as two. Labels come from
`training.online_update.record_correction`, after a human looked.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

from .model import BotDetector

logger = logging.getLogger(__name__)

NUM_FEATURES = BotDetector.NUM_FEATURES


def default_collection_dir() -> Path:
    """Where collected decisions accumulate.

    Not inside the package: `data/` ships in the wheel and is read-only on a
    normal install. Mirrors `training.online_update.default_feedback_dir`.
    """
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(Path.home(), ".local", "share")
    return Path(base) / "microguard" / "collected"


def collection_path(path: Path | str | None = None) -> Path:
    """Resolve an explicit path, or the default archive file."""
    if path is not None:
        return Path(path)
    return default_collection_dir() / "decisions.jsonl"


@runtime_checkable
class DecisionSink(Protocol):
    """Somewhere durable to put a decision.

    Narrower than `events.DecisionRecorder` on purpose: a recorder also has to
    answer `stats()` and `recent()` for the dashboard, and an archive has no
    business doing either. The scorer takes both because they are different
    jobs with different failure costs, not two implementations of one.
    """

    def record(self, decision: dict) -> bool:
        """Append one decision. Must never raise into the caller's hot path."""
        ...


class DecisionCollector:
    """Append-only JSONL sink for scored decisions.

    One row per decision, opened and closed per write. That costs a syscall
    per request and buys a file that is complete after every single one --
    worth it, because this is the only copy and a half-written archive is
    worse than a short one.
    """

    def __init__(self, path: Path | str | None = None):
        self.path = collection_path(path)

    def record(self, decision: dict) -> bool:
        """Append one decision. Returns whether it was written.

        Never raises. This runs under nginx `auth_request`, where an exception
        becomes a 500 on a real visitor's page load, and nobody is watching a
        collection write. That is the opposite of `record_correction`, where a
        failure MUST propagate: an operator who clicked "wrong" and saw
        nothing happen would click again, so a lost correction has to be
        visible. Here the only honest choice is to log it and keep serving.
        """
        features = decision.get("features")
        if not isinstance(features, list) or len(features) != NUM_FEATURES:
            # scorer.py's fail-open result carries features=None. Those rows
            # describe an outage, not an actor, and a training set that
            # accepted them would learn from a vector of nothing.
            return False

        row = {
            "decision_id": decision.get("id"),
            "features": [float(f) for f in features],
            "score": decision.get("score"),
            # The model alone, beside the blend: without it no evaluation can
            # say whether the model adds anything to the heuristic.
            "model_score": decision.get("model_score"),
            "heuristic_label": decision.get("heuristic_label"),
            "heuristic_reason": decision.get("heuristic_reason"),
            "ip": decision.get("ip"),
            "blocked": decision.get("blocked"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            # Serialize before opening: an unserializable field should not
            # leave a truncated line in the archive.
            line = json.dumps(row)
        except (TypeError, ValueError):
            logger.warning(
                "could not serialize decision %r for collection; dropped",
                decision.get("id"),
                exc_info=True,
            )
            return False

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                # A row that survives only in the page cache is a row lost to
                # the next power cut, and there is no second copy.
                os.fsync(handle.fileno())
        except OSError:
            logger.warning(
                "could not record decision %r to %s; dropped",
                decision.get("id"), self.path,
                exc_info=True,
            )
            return False

        return True


def load_collected(
    path: Path | str | None = None,
    report_skipped: bool = False,
):
    """Read back collected rows, skipping anything unparseable.

    A truncated final line is the normal result of a killed process, so a
    corrupt row is counted rather than fatal -- the same contract as
    `training.online_update.load_corrections`.
    """
    target = collection_path(path)
    rows: list[dict] = []
    skipped = 0

    if not target.exists():
        return (rows, skipped) if report_skipped else rows

    with target.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            features = row.get("features")
            if not isinstance(features, list) or len(features) != NUM_FEATURES:
                skipped += 1
                continue
            rows.append(row)

    return (rows, skipped) if report_skipped else rows
