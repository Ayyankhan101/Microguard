"""The collection sink is the only durable record of a scored decision.

`mg:v1:events` is a ring buffer -- `events.py` caps it at DEFAULT_CAPACITY and
`redis_events.py` LTRIMs to it -- so it holds the most recent 1000 decisions
and silently discards the rest. That is the right shape for a dashboard and
the wrong shape for building a training set, which is the one thing this
project actually needs: there is no real human ground truth anywhere in the
repo, and live traffic is the only source of it.

Two properties matter more than anything else here. The rows must survive a
power cut, because there is no second copy. And a failure to write one must
never reach the visitor: this runs under nginx `auth_request`, where a raised
exception becomes a 500 on someone's page load.
"""

import json
import os
from pathlib import Path

from microguard.collect import (
    DecisionCollector,
    collection_path,
    default_collection_dir,
)

FEATURE_COUNT = 19


_UNSET = object()


def _decision(decision_id="abc123", features=_UNSET, **overrides):
    # Sentinel, not None: `features=None` is the fail-open shape these tests
    # need to pass through verbatim, so it cannot double as "use the default".
    row = {
        "id": decision_id,
        "features": [0.5] * FEATURE_COUNT if features is _UNSET else features,
        "score": 0.42,
        "heuristic_label": "human",
        "heuristic_reason": "known browser, reasonable session",
        "ip": "203.0.113.7",
        "blocked": False,
    }
    row.update(overrides)
    return row


class TestWhereItWrites:
    def test_the_default_directory_is_not_inside_the_package(self, monkeypatch, tmp_path):
        """data/ ships in the wheel and is read-only on a normal install."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        package_root = Path(__file__).resolve().parent.parent / "microguard"

        resolved = default_collection_dir().resolve()

        assert package_root not in resolved.parents
        assert resolved != package_root

    def test_it_falls_back_to_a_home_directory(self, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)

        assert ".local" in str(default_collection_dir())

    def test_an_explicit_path_is_used_verbatim(self, tmp_path):
        target = tmp_path / "nested" / "run.jsonl"

        assert collection_path(target) == target


class TestItRecordsWhatTrainingNeeds:
    def test_a_decision_is_appended_as_one_json_line(self, tmp_path):
        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        collector.record(_decision())

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert len(rows) == 1
        assert rows[0]["decision_id"] == "abc123"
        assert rows[0]["features"] == [0.5] * FEATURE_COUNT
        assert rows[0]["heuristic_label"] == "human"
        assert "timestamp" in rows[0]

    def test_rows_accumulate_rather_than_overwrite(self, tmp_path):
        """The Redis ring keeps 1000. This must keep all of them."""
        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        for i in range(1500):
            collector.record(_decision(decision_id=f"d{i}"))

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1500
        assert json.loads(lines[0])["decision_id"] == "d0"
        assert json.loads(lines[-1])["decision_id"] == "d1499"

    def test_a_reopened_collector_appends_to_the_same_file(self, tmp_path):
        """A restarted server must not truncate the archive."""
        path = tmp_path / "collected.jsonl"
        DecisionCollector(path).record(_decision(decision_id="before"))
        DecisionCollector(path).record(_decision(decision_id="after"))

        lines = path.read_text(encoding="utf-8").splitlines()
        assert [json.loads(line)["decision_id"] for line in lines] == ["before", "after"]

    def test_the_directory_is_created_if_absent(self, tmp_path):
        path = tmp_path / "does" / "not" / "exist" / "collected.jsonl"

        DecisionCollector(path).record(_decision())

        assert path.exists()


class TestRowsWithoutFeaturesAreSkipped:
    """`scorer.py`'s fail-open result carries `features: None`.

    Those rows describe an outage, not an actor, and a training set that
    accepted them would learn from a vector of nothing.
    """

    def test_a_fail_open_decision_is_not_recorded(self, tmp_path):
        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        collector.record(_decision(features=None))

        assert not path.exists() or path.read_text(encoding="utf-8") == ""

    def test_a_wrong_width_feature_vector_is_not_recorded(self, tmp_path):
        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        collector.record(_decision(features=[0.5] * 3))

        assert not path.exists() or path.read_text(encoding="utf-8") == ""

    def test_a_valid_row_still_lands_after_a_skipped_one(self, tmp_path):
        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        collector.record(_decision(decision_id="skipped", features=None))
        collector.record(_decision(decision_id="kept"))

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert [r["decision_id"] for r in rows] == ["kept"]


class TestAWriteFailureNeverReachesTheVisitor:
    """This runs inside nginx auth_request. A raised exception is a 500.

    Deliberately the opposite of `record_correction`, where a failure MUST
    propagate: an operator who clicked "wrong" and saw nothing happen would
    click again, so a lost correction has to be visible. Nobody is watching a
    collection write, and the cost of surfacing it is someone's page load.
    """

    def test_a_failed_write_is_logged_and_swallowed(self, tmp_path, caplog, monkeypatch):
        """Injected rather than provoked with chmod.

        The first version made the directory 0o500 and expected OSError.
        That is POSIX semantics: on Windows chmod does not remove write
        permission on a directory, so no error was raised, nothing was
        logged, and all four Windows matrix jobs failed on an empty caplog
        while every other platform passed. The contract under test -- an
        OSError during the write is logged, not raised -- is the same
        everywhere, so inject the OSError instead of asking the filesystem
        to produce one.
        """
        import logging

        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        def boom(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "open", boom)

        with caplog.at_level(logging.WARNING, logger="microguard.collect"):
            written = collector.record(_decision())  # must not raise

        assert written is False
        assert "could not record" in caplog.text

    def test_an_unserializable_row_does_not_raise(self, tmp_path):
        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        collector.record(_decision(heuristic_reason=object()))  # must not raise

    def test_recording_keeps_working_after_a_failure(self, tmp_path):
        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)

        collector.record(_decision(decision_id="bad", heuristic_reason=object()))
        collector.record(_decision(decision_id="good"))

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert [r["decision_id"] for r in rows] == ["good"]


class TestDurability:
    def test_each_row_is_flushed_and_fsynced(self, tmp_path, monkeypatch):
        """There is no second copy of this data.

        A row that survives only in the page cache is a row lost to the next
        power cut -- the same reasoning as `record_correction`.
        """
        path = tmp_path / "collected.jsonl"
        synced = []
        real_fsync = os.fsync
        monkeypatch.setattr(
            os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd))[1]
        )

        DecisionCollector(path).record(_decision())

        assert synced, "the row was never fsynced"

    def test_the_file_is_utf8_whatever_the_platform_locale(self, tmp_path):
        """Windows defaults to cp1252; a UA with non-ASCII would round-trip
        differently per platform without an explicit encoding."""
        path = tmp_path / "collected.jsonl"

        DecisionCollector(path).record(
            _decision(heuristic_reason="naïve navigation — 3 referrers")
        )

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert rows[0]["heuristic_reason"] == "naïve navigation — 3 referrers"


class TestLoadingBackWhatWasCollected:
    def test_collected_rows_load_as_feature_vectors(self, tmp_path):
        from microguard.collect import load_collected

        path = tmp_path / "collected.jsonl"
        collector = DecisionCollector(path)
        for i in range(3):
            collector.record(_decision(decision_id=f"d{i}"))

        rows = load_collected(path)

        assert len(rows) == 3
        assert all(len(row["features"]) == FEATURE_COUNT for row in rows)

    def test_a_corrupt_line_is_skipped_and_counted(self, tmp_path):
        from microguard.collect import load_collected

        path = tmp_path / "collected.jsonl"
        DecisionCollector(path).record(_decision(decision_id="good"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write("{not json\n")

        rows, skipped = load_collected(path, report_skipped=True)

        assert [r["decision_id"] for r in rows] == ["good"]
        assert skipped == 1

    def test_an_absent_file_is_empty_not_an_error(self, tmp_path):
        from microguard.collect import load_collected

        assert load_collected(tmp_path / "nothing.jsonl") == []

    def test_the_model_score_is_archived_beside_the_blend(self, tmp_path):
        """The blended score alone cannot say whether the model helps."""
        from microguard.collect import load_collected

        path = tmp_path / "decisions.jsonl"
        DecisionCollector(path).record(_decision(model_score=0.73))

        assert load_collected(path)[0]["model_score"] == 0.73

    def test_collected_rows_carry_no_confirmed_label(self, tmp_path):
        """The honest part, pinned as a test.

        A collected row is what the tool GUESSED. Treating it as ground truth
        would train the model to reproduce `labeler.py`, and
        `compute_combined_score` blends the two -- so one signal would be
        counted twice while reading as independent corroboration. Labels come
        from `record_correction` only, after a human looked.
        """
        from microguard.collect import load_collected

        path = tmp_path / "collected.jsonl"
        DecisionCollector(path).record(_decision())

        rows = load_collected(path)

        assert "label" not in rows[0]


class TestDefaultPathAndBlankLines:
    """The branches the archive takes when nothing is passed explicitly."""

    def test_no_path_resolves_to_the_default_archive_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

        assert collection_path() == tmp_path / "microguard" / "collected" / "decisions.jsonl"

    def test_blank_lines_are_ignored_not_counted_as_corrupt(self, tmp_path):
        """A trailing newline is normal, not damage."""
        from microguard.collect import load_collected

        path = tmp_path / "collected.jsonl"
        DecisionCollector(path).record(_decision(decision_id="real"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n   \n")

        rows, skipped = load_collected(path, report_skipped=True)

        assert [r["decision_id"] for r in rows] == ["real"]
        assert skipped == 0

    def test_a_row_with_the_wrong_feature_width_is_skipped_on_read(self, tmp_path):
        """Guarded on the way in AND on the way out: the file is append-only
        on disk and anything can append to it."""
        from microguard.collect import load_collected

        path = tmp_path / "collected.jsonl"
        DecisionCollector(path).record(_decision(decision_id="good"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"decision_id": "narrow", "features": [0.1, 0.2]}) + "\n")
            handle.write(json.dumps({"decision_id": "absent"}) + "\n")

        rows, skipped = load_collected(path, report_skipped=True)

        assert [r["decision_id"] for r in rows] == ["good"]
        assert skipped == 2
