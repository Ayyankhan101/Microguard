"""The report must not claim it knows when its own tables were measured.

`report.py` used to append a fixed paragraph saying "the numbers above were
measured BEFORE the three fixes". The tables regenerate from whatever JSON is
on disk, so the first re-run made that false about its own fresh numbers. These
tests pin the replacement: a section derived from what each suite recorded,
which stays true without anybody maintaining a sentence.
"""

from benchmarks import provenance

HEAD = "a" * 40
OLDER = "b" * 40


def _result(commit=None, dirty=False, at="2026-09-19T18:00:00+00:00"):
    if commit is None:
        return {"cells": []}
    return {"cells": [], "provenance": {"captured_at": at, "commit": commit,
                                        "dirty": dirty}}


def _describe(results, head=HEAD, monkeypatch=None):
    monkeypatch.setattr(provenance, "current_commit", lambda: head)
    return provenance.describe(results)


class TestStamp:
    def test_stamp_carries_commit_time_and_dirtiness(self):
        s = provenance.stamp()

        assert set(s) == {"captured_at", "commit", "dirty"}
        assert s["captured_at"].endswith("+00:00")

    def test_git_failures_never_raise(self, monkeypatch):
        """A result is still worth having outside a git checkout."""
        monkeypatch.setattr(provenance, "_git", lambda *a: None)

        s = provenance.stamp()

        assert s["commit"] is None
        assert s["dirty"] is None


class TestDescribe:
    def test_a_suite_at_the_rendered_commit_is_reported_current(self, monkeypatch):
        out = _describe({"Suite A": _result(HEAD)}, monkeypatch=monkeypatch)

        assert "Measured against this commit:** `Suite A`" in out
        assert "older code" not in out

    def test_a_suite_at_another_commit_is_reported_stale(self, monkeypatch):
        out = _describe({"Suite A": _result(OLDER)}, monkeypatch=monkeypatch)

        assert "Measured against older code" in out
        assert OLDER[:12] in out
        assert "Measured against this commit" not in out

    def test_an_unstamped_suite_is_reported_unknown_not_guessed(self, monkeypatch):
        """The failure mode being fixed is asserting what cannot be known."""
        out = _describe({"Suite A": _result(None)}, monkeypatch=monkeypatch)

        assert "Provenance unknown:** `Suite A`" in out
        assert "older code" not in out
        assert "Measured against this commit" not in out

    def test_the_three_states_are_reported_together(self, monkeypatch):
        out = _describe({
            "Suite A": _result(OLDER),
            "Suite B": _result(HEAD),
            "Suite C": _result(None),
        }, monkeypatch=monkeypatch)

        assert "Measured against older code" in out
        assert "Measured against this commit:** `Suite B`" in out
        assert "Provenance unknown:** `Suite C`" in out

    def test_a_dirty_tree_is_called_out(self, monkeypatch):
        out = _describe({"Suite A": _result(OLDER, dirty=True)},
                        monkeypatch=monkeypatch)

        assert "(dirty tree)" in out
        assert "does not fully identify the code" in out

    def test_suites_that_have_not_run_are_omitted(self, monkeypatch):
        out = _describe({"Suite A": _result(HEAD), "Suite B": None},
                        monkeypatch=monkeypatch)

        assert "Suite B" not in out

    def test_nothing_run_produces_no_section(self, monkeypatch):
        assert _describe({"Suite A": None}, monkeypatch=monkeypatch) == ""

    def test_outside_a_git_checkout_everything_is_unknown(self, monkeypatch):
        """No HEAD to compare against is not the same as stale."""
        out = _describe({"Suite A": _result(HEAD)}, head=None,
                        monkeypatch=monkeypatch)

        assert "Provenance unknown" in out
        assert "older code" not in out
