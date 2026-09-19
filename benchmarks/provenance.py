"""What code produced a result, recorded at the moment it was produced.

`report.py` used to append a fixed paragraph asserting that the tables above it
were measured before three detection fixes landed. The tables are regenerated
from whatever JSON is on disk, so the paragraph became false the first time
anyone re-ran a suite: the document would state that its own fresh numbers were
stale. Commit 6a1932f was titled "Fix the self-contradicting benchmark report"
and fixed a different instance of exactly this, one section over.

The fix is to stop asserting and start recording. Every suite stamps the commit
it ran against, and the report compares those stamps to the checkout it is
rendering in. That answers the question the paragraph was trying to answer --
do these numbers reflect the current code? -- and it keeps answering it after
the next rule change, which a hand-written sentence cannot.

`benchmarks/results/` is gitignored, so results always come from the reader's
own run and will carry a stamp. Results written before this existed have none,
and the report says "unknown" for those rather than guessing.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str | None:
    """Run a read-only git command, or None if git or the repo is unavailable.

    A benchmark result is still worth having outside a git checkout (an
    extracted tarball, a container), so this never raises.
    """
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def current_commit() -> str | None:
    return _git("rev-parse", "HEAD")


def is_dirty() -> bool | None:
    status = _git("status", "--porcelain")
    return None if status is None else bool(status)


def stamp() -> dict:
    """The provenance block every suite writes into its results JSON."""
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": current_commit(),
        "dirty": is_dirty(),
    }


def describe(results: dict[str, dict | None]) -> str:
    """The report section replacing the hardcoded "measured before" paragraph.

    `results` maps a suite label to its loaded JSON (or None if it has not run).
    Says only what the stamps support: which suites match the checkout being
    rendered, which predate it, and which cannot say.
    """
    head = current_commit()
    current, stale, unknown = [], [], []
    for label, data in sorted(results.items()):
        if not data:
            continue
        prov = data.get("provenance") or {}
        commit = prov.get("commit")
        if not commit or not head:
            unknown.append((label, prov))
        elif commit == head:
            current.append((label, prov))
        else:
            stale.append((label, prov))

    if not (current or stale or unknown):
        return ""

    lines = ["## How current these numbers are", ""]
    if head:
        lines += [
            (f"Rendered at `{head[:12]}`. Each suite records the commit it ran "
             "against, so this section is derived, not asserted."),
            "",
        ]

    if stale:
        lines.append(
            "**Measured against older code.** These tables do not reflect the "
            "checkout you are reading, and any detection change since then is "
            "not in them:"
        )
        lines.append("")
        for label, prov in stale:
            at = prov.get("captured_at", "unknown time")
            dirty = " (dirty tree)" if prov.get("dirty") else ""
            lines.append(f"- `{label}` — `{prov['commit'][:12]}`{dirty}, {at}")
        lines.append("")

    if current:
        lines.append("**Measured against this commit:** "
                     + ", ".join(f"`{label}`" for label, _ in current) + ".")
        lines.append("")

    if unknown:
        lines.append(
            "**Provenance unknown:** "
            + ", ".join(f"`{label}`" for label, _ in unknown)
            + ". These ran before the suites recorded a commit, so whether they "
            "match the current code cannot be determined from the result files."
        )
        lines.append("")

    if any(prov.get("dirty") for _, prov in current + stale):
        lines.append(
            "At least one suite ran against a tree with uncommitted changes, so "
            "its commit does not fully identify the code that produced it."
        )
        lines.append("")

    return "\n".join(lines)
