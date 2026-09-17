"""The real attack tools that make up vulnscan at L0-L2.

ffuf, sqlmap and nuclei, each pinned to its own IP through X-Forwarded-For and
aimed only at 127.0.0.1. At L0 they carry their own user agent; at L1/L2 they
spoof Chrome, which is the whole point of moving up the ladder. Whatever real
requests they emit are the bot traffic — genuine tool output, not a script's
imitation of it.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from benchmarks.ladder.actors import CHROME_UA

BASE = "http://127.0.0.1:8080"
TOOL_TIMEOUT_S = 75


WORDS = (
    ".env", ".git", "wp-login.php", "wp-admin", "phpmyadmin", "xmlrpc.php",
    "admin", "login", "catalog", "search", "robots.txt", "config.json",
    "backup", "test", "api", "console",
)


def _wordlist() -> str:
    fd, path = tempfile.mkstemp(suffix=".txt")
    with open(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(WORDS))
    return path


def tool_command(tool: str, ip: str, level: str) -> list[str] | None:
    """The argv for one tool at one level, or None if the binary is absent."""
    if shutil.which(tool) is None:
        return None
    xff = f"X-Forwarded-For: {ip}"
    spoof = level in ("L1", "L2")
    if tool == "ffuf":
        cmd = ["ffuf", "-u", f"{BASE}/FUZZ", "-w", _wordlist(), "-H", xff,
               "-mc", "all", "-t", "8", "-p", "0.05", "-s"]
        if spoof:
            cmd += ["-H", f"User-Agent: {CHROME_UA}"]
        return cmd
    if tool == "sqlmap":
        cmd = ["sqlmap", "-u", f"{BASE}/search?q=1", "--batch", "--level=1", "--risk=1",
               "--technique=B", "--headers", xff, "--flush-session", "--disable-coloring"]
        cmd += ["--random-agent"] if spoof else []
        return cmd
    if tool == "nuclei":
        cmd = ["nuclei", "-u", BASE, "-H", xff, "-rl", "50", "-timeout", "3",
               "-silent", "-nc", "-tags", "exposure,misconfig,tech"]
        if spoof:
            cmd += ["-H", f"User-Agent: {CHROME_UA}"]
        return cmd
    raise ValueError(tool)


def run_tool(tool: str, ip: str, level: str, log: Path | None = None) -> str:
    """Run one tool to completion (or timeout). Returns a one-line status."""
    cmd = tool_command(tool, ip, level)
    if cmd is None:
        return f"skip {tool}: not installed"
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=TOOL_TIMEOUT_S, check=False)
        return f"{tool} done ({ip}, {level})"
    except subprocess.TimeoutExpired:
        return f"{tool} timed out, partial traffic kept ({ip}, {level})"
    except Exception as exc:  # noqa: BLE001
        return f"{tool} error: {exc}"
