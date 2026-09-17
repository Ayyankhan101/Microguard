"""Shared test fixtures: LogEntry/Session builders and a real-file helper."""

from datetime import datetime, timezone

import pytest

from microguard.features import Session
from microguard.parser import LogEntry


# Env vars that point MLflow or the Databricks SDK at a real workspace.
@pytest.fixture
def make_entry():
    """Factory fixture: build a LogEntry with sensible defaults.

    Usage: make_entry(url="/api", status=404, user_agent="curl/8.0")
    """
    def _make(
        ip: str = "192.168.1.1",
        timestamp: datetime | None = None,
        method: str = "GET",
        url: str = "/products",
        status: int = 200,
        size: int = 1234,
        referer: str = "https://example.com",
        user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        raw_line: str = "",
    ) -> LogEntry:
        if timestamp is None:
            timestamp = datetime(2023, 3, 24, 17, 7, 41, tzinfo=timezone.utc)
        return LogEntry(
            ip=ip,
            timestamp=timestamp,
            method=method,
            url=url,
            status=status,
            size=size,
            referer=referer,
            user_agent=user_agent,
            raw_line=raw_line,
        )
    return _make


@pytest.fixture
def make_session(make_entry):
    """Factory fixture: build a Session from a list of LogEntry objects.

    Usage: make_session("10.0.0.1", "curl/8.0", [make_entry(url="/a"), ...])
    """
    def _make(ip: str, user_agent: str, entries: list[LogEntry]) -> Session:
        session = Session(ip, user_agent)
        for entry in entries:
            session.add_request(entry)
        return session
    return _make


@pytest.fixture
def nginx_log_file(tmp_path):
    """Factory fixture: write nginx-combined-format lines to a real temp file.

    Usage: path = nginx_log_file(["10.0.0.1 - - [...] ...", ...])
    Returns the file path as a string.
    """
    def _write(lines: list[str], name: str = "access.log") -> str:
        log_path = tmp_path / name
        log_path.write_text("\n".join(lines) + "\n", encoding='utf-8')
        return str(log_path)
    return _write
