"""Parsing of Apache/Nginx access-log lines into :class:`LogEntry` objects.

Both the "common" and the "combined" log formats are supported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional

LOG_PATTERN = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<protocol>HTTP/[\d.]+))?" '
    r"(?P<status>\d{3}) (?P<size>\d+|-)"
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass(frozen=True)
class LogEntry:
    """A single parsed request from an access log."""

    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int
    referrer: str = ""
    user_agent: str = ""

    @property
    def route(self) -> str:
        """The request path without its query string."""
        return self.path.split("?", 1)[0]

    @property
    def is_error(self) -> bool:
        """True for any 4xx or 5xx response."""
        return self.status >= 400

    @property
    def is_server_error(self) -> bool:
        """True for any 5xx response."""
        return self.status >= 500


@dataclass
class ParseResult:
    """The outcome of parsing many lines: good entries plus a malformed count."""

    entries: List[LogEntry] = field(default_factory=list)
    malformed: int = 0

    @property
    def total_lines(self) -> int:
        """Number of non-blank lines that were examined."""
        return len(self.entries) + self.malformed


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse one log line, returning ``None`` if it is not a valid entry."""
    match = LOG_PATTERN.match(line.strip())
    if match is None:
        return None

    try:
        timestamp = datetime.strptime(match.group("time"), TIME_FORMAT)
    except ValueError:
        return None

    size = match.group("size")
    referrer = match.group("referrer")

    return LogEntry(
        ip=match.group("ip"),
        timestamp=timestamp,
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        size=0 if size == "-" else int(size),
        referrer="" if referrer in (None, "-") else referrer,
        user_agent=match.group("agent") or "",
    )


def parse_lines(lines: Iterable[str]) -> ParseResult:
    """Parse many lines. Blank lines are ignored; bad lines are counted."""
    result = ParseResult()
    for raw in lines:
        if not raw.strip():
            continue
        entry = parse_line(raw)
        if entry is None:
            result.malformed += 1
        else:
            result.entries.append(entry)
    return result
