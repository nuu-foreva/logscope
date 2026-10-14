"""Statistics, filtering and anomaly detection over parsed log entries."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .parser import LogEntry


@dataclass(frozen=True)
class Summary:
    """Aggregate statistics for a set of log entries."""

    total_requests: int
    unique_ips: int
    total_bytes: int
    error_rate: float  # percentage of 4xx/5xx responses, 0-100
    methods: Dict[str, int]
    status_classes: Dict[str, int]
    top_paths: List[Tuple[str, int]]
    top_ips: List[Tuple[str, int]]
    requests_per_hour: Dict[str, int]  # keys are UTC hours, "YYYY-MM-DD HH:00"
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    busiest_hour: Optional[Tuple[str, int]]

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "total_requests": self.total_requests,
            "unique_ips": self.unique_ips,
            "total_bytes": self.total_bytes,
            "error_rate": self.error_rate,
            "methods": self.methods,
            "status_classes": self.status_classes,
            "top_paths": [{"path": p, "count": c} for p, c in self.top_paths],
            "top_ips": [{"ip": ip, "count": c} for ip, c in self.top_ips],
            "requests_per_hour": self.requests_per_hour,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "busiest_hour": (
                {"hour": self.busiest_hour[0], "count": self.busiest_hour[1]}
                if self.busiest_hour
                else None
            ),
        }


@dataclass(frozen=True)
class SuspiciousIP:
    """A client whose traffic looks like scanning or brute-forcing."""

    ip: str
    client_errors: int
    total_requests: int
    distinct_error_paths: int

    @property
    def error_ratio(self) -> float:
        """Fraction of this client's requests that were 4xx responses."""
        return self.client_errors / self.total_requests


def _top(counter: Counter, limit: int) -> List[Tuple[str, int]]:
    """Return the ``limit`` most common items, breaking ties alphabetically."""
    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return ranked[:limit]


def analyze(entries: Iterable[LogEntry], top_n: int = 5) -> Summary:
    """Compute a :class:`Summary` for the given entries."""
    if top_n < 1:
        raise ValueError("top_n must be at least 1")

    items = list(entries)
    if not items:
        return Summary(
            total_requests=0,
            unique_ips=0,
            total_bytes=0,
            error_rate=0.0,
            methods={},
            status_classes={},
            top_paths=[],
            top_ips=[],
            requests_per_hour={},
            first_seen=None,
            last_seen=None,
            busiest_hour=None,
        )

    methods = Counter(entry.method for entry in items)
    classes = Counter(f"{entry.status // 100}xx" for entry in items)
    paths = Counter(entry.route for entry in items)
    ips = Counter(entry.ip for entry in items)
    hours = Counter(
        entry.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:00")
        for entry in items
    )

    errors = sum(1 for entry in items if entry.is_error)
    ordered_hours = dict(sorted(hours.items()))
    # max() keeps the first maximum it sees, so ties go to the earliest hour.
    busiest = max(ordered_hours.items(), key=lambda pair: pair[1])

    return Summary(
        total_requests=len(items),
        unique_ips=len(ips),
        total_bytes=sum(entry.size for entry in items),
        error_rate=round(errors / len(items) * 100, 2),
        methods=dict(_top(methods, len(methods))),
        status_classes=dict(sorted(classes.items())),
        top_paths=_top(paths, top_n),
        top_ips=_top(ips, top_n),
        requests_per_hour=ordered_hours,
        first_seen=min(entry.timestamp for entry in items),
        last_seen=max(entry.timestamp for entry in items),
        busiest_hour=busiest,
    )


def status_matches(code: int, spec: str) -> bool:
    """Check a status code against ``"404"`` or a class such as ``"4xx"``."""
    spec = spec.strip().lower()
    if len(spec) == 3 and spec.endswith("xx"):
        return str(code // 100) == spec[0]
    return str(code) == spec


def _as_aware(value: datetime) -> datetime:
    """Treat naive datetimes as UTC so they can be compared with log times."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def filter_entries(
    entries: Iterable[LogEntry],
    *,
    status: Optional[str] = None,
    method: Optional[str] = None,
    ip: Optional[str] = None,
    path_contains: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
) -> List[LogEntry]:
    """Return only the entries that match every filter that was supplied."""
    since_dt = _as_aware(since) if since is not None else None
    until_dt = _as_aware(until) if until is not None else None
    wanted_method = method.upper() if method else None

    matched: List[LogEntry] = []
    for entry in entries:
        if status is not None and not status_matches(entry.status, status):
            continue
        if wanted_method and entry.method != wanted_method:
            continue
        if ip and entry.ip != ip:
            continue
        if path_contains and path_contains not in entry.path:
            continue
        if since_dt is not None and entry.timestamp < since_dt:
            continue
        if until_dt is not None and entry.timestamp > until_dt:
            continue
        matched.append(entry)
    return matched


def find_suspicious_ips(
    entries: Iterable[LogEntry], min_errors: int = 10, min_ratio: float = 0.5
) -> List[SuspiciousIP]:
    """Flag clients that look like scanners or brute-forcers.

    A client is flagged when it has at least ``min_errors`` 4xx responses
    *and* at least ``min_ratio`` (0-1) of its requests were 4xx. Requiring
    both stops busy, legitimate visitors from being flagged just because they
    hit a few broken links among thousands of good requests.
    """
    if min_errors < 1:
        raise ValueError("min_errors must be at least 1")
    if not 0 <= min_ratio <= 1:
        raise ValueError("min_ratio must be between 0 and 1")

    totals: Counter = Counter()
    client_errors: Counter = Counter()
    error_paths: Dict[str, Set[str]] = defaultdict(set)

    for entry in entries:
        totals[entry.ip] += 1
        if 400 <= entry.status < 500:
            client_errors[entry.ip] += 1
            error_paths[entry.ip].add(entry.route)

    flagged = [
        SuspiciousIP(
            ip=ip,
            client_errors=count,
            total_requests=totals[ip],
            distinct_error_paths=len(error_paths[ip]),
        )
        for ip, count in client_errors.items()
        if count >= min_errors and count / totals[ip] >= min_ratio
    ]
    flagged.sort(key=lambda row: (-row.client_errors, row.ip))
    return flagged
