"""Deterministic generator for realistic-looking sample access logs."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import List

START = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)

_SCANNER_IP = "203.0.113.66"
_VISITOR_IPS = [f"198.51.100.{n}" for n in range(10, 22)]

# (path, relative popularity)
_PAGES = [
    ("/", 30),
    ("/index.html", 15),
    ("/about", 8),
    ("/products", 14),
    ("/products/42", 9),
    ("/api/v1/users", 10),
    ("/api/v1/orders", 8),
    ("/login", 6),
    ("/static/app.js", 12),
    ("/static/style.css", 12),
    ("/missing-page", 3),
]
_POST_PATHS = {"/login", "/api/v1/orders"}
_PROBES = ["/wp-admin", "/.env", "/phpmyadmin", "/admin.php", "/.git/config", "/backup.zip"]

_STATUS_CODES = (200, 304, 301, 404, 500, 403)
_STATUS_WEIGHTS = (80, 8, 3, 5, 2, 1)

_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) Chrome/129.0 Mobile Safari/537.36",
]
_REFERRERS = ["-", "https://example.com/", "https://www.google.com/"]


def _pick_status(rng: random.Random, path: str) -> int:
    if path == "/missing-page":
        return 404
    return rng.choices(_STATUS_CODES, weights=_STATUS_WEIGHTS)[0]


def _pick_size(rng: random.Random, status: int) -> int:
    if status == 304:
        return 0
    if status in (403, 404):
        return rng.randint(150, 600)
    return rng.randint(300, 60_000)


def generate_sample_lines(count: int, seed: int = 42) -> List[str]:
    """Create ``count`` log lines in combined format.

    Every 15th request comes from a scanning client, and every 100th line is
    deliberately malformed so the parser's error handling has something to do.
    The same ``seed`` always produces the same output.
    """
    if count < 1:
        raise ValueError("count must be at least 1")

    rng = random.Random(seed)
    paths = [path for path, _ in _PAGES]
    weights = [weight for _, weight in _PAGES]

    moment = START
    lines: List[str] = []

    for index in range(count):
        if index % 100 == 99:
            lines.append("malformed entry - this line cannot be parsed")
            continue

        moment += timedelta(seconds=rng.randint(1, 60))

        if index % 15 == 14:
            ip = _SCANNER_IP
            method = "GET"
            path = rng.choice(_PROBES)
            status = rng.choice((403, 404))
            referrer = "-"
            agent = "python-requests/2.31.0"
        else:
            ip = rng.choice(_VISITOR_IPS)
            path = rng.choices(paths, weights=weights)[0]
            method = "POST" if path in _POST_PATHS and rng.random() < 0.6 else "GET"
            status = _pick_status(rng, path)
            referrer = rng.choice(_REFERRERS)
            agent = rng.choice(_AGENTS)

        size = _pick_size(rng, status)
        stamp = moment.strftime("%d/%b/%Y:%H:%M:%S %z")
        lines.append(
            f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} '
            f'"{referrer}" "{agent}"'
        )

    return lines
