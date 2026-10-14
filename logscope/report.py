"""Turn analysis results into human-readable text or JSON."""

from __future__ import annotations

import json
from typing import List, Sequence, Tuple

from .analyzer import Summary, SuspiciousIP

BAR_WIDTH = 30
TIME_DISPLAY = "%Y-%m-%d %H:%M:%S %z"


def _human_bytes(count: int) -> str:
    """Format a byte count such as ``1536`` as ``1.5 KB``."""
    size = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _table(title: str, rows: Sequence[Tuple[str, int]]) -> List[str]:
    """Render ``(label, count)`` rows as an aligned block with a heading."""
    width = max((len(label) for label, _ in rows), default=0)
    lines = ["", title]
    lines.extend(f"  {label:<{width}}  {count:>7,}" for label, count in rows)
    return lines


def _bar(value: int, maximum: int) -> str:
    """Scale ``value`` to a bar of '#' characters (ASCII keeps every terminal happy)."""
    if value <= 0 or maximum <= 0:
        return ""
    return "#" * max(1, round(value / maximum * BAR_WIDTH))


def format_text(summary: Summary, malformed: int = 0) -> str:
    """Render a summary as a plain-text report."""
    lines = ["LogScope report", "=" * 40]

    if summary.total_requests == 0:
        lines.append("No matching requests.")
        if malformed:
            lines.append(f"Skipped {malformed:,} malformed line(s).")
        return "\n".join(lines)

    lines.extend(
        [
            f"Requests:    {summary.total_requests:,}",
            f"Unique IPs:  {summary.unique_ips:,}",
            f"Data served: {_human_bytes(summary.total_bytes)}",
            f"Error rate:  {summary.error_rate:.2f}% (4xx and 5xx)",
        ]
    )
    if summary.first_seen and summary.last_seen:
        lines.extend(
            [
                f"From:        {summary.first_seen.strftime(TIME_DISPLAY)}",
                f"To:          {summary.last_seen.strftime(TIME_DISPLAY)}",
            ]
        )
    if malformed:
        lines.append(f"Skipped:     {malformed:,} malformed line(s)")

    lines.extend(_table("Status classes", list(summary.status_classes.items())))
    lines.extend(_table("HTTP methods", list(summary.methods.items())))
    lines.extend(_table("Top paths", summary.top_paths))
    lines.extend(_table("Top clients", summary.top_ips))

    peak = max(summary.requests_per_hour.values(), default=0)
    lines.extend(["", "Requests per hour (UTC)"])
    for hour, count in summary.requests_per_hour.items():
        lines.append(f"  {hour}  {count:>5,}  {_bar(count, peak)}")

    if summary.busiest_hour:
        hour, count = summary.busiest_hour
        lines.extend(["", f"Busiest hour: {hour} UTC with {count:,} requests"])

    return "\n".join(lines)


def format_json(summary: Summary, malformed: int = 0) -> str:
    """Render a summary as pretty-printed JSON."""
    payload = summary.to_dict()
    payload["malformed_lines"] = malformed
    return json.dumps(payload, indent=2)


def format_suspicious(
    rows: Sequence[SuspiciousIP], min_errors: int, min_ratio: float = 0.5
) -> str:
    """Render the suspicious-client report."""
    criteria = f"{min_errors:,}+ 4xx responses making up {min_ratio:.0%}+ of requests"
    if not rows:
        return f"No suspicious clients found ({criteria})."

    header = f"{'IP address':<18}{'4xx':>7}{'Requests':>10}{'4xx share':>11}{'Paths':>7}"
    lines = [f"Suspicious clients ({criteria})", header, "-" * len(header)]
    for row in rows:
        lines.append(
            f"{row.ip:<18}{row.client_errors:>7,}{row.total_requests:>10,}"
            f"{row.error_ratio * 100:>10.1f}%{row.distinct_error_paths:>7,}"
        )
    return "\n".join(lines)
