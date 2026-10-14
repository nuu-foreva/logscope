"""Command-line interface for LogScope."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .analyzer import analyze, filter_entries, find_suspicious_ips
from .parser import LogEntry, ParseResult, parse_lines
from .report import format_json, format_suspicious, format_text
from .sample import generate_sample_lines

STATUS_SPEC = re.compile(r"^[1-5](\d{2}|xx)$", re.IGNORECASE)


# --- argument type helpers -------------------------------------------------


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _status_spec(value: str) -> str:
    if not STATUS_SPEC.match(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not valid; use a code like 404 or a class like 4xx"
        )
    return value.lower()


def _ratio(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if not 0 <= number <= 1:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return number


def _datetime(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not an ISO date or time (e.g. 2026-10-01 or 2026-10-01T13:30)"
        ) from None


# --- helpers ---------------------------------------------------------------


def _load(path: str) -> ParseResult:
    """Read and parse a log file, or standard input when ``path`` is ``-``."""
    if path == "-":
        # Undecodable bytes must not crash the run; they become malformed lines.
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(errors="replace")
        return parse_lines(sys.stdin)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle)


def _filtered(entries: List[LogEntry], args: argparse.Namespace) -> List[LogEntry]:
    return filter_entries(
        entries,
        status=args.status,
        method=args.method,
        ip=args.ip,
        path_contains=args.contains,
        since=args.since,
        until=args.until,
    )


# --- command handlers ------------------------------------------------------


def _cmd_summary(args: argparse.Namespace) -> int:
    result = _load(args.path)
    summary = analyze(_filtered(result.entries, args), top_n=args.top)
    formatter = format_json if args.format == "json" else format_text
    print(formatter(summary, result.malformed))
    return 0


def _cmd_suspicious(args: argparse.Namespace) -> int:
    result = _load(args.path)
    rows = find_suspicious_ips(
        _filtered(result.entries, args), args.min_errors, args.min_ratio
    )
    print(format_suspicious(rows, args.min_errors, args.min_ratio))
    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    lines = generate_sample_lines(args.lines, args.seed)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines):,} lines to {output}")
    return 0


# --- parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    filters = argparse.ArgumentParser(add_help=False)
    group = filters.add_argument_group("filters")
    group.add_argument(
        "--status", type=_status_spec, help="status code (404) or class (4xx)"
    )
    group.add_argument("--method", help="HTTP method, e.g. GET or POST")
    group.add_argument("--ip", help="only requests from this client address")
    group.add_argument(
        "--contains", metavar="TEXT", help="only paths that contain TEXT"
    )
    group.add_argument(
        "--since", type=_datetime, metavar="WHEN", help="ISO date/time, UTC if no zone"
    )
    group.add_argument(
        "--until", type=_datetime, metavar="WHEN", help="ISO date/time, UTC if no zone"
    )

    parser = argparse.ArgumentParser(
        prog="logscope",
        description="Analyse web-server access logs (common and combined formats).",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    summary = commands.add_parser(
        "summary", parents=[filters], help="traffic statistics for a log file"
    )
    summary.add_argument("path", help="log file to read, or - for standard input")
    summary.add_argument(
        "--top", type=_positive_int, default=5, help="rows in top lists (default: 5)"
    )
    summary.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    summary.set_defaults(handler=_cmd_summary)

    suspicious = commands.add_parser(
        "suspicious", parents=[filters], help="find clients that look like scanners"
    )
    suspicious.add_argument("path", help="log file to read, or - for standard input")
    suspicious.add_argument(
        "--min-errors",
        type=_positive_int,
        default=10,
        help="minimum 4xx responses to flag a client (default: 10)",
    )
    suspicious.add_argument(
        "--min-ratio",
        type=_ratio,
        default=0.5,
        metavar="0-1",
        help="minimum share of a client's requests that are 4xx (default: 0.5)",
    )
    suspicious.set_defaults(handler=_cmd_suspicious)

    generate = commands.add_parser("generate", help="write a sample log file")
    generate.add_argument("output", help="where to write the sample log")
    generate.add_argument(
        "--lines", type=_positive_int, default=500, help="number of lines (default: 500)"
    )
    generate.add_argument(
        "--seed", type=int, default=42, help="random seed (default: 42)"
    )
    generate.set_defaults(handler=_cmd_generate)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
