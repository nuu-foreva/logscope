# LogScope

[![CI](https://github.com/nuu-foreva/logscope/actions/workflows/ci.yml/badge.svg)](https://github.com/nuu-foreva/logscope/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

A command-line tool for analysing web-server access logs. It reads Apache and
Nginx logs (common and combined formats), prints traffic statistics, and spots
clients that behave like vulnerability scanners.

Built with only the Python standard library: no installs, no dependencies.

## Features

- **Traffic summary**: requests, unique clients, bytes served, error rate,
  status classes, HTTP methods, top paths, top clients and requests per hour.
- **Scanner detection**: flags clients that send many 4xx responses *and* whose
  traffic is mostly errors, so busy legitimate visitors are not flagged.
- **Filters**: by status (`404` or `4xx`), method, client IP, path text and
  time window.
- **Two output formats**: readable text or JSON for other tools.
- **Robust parsing**: malformed lines are counted and skipped, never fatal.
- **Reads stdin**: use `-` as the path to pipe logs in.
- **Sample data generator**: reproducible fake logs for demos and testing.

## Quick start

```bash
git clone https://github.com/nuu-foreva/logscope.git
cd logscope

python -m logscope summary examples/sample_access.log
python -m logscope suspicious examples/sample_access.log --min-errors 5
```

Or install it to get a `logscope` command:

```bash
pip install .
logscope summary examples/sample_access.log
```

## Usage

```text
logscope summary    PATH [filters] [--top N] [--format text|json]
logscope suspicious PATH [filters] [--min-errors N] [--min-ratio 0-1]
logscope generate   OUTPUT [--lines N] [--seed N]
```

Filters (available on `summary` and `suspicious`):

| Option | Meaning |
| --- | --- |
| `--status 404` / `--status 4xx` | exact status code or whole class |
| `--method POST` | HTTP method (case-insensitive) |
| `--ip 203.0.113.66` | only this client |
| `--contains /api` | only paths containing this text |
| `--since 2026-10-01T09:00` | on or after this ISO date/time (UTC if no zone given) |
| `--until 2026-10-01T10:00` | on or before this ISO date/time |

### Examples

```bash
# Server errors in a given window, as JSON
logscope summary access.log --status 5xx --since 2026-10-01 --format json

# Which API paths are people hitting?
logscope summary access.log --contains /api/ --top 10

# Read from another command
zcat access.log.gz | logscope summary -
```

### Sample output

```text
$ logscope summary examples/sample_access.log --top 3
LogScope report
========================================
Requests:    297
Unique IPs:  13
Data served: 6.7 MB
Error rate:  19.19% (4xx and 5xx)
From:        2026-10-01 08:00:41 +0000
To:          2026-10-01 10:27:19 +0000
Skipped:     3 malformed line(s)

Status classes
  2xx      213
  3xx       27
  4xx       49
  5xx        8

HTTP methods
  GET       279
  POST       18

Top paths
  /                    65
  /products            42
  /static/app.js       28

Top clients
  198.51.100.20       35
  198.51.100.14       31
  198.51.100.18       29
  ...
```

```text
$ logscope suspicious examples/sample_access.log --min-errors 5
Suspicious clients (5+ 4xx responses making up 50%+ of requests)
IP address            4xx  Requests  4xx share  Paths
-----------------------------------------------------
203.0.113.66           19        19     100.0%      6
```

Exit codes: `0` success, `2` for unreadable files or invalid arguments.

## How it works

```text
logscope/
  parser.py    regex parsing of log lines into immutable LogEntry objects
  analyzer.py  statistics, filtering and scanner detection (pure functions)
  report.py    text and JSON formatting
  sample.py    deterministic sample-log generator
  cli.py       argparse interface wiring it all together
tests/         48 unittest tests covering every module
```

Design notes:

- The analysis code never touches files or the terminal, so it is easy to test
  and reuse as a library.
- Hourly buckets are normalised to UTC, so logs from servers in different time
  zones line up.
- A client is "suspicious" only when it passes both an absolute threshold
  (`--min-errors`) and a proportion threshold (`--min-ratio`). Counting errors
  alone flagged ordinary visitors who happened to hit a few broken links.

### Use it as a library

```python
from logscope.parser import parse_lines
from logscope.analyzer import analyze

with open("access.log", encoding="utf-8", errors="replace") as handle:
    result = parse_lines(handle)

summary = analyze(result.entries)
print(summary.total_requests, summary.error_rate, summary.busiest_hour)
```

## Known limitations

- Only the common and combined log formats are supported; custom formats need
  a new pattern in `parser.py`.
- Requests that are not a normal `METHOD /path` line (for example some bad
  TLS or probe requests logged as `"-"`) are counted as malformed.
- Scanner detection is a heuristic based on 4xx behaviour. It will not catch
  slow scanners or those hiding behind a shared IP address.

## Development

```bash
python -m unittest -v
```

Requires Python 3.11 or newer. Tested on 3.11, 3.12 and 3.13.

## License

MIT. See [LICENSE](LICENSE).
