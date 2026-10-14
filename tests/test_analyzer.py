import unittest
from datetime import datetime

from logscope.analyzer import (
    analyze,
    filter_entries,
    find_suspicious_ips,
    status_matches,
)
from logscope.parser import parse_line


def make_entry(ip, path, status, size=100, method="GET", hour=8, minute=0, zone="+0000"):
    line = (
        f'{ip} - - [01/Oct/2026:{hour:02d}:{minute:02d}:00 {zone}] '
        f'"{method} {path} HTTP/1.1" {status} {size} "-" "test-agent"'
    )
    entry = parse_line(line)
    assert entry is not None, line
    return entry


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.entries = [
            make_entry("1.1.1.1", "/a", 200, 100, minute=10),
            make_entry("1.1.1.1", "/a", 404, 50, minute=20),
            make_entry("2.2.2.2", "/b", 200, 150, method="POST", hour=9, minute=5),
            make_entry("2.2.2.2", "/a?x=1", 500, 0, hour=9, minute=30),
        ]

    def test_totals(self):
        summary = analyze(self.entries)
        self.assertEqual(summary.total_requests, 4)
        self.assertEqual(summary.unique_ips, 2)
        self.assertEqual(summary.total_bytes, 300)
        self.assertEqual(summary.error_rate, 50.0)

    def test_breakdowns(self):
        summary = analyze(self.entries)
        self.assertEqual(summary.status_classes, {"2xx": 2, "4xx": 1, "5xx": 1})
        self.assertEqual(summary.methods, {"GET": 3, "POST": 1})
        # Query strings are ignored when ranking paths.
        self.assertEqual(summary.top_paths, [("/a", 3), ("/b", 1)])
        self.assertEqual(summary.top_ips, [("1.1.1.1", 2), ("2.2.2.2", 2)])

    def test_hourly_buckets_and_busiest_hour_tie_goes_to_earliest(self):
        summary = analyze(self.entries)
        self.assertEqual(
            summary.requests_per_hour,
            {"2026-10-01 08:00": 2, "2026-10-01 09:00": 2},
        )
        self.assertEqual(summary.busiest_hour, ("2026-10-01 08:00", 2))

    def test_hours_are_normalised_to_utc(self):
        entry = make_entry("3.3.3.3", "/", 200, hour=9, minute=30, zone="+0100")
        summary = analyze([entry])
        self.assertEqual(summary.requests_per_hour, {"2026-10-01 08:00": 1})

    def test_top_n_limits_lists(self):
        summary = analyze(self.entries, top_n=1)
        self.assertEqual(summary.top_paths, [("/a", 3)])
        self.assertEqual(len(summary.top_ips), 1)

    def test_first_and_last_seen(self):
        summary = analyze(self.entries)
        self.assertEqual(summary.first_seen, self.entries[0].timestamp)
        self.assertEqual(summary.last_seen, self.entries[-1].timestamp)

    def test_empty_input(self):
        summary = analyze([])
        self.assertEqual(summary.total_requests, 0)
        self.assertEqual(summary.error_rate, 0.0)
        self.assertIsNone(summary.first_seen)
        self.assertIsNone(summary.busiest_hour)

    def test_invalid_top_n(self):
        with self.assertRaises(ValueError):
            analyze(self.entries, top_n=0)

    def test_to_dict_is_json_friendly(self):
        import json

        payload = analyze(self.entries).to_dict()
        json.dumps(payload)  # must not raise
        self.assertEqual(payload["busiest_hour"]["count"], 2)
        self.assertEqual(analyze([]).to_dict()["busiest_hour"], None)


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.entries = [
            make_entry("1.1.1.1", "/a", 200, minute=10),
            make_entry("1.1.1.1", "/a", 404, minute=20),
            make_entry("2.2.2.2", "/b", 200, method="POST", hour=9, minute=5),
            make_entry("2.2.2.2", "/a", 500, hour=9, minute=30),
        ]

    def test_status_exact_and_class(self):
        self.assertEqual(len(filter_entries(self.entries, status="404")), 1)
        self.assertEqual(len(filter_entries(self.entries, status="4xx")), 1)
        self.assertEqual(len(filter_entries(self.entries, status="5XX")), 1)
        self.assertEqual(len(filter_entries(self.entries, status="2xx")), 2)

    def test_method_is_case_insensitive(self):
        self.assertEqual(len(filter_entries(self.entries, method="post")), 1)

    def test_ip_and_path(self):
        self.assertEqual(len(filter_entries(self.entries, ip="1.1.1.1")), 2)
        self.assertEqual(len(filter_entries(self.entries, path_contains="/b")), 1)

    def test_time_window_with_naive_datetimes_is_treated_as_utc(self):
        since = filter_entries(self.entries, since=datetime(2026, 10, 1, 9, 0))
        until = filter_entries(self.entries, until=datetime(2026, 10, 1, 8, 20))
        self.assertEqual(len(since), 2)
        self.assertEqual(len(until), 2)  # the 08:20 entry is included

    def test_filters_combine(self):
        result = filter_entries(self.entries, ip="2.2.2.2", status="2xx")
        self.assertEqual([e.path for e in result], ["/b"])

    def test_no_filters_returns_everything(self):
        self.assertEqual(len(filter_entries(self.entries)), 4)

    def test_status_matches_helper(self):
        self.assertTrue(status_matches(404, "404"))
        self.assertTrue(status_matches(404, "4xx"))
        self.assertFalse(status_matches(404, "5xx"))
        self.assertFalse(status_matches(404, "400"))


class SuspiciousTests(unittest.TestCase):
    def test_flags_only_clients_over_threshold(self):
        entries = [
            make_entry("9.9.9.9", f"/probe{i % 3}", 404, minute=i) for i in range(12)
        ]
        entries += [make_entry("9.9.9.9", "/", 200, minute=i) for i in range(3)]
        entries += [make_entry("1.2.3.4", "/missing", 404)]
        entries += [make_entry("5.6.7.8", "/", 500) for _ in range(20)]

        flagged = find_suspicious_ips(entries, min_errors=10)

        self.assertEqual(len(flagged), 1)
        row = flagged[0]
        self.assertEqual(row.ip, "9.9.9.9")
        self.assertEqual(row.client_errors, 12)
        self.assertEqual(row.total_requests, 15)
        self.assertEqual(row.distinct_error_paths, 3)
        self.assertAlmostEqual(row.error_ratio, 0.8)

    def test_results_sorted_by_error_count(self):
        entries = [make_entry("1.1.1.1", "/x", 403) for _ in range(3)]
        entries += [make_entry("2.2.2.2", "/x", 403) for _ in range(5)]
        flagged = find_suspicious_ips(entries, min_errors=1)
        self.assertEqual([row.ip for row in flagged], ["2.2.2.2", "1.1.1.1"])

    def test_busy_legitimate_client_is_not_flagged_by_default(self):
        # 10 broken links among 100 requests: 10% errors, so not a scanner.
        entries = [make_entry("7.7.7.7", "/gone", 404, minute=i) for i in range(10)]
        entries += [make_entry("7.7.7.7", "/", 200, minute=i % 60) for i in range(90)]

        self.assertEqual(find_suspicious_ips(entries, min_errors=10), [])

        loose = find_suspicious_ips(entries, min_errors=10, min_ratio=0.1)
        self.assertEqual([row.ip for row in loose], ["7.7.7.7"])

    def test_5xx_responses_do_not_count_as_client_errors(self):
        entries = [make_entry("5.6.7.8", "/", 500) for _ in range(20)]
        self.assertEqual(find_suspicious_ips(entries, min_errors=1, min_ratio=0), [])

    def test_empty_input_and_invalid_thresholds(self):
        self.assertEqual(find_suspicious_ips([]), [])
        with self.assertRaises(ValueError):
            find_suspicious_ips([], min_errors=0)
        with self.assertRaises(ValueError):
            find_suspicious_ips([], min_ratio=1.5)
        with self.assertRaises(ValueError):
            find_suspicious_ips([], min_ratio=-0.1)


if __name__ == "__main__":
    unittest.main()
