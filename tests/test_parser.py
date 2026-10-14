import unittest
from datetime import datetime, timedelta, timezone

from logscope.parser import parse_line, parse_lines

COMBINED = (
    '198.51.100.10 - - [01/Oct/2026:08:00:05 +0000] "GET /products?id=3 HTTP/1.1" '
    '200 5120 "https://example.com/" "Mozilla/5.0"'
)
COMMON = '10.0.0.1 - - [01/Oct/2026:08:00:05 +0100] "GET / HTTP/1.0" 304 -'


class ParseLineTests(unittest.TestCase):
    def test_combined_format_fields(self):
        entry = parse_line(COMBINED)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "198.51.100.10")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/products?id=3")
        self.assertEqual(entry.route, "/products")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 5120)
        self.assertEqual(entry.referrer, "https://example.com/")
        self.assertEqual(entry.user_agent, "Mozilla/5.0")
        self.assertEqual(
            entry.timestamp, datetime(2026, 10, 1, 8, 0, 5, tzinfo=timezone.utc)
        )

    def test_common_format_has_no_referrer_or_agent(self):
        entry = parse_line(COMMON)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.size, 0)
        self.assertEqual(entry.referrer, "")
        self.assertEqual(entry.user_agent, "")
        self.assertEqual(entry.timestamp.utcoffset(), timedelta(hours=1))

    def test_dash_referrer_becomes_empty_string(self):
        entry = parse_line(COMBINED.replace('"https://example.com/"', '"-"'))
        self.assertEqual(entry.referrer, "")

    def test_surrounding_whitespace_is_ignored(self):
        self.assertIsNotNone(parse_line("  " + COMBINED + "\n"))

    def test_malformed_lines_return_none(self):
        bad_lines = [
            "",
            "garbage",
            '1.2.3.4 - - [bad] "GET / HTTP/1.1" 200 1',
            '1.2.3.4 - - [01/Oct/2026:08:00:05 +0000] "GET / HTTP/1.1" 20 1',
        ]
        for line in bad_lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))

    def test_impossible_timestamp_returns_none(self):
        line = COMBINED.replace("01/Oct/2026", "99/Foo/2026")
        self.assertIsNone(parse_line(line))

    def test_error_flags(self):
        not_found = parse_line(COMBINED.replace(" 200 ", " 404 "))
        server_error = parse_line(COMBINED.replace(" 200 ", " 500 "))
        ok = parse_line(COMBINED)
        self.assertFalse(ok.is_error)
        self.assertTrue(not_found.is_error)
        self.assertFalse(not_found.is_server_error)
        self.assertTrue(server_error.is_error)
        self.assertTrue(server_error.is_server_error)


class ParseLinesTests(unittest.TestCase):
    def test_counts_good_and_malformed_and_skips_blanks(self):
        result = parse_lines([COMBINED, "", "   ", "garbage", COMMON])
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.malformed, 1)
        self.assertEqual(result.total_lines, 3)

    def test_empty_input(self):
        result = parse_lines([])
        self.assertEqual(result.entries, [])
        self.assertEqual(result.malformed, 0)


if __name__ == "__main__":
    unittest.main()
