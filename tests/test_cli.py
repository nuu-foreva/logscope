import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from logscope import __version__
from logscope.cli import main
from logscope.parser import parse_lines
from logscope.sample import generate_sample_lines

LINE = (
    '198.51.100.10 - - [01/Oct/2026:08:00:05 +0000] "GET / HTTP/1.1" 200 512 '
    '"-" "Mozilla/5.0"'
)


def run(*argv):
    """Run the CLI and return ``(exit_code, stdout, stderr)``."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.log = Path(tmp.name) / "nested" / "access.log"
        code, _, _ = run("generate", str(self.log), "--lines", "500", "--seed", "7")
        self.assertEqual(code, 0)

    def test_generate_creates_parent_folders_and_file(self):
        self.assertTrue(self.log.is_file())
        self.assertEqual(len(self.log.read_text(encoding="utf-8").splitlines()), 500)

    def test_summary_json(self):
        code, out, _ = run("summary", str(self.log), "--format", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["total_requests"], 495)  # 5 of 500 lines are malformed
        self.assertEqual(data["malformed_lines"], 5)
        self.assertEqual(len(data["top_paths"]), 5)

    def test_summary_text_and_top_option(self):
        code, out, _ = run("summary", str(self.log), "--top", "2")
        self.assertEqual(code, 0)
        self.assertIn("LogScope report", out)
        self.assertIn("Requests:    495", out)
        self.assertIn("Busiest hour", out)

    def test_filters_reduce_the_result(self):
        code, out, _ = run(
            "summary", str(self.log), "--format", "json", "--method", "post"
        )
        self.assertEqual(code, 0)
        total = json.loads(out)["total_requests"]
        self.assertTrue(0 < total < 495)

    def test_no_matches_prints_friendly_message(self):
        code, out, _ = run("summary", str(self.log), "--ip", "10.10.10.10")
        self.assertEqual(code, 0)
        self.assertIn("No matching requests.", out)

    def test_suspicious_finds_only_the_scanner(self):
        code, out, _ = run("suspicious", str(self.log))
        self.assertEqual(code, 0)
        self.assertIn("203.0.113.66", out)
        self.assertNotIn("198.51.100.", out)  # ordinary visitors are not flagged

    def test_suspicious_with_high_threshold_finds_nothing(self):
        code, out, _ = run("suspicious", str(self.log), "--min-errors", "1000")
        self.assertEqual(code, 0)
        self.assertIn("No suspicious clients found", out)

    def test_suspicious_min_ratio_zero_flags_more_clients(self):
        code, out, _ = run(
            "suspicious", str(self.log), "--min-errors", "3", "--min-ratio", "0"
        )
        self.assertEqual(code, 0)
        self.assertIn("198.51.100.", out)

    def test_undecodable_bytes_on_stdin_do_not_crash(self):
        proc = subprocess.run(
            [sys.executable, "-m", "logscope", "summary", "-"],
            input=b"\xff\xfe not a log line\n" + LINE.encode() + b"\n",
            capture_output=True,
            cwd=Path(__file__).resolve().parent.parent,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertIn(b"Requests:    1", proc.stdout)
        self.assertIn(b"1 malformed", proc.stdout)

    def test_reads_from_standard_input(self):
        with mock.patch("sys.stdin", io.StringIO(LINE + "\n")):
            code, out, _ = run("summary", "-", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["total_requests"], 1)

    def test_missing_file_gives_exit_code_2(self):
        code, out, err = run("summary", str(self.log.parent / "nope.log"))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("error:", err)

    def test_directory_instead_of_file_gives_exit_code_2(self):
        code, _, err = run("summary", str(self.log.parent))
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_invalid_arguments_are_rejected(self):
        bad_invocations = [
            ("summary", str(self.log), "--status", "999"),
            ("summary", str(self.log), "--top", "0"),
            ("summary", str(self.log), "--since", "yesterday-ish"),
            ("suspicious", str(self.log), "--min-ratio", "1.5"),
            ("suspicious", str(self.log), "--min-ratio", "lots"),
            ("generate", str(self.log), "--lines", "-3"),
            (),
        ]
        for argv in bad_invocations:
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit) as ctx:
                    run(*argv)
                self.assertEqual(ctx.exception.code, 2)

    def test_version_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(__version__, out.getvalue())


class SampleGeneratorTests(unittest.TestCase):
    def test_same_seed_gives_same_output(self):
        self.assertEqual(generate_sample_lines(120, 1), generate_sample_lines(120, 1))
        self.assertNotEqual(generate_sample_lines(120, 1), generate_sample_lines(120, 2))

    def test_exactly_requested_number_of_lines(self):
        self.assertEqual(len(generate_sample_lines(1)), 1)
        self.assertEqual(len(generate_sample_lines(250)), 250)

    def test_only_every_hundredth_line_is_malformed(self):
        result = parse_lines(generate_sample_lines(250))
        self.assertEqual(result.malformed, 2)
        self.assertEqual(len(result.entries), 248)

    def test_invalid_count(self):
        with self.assertRaises(ValueError):
            generate_sample_lines(0)


if __name__ == "__main__":
    unittest.main()
