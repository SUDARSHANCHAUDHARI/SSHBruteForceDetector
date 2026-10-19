"""Parser tests for SSH Brute-Force Detection."""

from __future__ import annotations

import unittest
from pathlib import Path

from detector.parser import parse_auth_file, parse_auth_log, timestamp_to_seconds


ROOT = Path(__file__).resolve().parents[1]


class ParserTests(unittest.TestCase):
    def test_parses_failed_and_successful_logins(self) -> None:
        events = parse_auth_file(ROOT / "data/sample-auth.log")

        failed = [event for event in events if event["event_type"] == "failed_login"]
        successful = [event for event in events if event["event_type"] == "successful_login"]

        self.assertEqual(len(failed), 5)
        self.assertEqual(len(successful), 2)
        self.assertEqual(failed[0]["ip"], "198.51.100.22")
        self.assertIn("timestamp_seconds", failed[0])

    def test_gap_across_month_boundary(self) -> None:
        gap = timestamp_to_seconds("May 1 00:05:00", 2026) - timestamp_to_seconds("Apr 30 23:50:00", 2026)

        self.assertEqual(gap, 900)

    def test_year_rolls_over_from_december_to_january(self) -> None:
        log = (
            "Dec 31 23:55:00 host sshd[1]: Failed password for root from 203.0.113.5 port 2201 ssh2\n"
            "Jan  1 00:05:00 host sshd[2]: Accepted password for root from 203.0.113.5 port 2202 ssh2\n"
        )

        failed, accepted = parse_auth_log(log, year=2025)

        self.assertEqual(accepted["timestamp_seconds"] - failed["timestamp_seconds"], 600)

    def test_feb_29_in_non_leap_year_uses_latest_leap_year(self) -> None:
        gap = timestamp_to_seconds("Mar 1 00:00:10", 2024) - timestamp_to_seconds("Feb 29 23:59:50", 2026)

        self.assertEqual(gap, 20)


if __name__ == "__main__":
    unittest.main()
