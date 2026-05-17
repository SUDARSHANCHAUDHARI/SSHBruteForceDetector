"""Rule tests for SSH Brute-Force Detection."""

from __future__ import annotations

import unittest
from pathlib import Path

from detector.alert import format_alerts
from detector.parser import parse_auth_file
from detector.rules import build_summary, detect_bruteforce


ROOT = Path(__file__).resolve().parents[1]


class RuleTests(unittest.TestCase):
    def test_detects_bruteforce_above_threshold(self) -> None:
        events = parse_auth_file(ROOT / "data/sample-auth.log")

        findings = detect_bruteforce(events, threshold=3)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["ip"], "198.51.100.22")

    def test_builds_dashboard_summary_and_alert(self) -> None:
        events = parse_auth_file(ROOT / "data/sample-auth.log")
        findings = detect_bruteforce(events, threshold=3)
        summary = build_summary(events, findings)
        alerts = format_alerts(findings)

        self.assertEqual(summary["failed_logins"], 5)
        self.assertEqual(summary["alerts"], 1)
        self.assertIn("198.51.100.22", alerts[0])


if __name__ == "__main__":
    unittest.main()
