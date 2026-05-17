"""Parser tests for SSH Brute-Force Detection."""

from __future__ import annotations

import unittest
from pathlib import Path

from detector.parser import parse_auth_file


ROOT = Path(__file__).resolve().parents[1]


class ParserTests(unittest.TestCase):
    def test_parses_failed_and_successful_logins(self) -> None:
        events = parse_auth_file(ROOT / "data/sample-auth.log")

        failed = [event for event in events if event["event_type"] == "failed_login"]
        successful = [event for event in events if event["event_type"] == "successful_login"]

        self.assertEqual(len(failed), 5)
        self.assertEqual(len(successful), 1)
        self.assertEqual(failed[0]["ip"], "198.51.100.22")


if __name__ == "__main__":
    unittest.main()
