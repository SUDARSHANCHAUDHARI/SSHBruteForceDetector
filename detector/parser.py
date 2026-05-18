"""Parse Linux auth logs for SSH login events."""

from __future__ import annotations

import re
from pathlib import Path


MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}
FAILED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Failed password for(?: invalid user)? "
    r"(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Accepted password for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
)


def timestamp_to_seconds(timestamp: str) -> int:
    """Return rough seconds from auth-log timestamp for same-year ordering."""
    month, day, clock = timestamp.split()
    hour, minute, second = [int(part) for part in clock.split(":")]
    return (((MONTHS.get(month, 1) * 31 + int(day)) * 24 + hour) * 60 + minute) * 60 + second


def parse_auth_log(text: str) -> list[dict]:
    """Return normalized SSH login events from auth log text."""
    events: list[dict] = []
    for line in text.splitlines():
        failed = FAILED_RE.search(line)
        if failed:
            events.append(
                {
                    "event_type": "failed_login",
                    "timestamp": failed.group("timestamp"),
                    "user": failed.group("user"),
                    "ip": failed.group("ip"),
                    "port": int(failed.group("port")),
                    "timestamp_seconds": timestamp_to_seconds(failed.group("timestamp")),
                    "raw": line,
                }
            )
            continue
        accepted = ACCEPTED_RE.search(line)
        if accepted:
            events.append(
                {
                    "event_type": "successful_login",
                    "timestamp": accepted.group("timestamp"),
                    "user": accepted.group("user"),
                    "ip": accepted.group("ip"),
                    "port": int(accepted.group("port")),
                    "timestamp_seconds": timestamp_to_seconds(accepted.group("timestamp")),
                    "raw": line,
                }
            )
    return events


def parse_auth_file(path: Path) -> list[dict]:
    """Parse a Linux auth log file."""
    return parse_auth_log(path.read_text(encoding="utf-8", errors="replace"))
