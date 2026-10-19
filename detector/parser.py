"""Parse Linux auth logs for SSH login events."""

from __future__ import annotations

import calendar
import re
from datetime import datetime
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


def timestamp_to_seconds(timestamp: str, year: int | None = None) -> int:
    """Return epoch seconds for a year-less auth-log timestamp (default: current year)."""
    month, day, clock = timestamp.split()
    hour, minute, second = [int(part) for part in clock.split(":")]
    year = year or datetime.now().year
    if month == "Feb" and int(day) == 29:
        # Feb 29 only exists in a leap year, so the line is from the latest one.
        while not calendar.isleap(year):
            year -= 1
    when = datetime(year, MONTHS.get(month, 1), int(day), hour, minute, second)
    return calendar.timegm(when.timetuple())


def parse_auth_log(text: str, year: int | None = None) -> list[dict]:
    """Return normalized SSH login events from auth log text.

    Auth-log timestamps have no year. Events start in `year` (default: current year),
    and the year moves on whenever the month goes backwards (Dec -> Jan).
    """
    year = year or datetime.now().year
    last_month = 0
    events: list[dict] = []
    for line in text.splitlines():
        failed = FAILED_RE.search(line)
        match = failed or ACCEPTED_RE.search(line)
        if match:
            month = MONTHS.get(match.group("timestamp").split()[0], 1)
            if month < last_month:
                year += 1
            last_month = month
        if failed:
            events.append(
                {
                    "event_type": "failed_login",
                    "timestamp": failed.group("timestamp"),
                    "user": failed.group("user"),
                    "ip": failed.group("ip"),
                    "port": int(failed.group("port")),
                    "timestamp_seconds": timestamp_to_seconds(failed.group("timestamp"), year),
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
                    "timestamp_seconds": timestamp_to_seconds(accepted.group("timestamp"), year),
                    "raw": line,
                }
            )
    return events


def parse_auth_file(path: Path) -> list[dict]:
    """Parse a Linux auth log file."""
    return parse_auth_log(path.read_text(encoding="utf-8", errors="replace"))
