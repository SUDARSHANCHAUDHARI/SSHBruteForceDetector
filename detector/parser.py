"""Parse Linux auth logs for SSH login events."""

from __future__ import annotations

import re
from pathlib import Path


FAILED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Failed password for(?: invalid user)? "
    r"(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Accepted password for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
)


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
                    "raw": line,
                }
            )
    return events


def parse_auth_file(path: Path) -> list[dict]:
    """Parse a Linux auth log file."""
    return parse_auth_log(path.read_text(encoding="utf-8", errors="replace"))
