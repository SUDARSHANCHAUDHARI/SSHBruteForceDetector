"""Detection rules for SSH brute-force behavior."""

from __future__ import annotations

from collections import Counter, defaultdict

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def detect_bruteforce(events: list[dict], threshold: int = 3) -> list[dict]:
    """Detect repeated failed login attempts by source IP."""
    failed_events = [event for event in events if event.get("event_type") == "failed_login"]
    counts = Counter(str(event["ip"]) for event in failed_events)
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    ports_by_ip: dict[str, set[int]] = defaultdict(set)
    times_by_ip: dict[str, list[int]] = defaultdict(list)
    for event in failed_events:
        ip = str(event["ip"])
        users_by_ip[ip].add(str(event.get("user", "unknown")))
        ports_by_ip[ip].add(int(event.get("port", 0)))
        times_by_ip[ip].append(int(event.get("timestamp_seconds", 0)))

    findings: list[dict] = []
    for ip, count in counts.items():
        if count < threshold:
            continue
        window_seconds = max(times_by_ip[ip]) - min(times_by_ip[ip]) if times_by_ip[ip] else 0
        severity = "critical" if count >= threshold * 2 or window_seconds <= 60 else "high"
        findings.append(
            {
                "kind": "ssh.bruteforce",
                "severity": severity,
                "summary": "Repeated failed SSH logins from one IP.",
                "evidence": {
                    "ip": ip,
                    "failed_attempts": count,
                    "users": sorted(users_by_ip[ip]),
                    "ports": sorted(ports_by_ip[ip]),
                    "window_seconds": window_seconds,
                },
            }
        )

    successful_by_ip = [event for event in events if event.get("event_type") == "successful_login"]
    for success in successful_by_ip:
        ip = str(success.get("ip"))
        if ip not in counts:
            continue
        last_failure = max(times_by_ip[ip]) if times_by_ip[ip] else 0
        success_time = int(success.get("timestamp_seconds", 0))
        if counts[ip] >= threshold and 0 <= success_time - last_failure <= 900:
            findings.append(
                {
                    "kind": "ssh.success_after_failures",
                    "severity": "critical",
                    "summary": "Successful SSH login followed repeated failures from the same IP.",
                    "evidence": {
                        "ip": ip,
                        "successful_user": success.get("user"),
                        "failed_attempts": counts[ip],
                        "minutes_after_last_failure": round((success_time - last_failure) / 60, 2),
                    },
                }
            )

    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER.get(str(item.get("severity")), 0),
            -int(item.get("evidence", {}).get("failed_attempts", 0)),
        ),
    )


def build_summary(events: list[dict], findings: list[dict]) -> dict:
    """Return dashboard-friendly summary statistics."""
    failed = [event for event in events if event.get("event_type") == "failed_login"]
    successful = [event for event in events if event.get("event_type") == "successful_login"]
    top_ips = Counter(str(event["ip"]) for event in failed).most_common(5)
    by_severity = Counter(str(finding["severity"]) for finding in findings)
    unique_users = sorted({str(event.get("user")) for event in failed if event.get("user")})
    return {
        "total_events": len(events),
        "failed_logins": len(failed),
        "successful_logins": len(successful),
        "alerts": len(findings),
        "unique_failed_users": unique_users,
        "by_severity": dict(by_severity),
        "highest_severity": max((str(finding["severity"]) for finding in findings), key=lambda item: SEVERITY_ORDER.get(item, 0), default="none"),
        "top_failed_ips": [{"ip": ip, "failures": count} for ip, count in top_ips],
    }


def build_ip_timeline(events: list[dict]) -> list[dict]:
    """Return compact per-IP timeline rows."""
    rows = []
    for ip in sorted({str(event.get("ip")) for event in events if event.get("ip")}):
        ip_events = [event for event in events if str(event.get("ip")) == ip]
        rows.append(
            {
                "ip": ip,
                "first_seen": min(event["timestamp"] for event in ip_events),
                "last_seen": max(event["timestamp"] for event in ip_events),
                "failed_logins": sum(1 for event in ip_events if event.get("event_type") == "failed_login"),
                "successful_logins": sum(1 for event in ip_events if event.get("event_type") == "successful_login"),
                "users": sorted({str(event.get("user")) for event in ip_events if event.get("user")}),
            }
        )
    return rows
