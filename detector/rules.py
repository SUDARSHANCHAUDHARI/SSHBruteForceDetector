"""Detection rules for SSH brute-force behavior."""

from __future__ import annotations

from collections import Counter, defaultdict


def detect_bruteforce(events: list[dict], threshold: int = 3) -> list[dict]:
    """Detect repeated failed login attempts by source IP."""
    failed_events = [event for event in events if event.get("event_type") == "failed_login"]
    counts = Counter(str(event["ip"]) for event in failed_events)
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    ports_by_ip: dict[str, set[int]] = defaultdict(set)
    for event in failed_events:
        ip = str(event["ip"])
        users_by_ip[ip].add(str(event.get("user", "unknown")))
        ports_by_ip[ip].add(int(event.get("port", 0)))

    findings: list[dict] = []
    for ip, count in counts.items():
        if count < threshold:
            continue
        severity = "critical" if count >= threshold * 2 else "high"
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
                },
            }
        )
    return sorted(findings, key=lambda item: item["evidence"]["failed_attempts"], reverse=True)


def build_summary(events: list[dict], findings: list[dict]) -> dict:
    """Return dashboard-friendly summary statistics."""
    failed = [event for event in events if event.get("event_type") == "failed_login"]
    successful = [event for event in events if event.get("event_type") == "successful_login"]
    top_ips = Counter(str(event["ip"]) for event in failed).most_common(5)
    return {
        "total_events": len(events),
        "failed_logins": len(failed),
        "successful_logins": len(successful),
        "alerts": len(findings),
        "top_failed_ips": [{"ip": ip, "failures": count} for ip, count in top_ips],
    }
