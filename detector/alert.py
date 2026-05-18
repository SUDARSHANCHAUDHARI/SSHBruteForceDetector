"""Alert formatting for SSH brute-force findings."""

from __future__ import annotations


def format_alert(finding: dict) -> str:
    """Return a concise operator alert."""
    evidence = finding.get("evidence", {})
    users = ", ".join(evidence.get("users", []))
    user_note = f" users={users}" if users else ""
    if evidence.get("successful_user"):
        user_note = f" successful_user={evidence['successful_user']}"
    return (
        f"[{finding.get('severity', 'unknown').upper()}] {finding.get('summary')} "
        f"ip={evidence.get('ip')} failures={evidence.get('failed_attempts')}{user_note}"
    )


def format_alerts(findings: list[dict]) -> list[str]:
    """Return formatted alerts for all findings."""
    return [format_alert(finding) for finding in findings]
