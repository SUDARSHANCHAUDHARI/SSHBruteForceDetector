"""CLI dashboard for SSH brute-force detection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detector.alert import format_alerts
from detector.parser import parse_auth_file
from detector.rules import build_ip_timeline, build_summary, detect_bruteforce

NEXT_STEPS = {
    "ssh.bruteforce": "Block or rate-limit the source IP, confirm no successful login followed, and review targeted usernames.",
    "ssh.success_after_failures": "Treat as possible compromise until the login is confirmed legitimate; preserve logs and review session activity.",
}


def build_markdown(summary: dict, findings: list[dict], alerts: list[str]) -> str:
    """Return a simple Markdown dashboard report."""
    lines = [
        "# SSH Brute-Force Detection Report",
        "",
        "## Summary",
        "",
        f"- Total events: {summary['total_events']}",
        f"- Failed logins: {summary['failed_logins']}",
        f"- Successful logins: {summary['successful_logins']}",
        f"- Alerts: {summary['alerts']}",
        f"- Highest severity: `{summary['highest_severity']}`",
        f"- Unique failed users: {', '.join(summary['unique_failed_users'])}",
        "",
        "## Top Failed IPs",
        "",
    ]
    for item in summary["top_failed_ips"]:
        lines.append(f"- `{item['ip']}`: {item['failures']} failures")
    lines.extend(["", "## Alerts", ""])
    if not alerts:
        lines.append("No brute-force alerts detected.")
    else:
        lines.extend([f"- {alert}" for alert in alerts])
    lines.extend(["", "## Findings", ""])
    for finding in findings:
        kind = str(finding["kind"])
        lines.extend(
            [
                f"### {finding['summary']}",
                "",
                f"- Severity: `{finding['severity']}`",
                f"- Type: `{kind}`",
                f"- Evidence: `{finding['evidence']}`",
                f"- Recommended next step: {NEXT_STEPS.get(kind, 'Review this finding with the source auth log.')}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def build_triage_markdown(summary: dict, timeline: list[dict], findings: list[dict]) -> str:
    """Return a compact triage handoff report."""
    lines = [
        "# SSH Brute-Force Triage",
        "",
        f"- Failed logins: {summary['failed_logins']}",
        f"- Successful logins: {summary['successful_logins']}",
        f"- Alerts: {summary['alerts']}",
        "",
        "## IP Timeline",
        "",
    ]
    for row in timeline:
        lines.append(
            f"- `{row['ip']}`: {row['failed_logins']} failed, {row['successful_logins']} successful, users={', '.join(row['users'])}"
        )
    lines.extend(["", "## Analyst Queue", ""])
    if not findings:
        lines.append("- No immediate analyst queue was generated.")
    for finding in findings:
        lines.append(f"- `{finding['severity']}` {finding['kind']}: {finding['summary']}")
    return "\n".join(lines).rstrip() + "\n"


def analyze(path: Path, threshold: int, out_dir: Path) -> dict:
    """Analyze auth logs and write report artifacts."""
    events = parse_auth_file(path)
    findings = detect_bruteforce(events, threshold=threshold)
    alerts = format_alerts(findings)
    summary = build_summary(events, findings)
    timeline = build_ip_timeline(events)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "events.json").write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "ip-timeline.json").write_text(json.dumps(timeline, indent=2) + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(build_markdown(summary, findings, alerts), encoding="utf-8")
    (out_dir / "triage.md").write_text(build_triage_markdown(summary, timeline, findings), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH brute-force detector")
    parser.add_argument("--log", type=Path, default=Path("data/sample-auth.log"))
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--out-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()
    summary = analyze(args.log, args.threshold, args.out_dir)
    print(f"Parsed {summary['total_events']} events")
    print(f"Generated {summary['alerts']} alert(s)")


if __name__ == "__main__":
    main()
