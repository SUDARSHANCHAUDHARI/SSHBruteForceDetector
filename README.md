# SSH Brute-Force Detector

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-MVP-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

Linux auth log detector for repeated SSH failed-login attacks and alert summaries.

- **Portfolio group:** Cybersecurity lab project
- **Status:** MVP implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/SSHBruteForceDetector
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/SSHBruteForceDetector`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection or analysis logic, local tests, and generated output reports where relevant. It is ready for README/demo polish or deeper product work.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

## Core Features

- read /var/log/auth.log sample
- count failed logins by IP
- detect repeated attempts
- generate alert
- dashboard summary

## Status

Working CLI MVP.

## Quick Start

Analyze the included sample auth log:

```bash
python3 dashboard/app.py --log data/sample-auth.log --threshold 3 --out-dir reports
```

Run tests:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## MVP Capabilities

- Parses Linux auth log failed and successful SSH login events.
- Counts failed logins by source IP.
- Detects repeated failed attempts above a configurable threshold.
- Escalates fast attack windows and successful logins after repeated failures.
- Generates formatted alerts.
- Writes dashboard-friendly JSON summaries, IP timeline, Markdown report, and triage handoff.

## Demo Artifacts

- [Architecture](docs/ARCHITECTURE.md)
- [Security notes](docs/SECURITY_NOTES.md)
- [Demo walkthrough](docs/DEMO.md)
- [Release notes](docs/RELEASE_NOTES.md)
- [Sample report](reports/report.md)
- [Sample triage report](reports/triage.md)
- [Sample IP timeline](reports/ip-timeline.json)

## Docker Demo

```bash
docker compose run --rm ssh-bruteforce-demo
```

## Roadmap

- Add syslog year inference and timezone handling.
- Add allowlist/suppression support for trusted admin IPs.
- Add JSONL streaming mode for larger auth logs.
- Add Slack/webhook alert delivery.
- Prepare GitHub release `v0.1.0-mvp`.
