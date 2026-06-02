# SSH Brute-Force Detector

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-MVP-green)](#status)
[![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#safe-use)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Linux auth log detector for repeated SSH failed-login attacks. Parses `auth.log`, scores brute-force activity per source IP, and emits actionable alerts.

---

## Overview

SSH Brute-Force Detector is a defensive analysis tool that reads Linux SSH auth logs and detects brute-force patterns: high-volume failed logins, fast attack windows, and successful logins immediately after a string of failures. Outputs include Markdown reports, JSON summaries, IP timelines, and a triage handoff for analysts.

## Features

- Parses Linux `auth.log` failed and successful SSH login events
- Counts failed logins by source IP
- Detects repeated failed attempts above a configurable threshold
- Escalates fast attack windows and successful logins after repeated failures
- Generates formatted terminal alerts with recommended actions
- Writes JSON summaries, IP timeline, Markdown report, and triage handoff

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows
- No third-party Python packages (standard library only)
- Optional: Docker for the demo container

## Installation

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/SSHBruteForceDetector.git
cd SSHBruteForceDetector
pip install .
```

This registers the `ssh-brute-detector` CLI command.

To run without installing:

```bash
python3 main.py --help
```

## Usage

Analyze the included sample auth log:

```bash
python3 main.py --log data/sample-auth.log --threshold 3 --out-dir reports
```

Generated outputs in `reports/`:

- `events.json` — parsed auth events
- `findings.json` — detected brute-force findings
- `summary.json` — dashboard-friendly summary
- `ip-timeline.json` — per-IP activity timeline
- `report.md` — full Markdown detection report
- `triage.md` — analyst triage checklist

## Project Structure

```
SSHBruteForceDetector/
├── dashboard/      CLI dashboard (entrypoint)
├── detector/       Parser, rules, alert formatting
├── data/           Safe sample auth log
├── reports/        Example generated output
├── docker/         Dockerfile + compose support
├── docs/           Architecture, security notes, demo
├── tests/          Unit tests
├── main.py         CLI entrypoint
├── pyproject.toml  Package metadata
└── LICENSE
```

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Docker Demo

```bash
docker compose run --rm ssh-bruteforce-demo
```

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, and lab environments you own or have explicit written permission to assess. The included sample log is synthetic and safe for public demo use.

## Status

Working CLI MVP with tests, demo data, and Docker support.

## Roadmap

- Syslog year inference and timezone handling
- Allowlist / suppression support for trusted admin IPs
- JSONL streaming mode for larger auth logs
- Slack / webhook alert delivery
- GitHub release `v0.1.0-mvp`

## License

Released under the [MIT License](LICENSE). You are free to use, modify, and distribute this software with attribution.

## Author

**Sudarshan Chaudhari** — [SudarshanTechLabs](https://github.com/SUDARSHANCHAUDHARI)
Bangkok, Thailand

For inquiries: open an issue on [GitHub](https://github.com/SUDARSHANCHAUDHARI/SSHBruteForceDetector/issues).
