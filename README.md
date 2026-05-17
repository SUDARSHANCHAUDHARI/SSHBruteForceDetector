# SSH Brute-Force Detection

**Goal:** Detect failed SSH login attacks.

**MVP:** Parse Linux auth logs and alert repeated failures.

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
- Generates formatted alerts.
- Writes dashboard-friendly JSON summaries and a Markdown report.

## Repository Status

This repository contains the production-ready foundation for the SSH Brute-Force Detector MVP. The current codebase is scaffolded and ready for focused implementation work.

## Production Foundation

- Private GitHub repository linked to `main`
- Initial MVP scaffold committed
- CI repository-health workflow
- Security policy
- Contribution guide
- Pull request and issue templates
- Production readiness checklist
- Safe ignore rules for local secrets and generated files
