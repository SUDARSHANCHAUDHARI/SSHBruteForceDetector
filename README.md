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
- Generates formatted alerts.
- Writes dashboard-friendly JSON summaries and a Markdown report.

## Roadmap

- Polish sample output screenshots or terminal demos
- Add architecture diagram and deeper implementation notes
- Expand test coverage around edge cases
- Add Docker or local demo workflow where useful
- Prepare `v0.1.0-mvp` release notes
