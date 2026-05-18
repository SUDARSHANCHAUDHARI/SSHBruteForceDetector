# Production Readiness

## Current Status

This repository has a working local MVP with deterministic parsing, safe sample data, generated reports, and tests. It is not production complete yet.

## Required Before Public Release

- Add robust syslog year/timezone parsing.
- Validate and bound log file size before hosted uploads.
- Add structured logging without leaking secrets.
- Add allowlist and suppression audit history.
- Add authentication and authorization before storing multi-user logs.
- Add retention controls for uploaded auth logs and reports.
- Run dependency and secret scans before release.

## Definition of Done

- CI passes on pull requests.
- README has setup, usage, and security notes.
- Sample data is safe to publish.
- Error paths are handled clearly.
- No secrets or local machine paths are committed.
