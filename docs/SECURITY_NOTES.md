# Security Notes

This project is defensive and analysis-only. Use it only with auth logs from systems you own or have permission to investigate.

## Data Handling

- Auth logs can include real usernames, hostnames, source IPs, and login timing.
- Redact private hostnames, public customer IPs, and user identifiers before sharing reports.
- Do not commit production `/var/log/auth.log` files.
- Sample data uses documentation IP ranges.

## Detection Caveats

- A brute-force alert is a triage signal, not proof of compromise.
- A successful login after failures should be investigated with session logs and user validation.
- Thresholds should be tuned per environment to avoid false positives from automation or known admin activity.
