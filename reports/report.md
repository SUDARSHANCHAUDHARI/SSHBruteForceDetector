# SSH Brute-Force Detection Report

## Summary

- Total events: 7
- Failed logins: 5
- Successful logins: 2
- Alerts: 2
- Highest severity: `critical`
- Unique failed users: admin, deploy, oracle, root, test

## Top Failed IPs

- `198.51.100.22`: 3 failures
- `203.0.113.77`: 2 failures

## Alerts

- [CRITICAL] Repeated failed SSH logins from one IP. ip=198.51.100.22 failures=3 users=admin, deploy, root
- [CRITICAL] Successful SSH login followed repeated failures from the same IP. ip=198.51.100.22 failures=3 successful_user=deploy

## Findings

### Repeated failed SSH logins from one IP.

- Severity: `critical`
- Type: `ssh.bruteforce`
- Evidence: `{'ip': '198.51.100.22', 'failed_attempts': 3, 'users': ['admin', 'deploy', 'root'], 'ports': [50122, 50124, 50128], 'window_seconds': 7}`
- Recommended next step: Block or rate-limit the source IP, confirm no successful login followed, and review targeted usernames.

### Successful SSH login followed repeated failures from the same IP.

- Severity: `critical`
- Type: `ssh.success_after_failures`
- Evidence: `{'ip': '198.51.100.22', 'successful_user': 'deploy', 'failed_attempts': 3, 'minutes_after_last_failure': 0.2}`
- Recommended next step: Treat as possible compromise until the login is confirmed legitimate; preserve logs and review session activity.

