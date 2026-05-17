# SSH Brute-Force Detection Report

## Summary

- Total events: 6
- Failed logins: 5
- Successful logins: 1
- Alerts: 1

## Top Failed IPs

- `198.51.100.22`: 3 failures
- `203.0.113.77`: 2 failures

## Alerts

- [HIGH] Repeated failed SSH logins from one IP. ip=198.51.100.22 failures=3 users=admin, deploy, root

## Findings

- `ssh.bruteforce` {'ip': '198.51.100.22', 'failed_attempts': 3, 'users': ['admin', 'deploy', 'root'], 'ports': [50122, 50124, 50128]}
