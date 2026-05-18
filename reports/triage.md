# SSH Brute-Force Triage

- Failed logins: 5
- Successful logins: 2
- Alerts: 2

## IP Timeline

- `198.51.100.22`: 3 failed, 1 successful, users=admin, deploy, root
- `203.0.113.10`: 0 failed, 1 successful, users=kiosk
- `203.0.113.77`: 2 failed, 0 successful, users=oracle, test

## Analyst Queue

- `critical` ssh.bruteforce: Repeated failed SSH logins from one IP.
- `critical` ssh.success_after_failures: Successful SSH login followed repeated failures from the same IP.
