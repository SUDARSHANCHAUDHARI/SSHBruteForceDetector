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

Scaffolded. Implementation pending.
