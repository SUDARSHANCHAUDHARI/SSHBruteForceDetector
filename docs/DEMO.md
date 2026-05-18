# Demo

Run the included safe auth log sample:

```bash
python3 dashboard/app.py --log data/sample-auth.log --threshold 3 --out-dir reports
```

Expected output:

```text
Parsed 7 events
Generated 2 alert(s)
```

Generated artifacts:

- `reports/events.json`
- `reports/findings.json`
- `reports/summary.json`
- `reports/ip-timeline.json`
- `reports/report.md`
- `reports/triage.md`

The sample demonstrates repeated failed logins from one IP and a successful login shortly after those failures.
