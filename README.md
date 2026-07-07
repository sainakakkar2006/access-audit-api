# LogGuard API

**Security log analysis for SSH authentication logs — as a CLI for one-off audits and a FastAPI service for continuous monitoring.**

LogGuard parses raw, noisy `sshd` auth logs, detects suspicious failed-login patterns (brute-force attempts, credential spraying across usernames), and produces deterministic JSON reports that are safe to diff, alert on, or feed into a dashboard.

## Features

- **Robust log parsing** — handles real-world `sshd` log lines, counts parsed vs. unparseable events instead of crashing on noise
- **Suspicious-IP detection** — flags source IPs that cross a configurable failed-attempt threshold, with the usernames they targeted and a risk rating
- **Deterministic JSON reports** — same input always produces the same report, so results are scriptable and testable
- **Two interfaces, one engine** — the CLI and the REST API share the same analysis core
- **Production trimmings** — unit-tested parser and detector logic, sample data, Dockerfile, CI via GitHub Actions

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Analyze a sample log:

```bash
logguard analyze samples/auth.log --threshold 3 --out reports/auth-report.json
```

### Example report

```json
{
  "total_lines": 8,
  "parsed_events": 7,
  "failed_logins": 5,
  "accepted_logins": 1,
  "suspicious_ips": [
    {
      "ip": "203.0.113.4",
      "failed_attempts": 3,
      "usernames": ["admin", "root"],
      "risk": "medium"
    }
  ]
}
```

## Run as a service

```bash
uvicorn logguard.api:app --reload
```

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"threshold": 2, "lines": ["Apr 26 12:00:00 vm sshd[10]: Failed password for root from 203.0.113.4 port 53122 ssh2"]}'
```

| Endpoint        | Description                                        |
| --------------- | -------------------------------------------------- |
| `GET /health`   | Service status                                     |
| `POST /analyze` | Analyze log lines; returns the same JSON report as the CLI |

## Docker

```bash
docker build -t logguard-api .
docker run -p 8000:8000 logguard-api
```

## Design notes

The analysis pipeline is split into a **parser** (raw line → structured event) and a **detector** (event stream → findings), each unit-tested independently. The CLI and FastAPI layers are thin adapters over that core, so behavior can't drift between the two interfaces — a pattern that keeps security tooling auditable.

## License

MIT
