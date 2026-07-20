<!--
  README.md
-->

<p align="center">
  <!-- BADGES:START -->
  <a href="#"><img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blue"></a>
  <a href="#"><img alt="FastAPI" src="https://img.shields.io/badge/fastapi-009688?logo=fastapi&logoColor=white"></a>
  <a href="#"><img alt="Docker" src="https://img.shields.io/badge/docker-%230db7ed.svg?&style=flat&logo=docker&logoColor=white"></a>
  <a href="#"><img alt="GitHub Actions" src="https://img.shields.io/badge/github%20actions-%232671E5.svg?&style=flat&logo=githubactions&logoColor=white"></a>
  <a href="#"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
  <!-- BADGES:END -->
</p>

# LogGuard API

Author: Saina Kakkar

### Project Description
LogGuard is security log analysis for SSH authentication logs. You can use
it as a CLI for one-off audits or as a FastAPI service for continuous
monitoring.

It parses raw, noisy `sshd` auth logs, detects suspicious failed-login
patterns (brute-force attempts, and credential spraying across usernames),
and produces deterministic JSON reports that are safe to diff, alert on, or
feed into a dashboard.

```mermaid
graph LR
  A[Raw sshd log lines] --> B[Parser<br/>line to structured event]
  B --> C[Detector<br/>events to findings]
  C --> D[JSON report]
  E[CLI] --> B
  F[FastAPI service] --> B
```

The parser and the detector are separate, unit-tested pieces. The CLI and
the API are thin adapters over that same core, so the two interfaces cannot
drift apart in behavior. For a security tool I wanted the analysis to be
auditable in one place.

## Key Features

- Handles real-world `sshd` log lines and counts parsed vs. unparseable
  events instead of crashing on noise
- Flags source IPs that cross a configurable failed-attempt threshold, with
  the usernames they targeted and a risk rating
- Same input always produces the same report, so results are scriptable and
  testable
- Unit-tested parser and detector logic, sample data, a Dockerfile, and CI
  via GitHub Actions

## Quick Start

1. **Set up the environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. **Analyze a sample log:**

   ```bash
   logguard analyze samples/auth.log --threshold 3 --out reports/auth-report.json
   ```

### Example Report

This is the actual output for the bundled sample log:

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

Note `total_lines: 8` vs `parsed_events: 7`. One line in the sample is
garbage on purpose. The report tells you how much of the log the tool
actually understood, instead of pretending it saw everything.

## Run as a Service

Prefer an API over a CLI? The same engine runs behind FastAPI:

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

## Verify

```bash
pytest
```

## Additional Notes

- My first parser raised an exception on any line it did not recognize,
  which meant one weird log line killed a whole audit. Real auth logs are
  full of lines that are not login events. Now unknown lines are counted and
  skipped, and the parsed vs. unparseable numbers go into the report.
- The threshold is configurable because there is no single right answer.
  Three failed attempts from one IP is suspicious on a small personal
  server and completely normal on a busy one.

## License

MIT
