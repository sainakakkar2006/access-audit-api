# LogGuard API

LogGuard is a small security log-analysis service for SSH authentication logs. It parses failed-login activity, identifies suspicious IPs, and returns a JSON report through both a CLI and a FastAPI endpoint.

## Why This Project Exists

This project is built for the same kind of signal as a systems/security assessment:

- parse noisy real-world log lines
- detect suspicious failed-login patterns
- produce deterministic JSON reports
- expose the logic through a CLI and an API
- include tests, sample data, and Docker setup

## Quick Start

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

Run the API:

```bash
uvicorn logguard.api:app --reload
```

Then call:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"threshold": 2, "lines": ["Apr 26 12:00:00 vm sshd[10]: Failed password for root from 203.0.113.4 port 53122 ssh2"]}'
```

## Report Example

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

## API

### `GET /health`

Returns service status.

### `POST /analyze`

Request body:

```json
{
  "threshold": 3,
  "lines": ["...auth log line..."]
}
```

Response body is the same JSON report produced by the CLI.

## Docker

```bash
docker build -t logguard-api .
docker run -p 8000:8000 logguard-api
```

## What This Shows

This repo demonstrates CLI design, API design, security-oriented parsing, structured output, tests, and Docker readiness in a compact project.

