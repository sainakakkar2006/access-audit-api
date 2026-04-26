from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime


AUTH_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

FAILED_RE = re.compile(
    r"Failed password for (?:(?P<invalid>invalid user)\s+)?"
    r"(?P<user>[\w.@+-]+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+"
    r"(?P<port>\d+)"
)

INVALID_RE = re.compile(
    r"Invalid user (?P<user>[\w.@+-]+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+"
    r"(?P<port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>[\w.@+-]+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+"
    r"(?P<port>\d+)"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    host: str
    pid: int
    outcome: str
    username: str
    ip: str
    port: int
    method: str | None
    raw: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_line(line: str, *, year: int = 2026) -> AuthEvent | None:
    match = AUTH_LINE_RE.match(line.strip())
    if not match:
        return None

    message = match.group("message")
    timestamp = _parse_timestamp(
        year,
        match.group("month"),
        int(match.group("day")),
        match.group("time"),
    )

    failed = FAILED_RE.search(message)
    if failed:
        return AuthEvent(
            timestamp=timestamp,
            host=match.group("host"),
            pid=int(match.group("pid")),
            outcome="invalid_user_failed" if failed.group("invalid") else "failed",
            username=failed.group("user"),
            ip=failed.group("ip"),
            port=int(failed.group("port")),
            method="password",
            raw=line.rstrip("\n"),
        )

    invalid = INVALID_RE.search(message)
    if invalid:
        return AuthEvent(
            timestamp=timestamp,
            host=match.group("host"),
            pid=int(match.group("pid")),
            outcome="invalid_user",
            username=invalid.group("user"),
            ip=invalid.group("ip"),
            port=int(invalid.group("port")),
            method=None,
            raw=line.rstrip("\n"),
        )

    accepted = ACCEPTED_RE.search(message)
    if accepted:
        return AuthEvent(
            timestamp=timestamp,
            host=match.group("host"),
            pid=int(match.group("pid")),
            outcome="accepted",
            username=accepted.group("user"),
            ip=accepted.group("ip"),
            port=int(accepted.group("port")),
            method=accepted.group("method"),
            raw=line.rstrip("\n"),
        )

    return None


def _parse_timestamp(year: int, month: str, day: int, time_text: str) -> str:
    parsed = datetime.strptime(f"{year} {month} {day} {time_text}", "%Y %b %d %H:%M:%S")
    return parsed.isoformat()

