from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from .parser import AuthEvent, parse_line


FAILED_OUTCOMES = {"failed", "invalid_user", "invalid_user_failed"}


def analyze_lines(lines: Iterable[str], *, threshold: int = 5, year: int = 2026) -> dict:
    if threshold <= 0:
        raise ValueError("threshold must be positive")

    total_lines = 0
    events: list[AuthEvent] = []
    for line in lines:
        total_lines += 1
        event = parse_line(line, year=year)
        if event is not None:
            events.append(event)

    failed_events = [event for event in events if event.outcome in FAILED_OUTCOMES]
    accepted_events = [event for event in events if event.outcome == "accepted"]
    failures_by_ip = Counter(event.ip for event in failed_events)
    users_by_ip: dict[str, Counter[str]] = defaultdict(Counter)

    for event in failed_events:
        users_by_ip[event.ip][event.username] += 1

    suspicious_ips = [
        {
            "ip": ip,
            "failed_attempts": count,
            "usernames": sorted(users_by_ip[ip]),
            "risk": _risk_level(count, threshold),
        }
        for ip, count in failures_by_ip.most_common()
        if count >= threshold
    ]

    return {
        "total_lines": total_lines,
        "parsed_events": len(events),
        "failed_logins": len(failed_events),
        "accepted_logins": len(accepted_events),
        "suspicious_ips": suspicious_ips,
        "top_usernames": [
            {"username": username, "failed_attempts": count}
            for username, count in Counter(event.username for event in failed_events).most_common(5)
        ],
        "events": [event.to_dict() for event in events],
    }


def _risk_level(count: int, threshold: int) -> str:
    if count >= threshold * 3:
        return "high"
    if count >= threshold:
        return "medium"
    return "low"

