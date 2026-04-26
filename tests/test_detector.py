import pytest

from logguard.detector import analyze_lines


def test_analyze_lines_reports_suspicious_ips():
    lines = [
        "Apr 26 12:00:00 vm sshd[10]: Failed password for root from 203.0.113.4 port 53122 ssh2",
        "Apr 26 12:00:01 vm sshd[11]: Failed password for invalid user admin from 203.0.113.4 port 53123 ssh2",
        "Apr 26 12:00:02 vm sshd[12]: Accepted publickey for deploy from 198.51.100.7 port 42000 ssh2",
    ]

    report = analyze_lines(lines, threshold=2)

    assert report["total_lines"] == 3
    assert report["parsed_events"] == 3
    assert report["failed_logins"] == 2
    assert report["accepted_logins"] == 1
    assert report["suspicious_ips"] == [
        {
            "ip": "203.0.113.4",
            "failed_attempts": 2,
            "usernames": ["admin", "root"],
            "risk": "medium",
        }
    ]


def test_threshold_must_be_positive():
    with pytest.raises(ValueError):
        analyze_lines([], threshold=0)

