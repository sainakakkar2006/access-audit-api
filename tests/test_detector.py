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


def test_invalid_user_pair_counts_as_one_attempt():
    lines = [
        "Apr 26 12:05:00 vm sshd[20]: Invalid user oracle from 203.0.113.50 port 40100",
        "Apr 26 12:05:02 vm sshd[20]: Failed password for invalid user oracle from 203.0.113.50 port 40100 ssh2",
        "Apr 26 12:05:04 vm sshd[21]: Invalid user oracle from 203.0.113.50 port 40101",
        "Apr 26 12:05:06 vm sshd[21]: Failed password for invalid user oracle from 203.0.113.50 port 40101 ssh2",
    ]

    report = analyze_lines(lines, threshold=3)

    assert report["parsed_events"] == 4
    assert report["failed_logins"] == 2
    assert report["suspicious_ips"] == []
    assert report["top_usernames"] == [{"username": "oracle", "failed_attempts": 2}]


def test_invalid_user_without_password_attempt_still_counts():
    lines = [
        "Apr 26 12:06:00 vm sshd[30]: Invalid user guest from 192.0.2.77 port 50500",
        "Apr 26 12:06:01 vm sshd[31]: Invalid user guest from 192.0.2.77 port 50501",
    ]

    report = analyze_lines(lines, threshold=2)

    assert report["failed_logins"] == 2
    assert report["suspicious_ips"][0]["failed_attempts"] == 2


def test_login_after_repeated_failures_is_flagged():
    lines = [
        "Apr 26 13:00:00 vm sshd[40]: Failed password for root from 203.0.113.9 port 41000 ssh2",
        "Apr 26 13:00:03 vm sshd[41]: Failed password for root from 203.0.113.9 port 41001 ssh2",
        "Apr 26 13:00:06 vm sshd[42]: Failed password for root from 203.0.113.9 port 41002 ssh2",
        "Apr 26 13:00:09 vm sshd[43]: Accepted password for root from 203.0.113.9 port 41003 ssh2",
    ]

    report = analyze_lines(lines, threshold=3)

    assert report["logins_after_failures"] == [
        {
            "ip": "203.0.113.9",
            "username": "root",
            "accepted_at": "2026-04-26T13:00:09",
            "failures_before": 3,
        }
    ]


def test_failures_after_a_login_do_not_flag_it():
    lines = [
        "Apr 26 13:10:00 vm sshd[50]: Accepted publickey for deploy from 198.51.100.7 port 42000 ssh2",
        "Apr 26 13:10:05 vm sshd[51]: Failed password for deploy from 198.51.100.7 port 42001 ssh2",
        "Apr 26 13:10:06 vm sshd[52]: Failed password for deploy from 198.51.100.7 port 42002 ssh2",
    ]

    report = analyze_lines(lines, threshold=2)

    assert report["logins_after_failures"] == []
    assert report["suspicious_ips"][0]["ip"] == "198.51.100.7"


def test_login_from_a_different_ip_is_not_flagged():
    lines = [
        "Apr 26 13:20:00 vm sshd[60]: Failed password for root from 203.0.113.9 port 41000 ssh2",
        "Apr 26 13:20:01 vm sshd[61]: Failed password for root from 203.0.113.9 port 41001 ssh2",
        "Apr 26 13:20:02 vm sshd[62]: Accepted publickey for root from 198.51.100.7 port 42000 ssh2",
    ]

    report = analyze_lines(lines, threshold=2)

    assert report["logins_after_failures"] == []


def test_threshold_must_be_positive():
    with pytest.raises(ValueError):
        analyze_lines([], threshold=0)

