from logguard.parser import parse_line


def test_parse_failed_password():
    event = parse_line(
        "Apr 26 12:00:00 vm sshd[10]: Failed password for root from 203.0.113.4 port 53122 ssh2"
    )

    assert event is not None
    assert event.outcome == "failed"
    assert event.username == "root"
    assert event.ip == "203.0.113.4"
    assert event.port == 53122


def test_parse_invalid_user_failed_password():
    event = parse_line(
        "Apr 26 12:00:00 vm sshd[10]: Failed password for invalid user admin from 203.0.113.4 port 53122 ssh2"
    )

    assert event is not None
    assert event.outcome == "invalid_user_failed"
    assert event.username == "admin"


def test_parse_accepted_login():
    event = parse_line(
        "Apr 26 12:01:00 vm sshd[11]: Accepted publickey for deploy from 198.51.100.7 port 42000 ssh2"
    )

    assert event is not None
    assert event.outcome == "accepted"
    assert event.method == "publickey"


def test_ignores_unrelated_line():
    assert parse_line("Apr 26 12:03:00 vm sudo: deploy : COMMAND=/usr/bin/id") is None

