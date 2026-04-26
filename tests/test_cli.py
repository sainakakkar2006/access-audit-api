import json
import subprocess
import sys


def test_cli_writes_json_report(tmp_path):
    log_file = tmp_path / "auth.log"
    out_file = tmp_path / "report.json"
    log_file.write_text(
        "\n".join(
            [
                "Apr 26 12:00:00 vm sshd[10]: Failed password for root from 203.0.113.4 port 53122 ssh2",
                "Apr 26 12:00:01 vm sshd[11]: Failed password for root from 203.0.113.4 port 53123 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "logguard.cli",
            "analyze",
            str(log_file),
            "--threshold",
            "2",
            "--out",
            str(out_file),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(out_file.read_text(encoding="utf-8"))
    assert report["suspicious_ips"][0]["ip"] == "203.0.113.4"

