from fastapi.testclient import TestClient

from logguard.api import app


def test_health():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_endpoint():
    client = TestClient(app)

    response = client.post(
        "/analyze",
        json={
            "threshold": 1,
            "lines": [
                "Apr 26 12:00:00 vm sshd[10]: Failed password for root from 203.0.113.4 port 53122 ssh2"
            ],
        },
    )

    assert response.status_code == 200
    assert response.json()["suspicious_ips"][0]["ip"] == "203.0.113.4"

