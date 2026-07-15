import io
import json

import pytest

from trailsight.generator import generate

pytest.importorskip("flask")

from trailsight.dashboard import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _upload(client, records):
    payload = json.dumps({"Records": records}).encode("utf-8")
    data = {"logfile": (io.BytesIO(payload), "trail.json")}
    return client.post("/scan", data=data, content_type="multipart/form-data")


def test_landing_page_shows_upload(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"CloudTrail" in response.data
    assert b"Load demo data" in response.data


def test_scan_upload_shows_all_findings(client):
    records, _ = generate()
    response = _upload(client, records)
    assert response.status_code == 200
    body = response.data
    for rule in [b"privilege_escalation", b"security_controls",
                 b"leaked_credentials", b"recon", b"root_usage", b"console_mfa"]:
        assert rule in body


def test_scan_clean_file_shows_clean_state(client):
    response = _upload(client, [])
    assert response.status_code == 200
    assert b"No findings" in response.data


def test_scan_garbage_shows_error(client):
    data = {"logfile": (io.BytesIO(b"not json"), "trail.json")}
    response = client.post("/scan", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"does not look like" in response.data


def test_demo_shows_findings(client):
    response = client.get("/demo")
    assert response.status_code == 200
    assert b"privilege_escalation" in response.data


def test_serve_runs_app_on_chosen_port(monkeypatch):
    from trailsight import cli

    captured = {}

    class FakeApp:
        def run(self, host, port):
            captured["host"] = host
            captured["port"] = port

    monkeypatch.setattr("trailsight.dashboard.create_app", lambda: FakeApp())
    assert cli.main(["serve", "--port", "8080"]) == 0
    assert captured == {"host": "127.0.0.1", "port": 8080}
