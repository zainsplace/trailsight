import io
import json
import re

import pytest

from trailsight.generator import generate

pytest.importorskip("flask")

import trailsight.dashboard.app as dashboard_app
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

    monkeypatch.setattr("trailsight.dashboard.create_app",
                        lambda **kwargs: FakeApp())
    assert cli.main(["serve", "--port", "8080"]) == 0
    assert captured == {"host": "127.0.0.1", "port": 8080}


class StubProvider:
    def __init__(self, model="llama3", host="http://localhost:11434"):
        pass

    def complete(self, prompt):
        return "An administrator policy was attached."


def _scan_id(body):
    match = re.search(rb'data-scan-id="([^"]+)"', body)
    assert match, "results page must carry a scan id"
    return match.group(1).decode()


def test_explain_returns_text_for_a_stored_finding(client, monkeypatch):
    monkeypatch.setattr(dashboard_app, "OllamaProvider", StubProvider)
    records, _ = generate()
    scan_id = _scan_id(_upload(client, records).data)
    response = client.post("/explain", json={"scan_id": scan_id, "index": 0})
    assert response.status_code == 200
    assert response.get_json()["explanation"].startswith("An administrator")


def test_explain_rejects_an_unknown_scan(client):
    response = client.post("/explain", json={"scan_id": "nope", "index": 0})
    assert response.status_code == 404


def test_explain_rejects_an_out_of_range_index(client, monkeypatch):
    monkeypatch.setattr(dashboard_app, "OllamaProvider", StubProvider)
    records, _ = generate()
    scan_id = _scan_id(_upload(client, records).data)
    response = client.post("/explain", json={"scan_id": scan_id, "index": 9999})
    assert response.status_code == 404


def test_explain_reports_a_dead_provider(client, monkeypatch):
    class DeadProvider:
        def __init__(self, model="llama3", host="http://localhost:11434"):
            pass

        def complete(self, prompt):
            raise dashboard_app.ExplanationError("ollama is not running")

    monkeypatch.setattr(dashboard_app, "OllamaProvider", DeadProvider)
    records, _ = generate()
    scan_id = _scan_id(_upload(client, records).data)
    response = client.post("/explain", json={"scan_id": scan_id, "index": 0})
    assert response.status_code == 503
    assert "ollama is not running" in response.get_json()["error"]
