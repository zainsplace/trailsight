import json

import trailsight.cli
from trailsight.cli import main
from trailsight.generator import write_dataset


def test_generate_then_scan_text(capsys, tmp_path):
    path = tmp_path / "data.json"
    assert main(["generate", "--output", str(path)]) == 0
    out = capsys.readouterr().out
    assert "wrote" in out.lower()

    code = main(["scan", "--input", str(path), "--format", "text"])
    assert code == 1
    report = capsys.readouterr().out
    assert "privilege_escalation" in report


def test_scan_json_is_machine_readable(capsys, tmp_path):
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    rules = {item["rule"] for item in payload}
    assert "security_controls" in rules


def test_scan_clean_file_returns_zero(capsys, tmp_path):
    path = tmp_path / "clean.json"
    path.write_text('{"Records": []}')
    assert main(["scan", "--input", str(path), "--format", "text"]) == 0


class StubProvider:
    def __init__(self, model="llama3", host="http://localhost:11434"):
        self.model = model
        self.host = host

    def complete(self, prompt):
        return "Because the key was used from two countries."


def test_scan_without_explain_has_no_explanation_key(capsys, tmp_path):
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert all("explanation" not in item for item in payload)


def test_scan_explain_attaches_text_to_json(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(trailsight.cli, "OllamaProvider", StubProvider)
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path), "--format", "json", "--explain"])
    payload = json.loads(capsys.readouterr().out)
    assert payload
    assert all(item["explanation"].startswith("Because") for item in payload)


def test_scan_explain_prints_text_block(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(trailsight.cli, "OllamaProvider", StubProvider)
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path), "--explain"])
    out = capsys.readouterr().out
    assert "explanation:" in out
    assert "Because the key was used" in out


def test_scan_explain_passes_model_and_host(capsys, tmp_path, monkeypatch):
    captured = {}

    def factory(model, host):
        captured["model"] = model
        captured["host"] = host
        return StubProvider(model, host)

    monkeypatch.setattr(trailsight.cli, "OllamaProvider", factory)
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path), "--explain", "--ollama-model", "mistral",
          "--ollama-host", "http://127.0.0.1:9999"])
    assert captured == {"model": "mistral", "host": "http://127.0.0.1:9999"}


def test_scan_still_reports_findings_when_the_model_is_unreachable(
        capsys, tmp_path, monkeypatch):
    class DeadProvider:
        def __init__(self, model, host):
            pass

        def complete(self, prompt):
            raise trailsight.cli.ExplanationError("ollama is not running")

    monkeypatch.setattr(trailsight.cli, "OllamaProvider", DeadProvider)
    path = tmp_path / "data.json"
    write_dataset(str(path))
    code = main(["scan", "--input", str(path), "--explain"])
    out = capsys.readouterr().out
    assert code == 1
    assert "privilege_escalation" in out
    assert "ollama is not running" in out
