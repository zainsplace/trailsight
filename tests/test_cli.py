import gzip
import json

import pytest

import trailsight
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


def _write_medium_only_trail(path):
    path.write_text(json.dumps({"Records": [{
        "eventName": "ConsoleLogin",
        "eventTime": "2026-01-02T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111:user/alice"},
        "additionalEventData": {"MFAUsed": "No"},
    }]}))
    return path


def test_scan_reports_a_missing_file_without_a_traceback(capsys, tmp_path):
    code = main(["scan", "--input", str(tmp_path / "nope.json")])
    captured = capsys.readouterr()
    assert code == 2
    assert "does not exist" in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""


def test_scan_reports_invalid_json_with_exit_code_two(capsys, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{bad")
    assert main(["scan", "--input", str(path)]) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_scan_accepts_a_folder_of_gzipped_logs(capsys, tmp_path):
    source = tmp_path / "data.json"
    write_dataset(str(source))
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "part.json.gz").write_bytes(gzip.compress(source.read_bytes()))
    assert main(["scan", "--input", str(folder), "--format", "json"]) == 1
    rules = {item["rule"] for item in json.loads(capsys.readouterr().out)}
    assert "privilege_escalation" in rules


def test_scan_accepts_several_inputs(capsys, tmp_path):
    first = _write_medium_only_trail(tmp_path / "a.json")
    second = tmp_path / "b.json"
    write_dataset(str(second))
    main(["scan", "--input", str(first), str(second), "--format", "json"])
    identities = {item["identity"] for item in json.loads(capsys.readouterr().out)}
    assert "arn:aws:iam::111:user/alice" in identities
    assert len(identities) > 1


def test_scan_text_lists_the_most_severe_first(capsys, tmp_path):
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path)])
    headings = [line for line in capsys.readouterr().out.splitlines()
                if line.startswith("[")]
    assert headings[0].startswith("[CRITICAL]")
    assert headings[-1].startswith("[MEDIUM]")


def test_scan_text_ends_with_a_summary_line(capsys, tmp_path):
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path)])
    last = capsys.readouterr().out.strip().splitlines()[-1]
    assert last == "6 findings: 2 critical, 2 high, 2 medium"


def test_scan_summary_uses_the_singular_for_one_finding(capsys, tmp_path):
    path = _write_medium_only_trail(tmp_path / "a.json")
    main(["scan", "--input", str(path)])
    last = capsys.readouterr().out.strip().splitlines()[-1]
    assert last == "1 finding: 1 medium"


def test_min_severity_hides_less_severe_findings(capsys, tmp_path):
    path = tmp_path / "data.json"
    write_dataset(str(path))
    code = main(["scan", "--input", str(path), "--format", "json",
                 "--min-severity", "critical"])
    severities = {item["severity"] for item in json.loads(capsys.readouterr().out)}
    assert code == 1
    assert severities == {"critical"}


def test_min_severity_exits_zero_when_everything_is_filtered(capsys, tmp_path):
    path = _write_medium_only_trail(tmp_path / "a.json")
    code = main(["scan", "--input", str(path), "--min-severity", "high"])
    assert code == 0
    assert "No findings" in capsys.readouterr().out


def test_min_severity_only_explains_kept_findings(capsys, tmp_path, monkeypatch):
    prompts = []

    class CountingProvider(StubProvider):
        def complete(self, prompt):
            prompts.append(prompt)
            return super().complete(prompt)

    monkeypatch.setattr(trailsight.cli, "OllamaProvider", CountingProvider)
    path = tmp_path / "data.json"
    write_dataset(str(path))
    main(["scan", "--input", str(path), "--explain", "--min-severity", "critical"])
    assert len(prompts) == 2


def test_version_flag_prints_the_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"trailsight {trailsight.__version__}"
