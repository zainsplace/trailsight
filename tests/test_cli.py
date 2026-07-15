import json

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
