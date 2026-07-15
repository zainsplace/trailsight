from trailsight.engine import scan
from trailsight.generator import write_dataset


def test_scan_detects_every_seeded_attack(tmp_path):
    path = tmp_path / "data.json"
    manifest = write_dataset(str(path))
    findings = scan(str(path))
    fired = {f.rule for f in findings}
    expected = {entry["rule"] for entry in manifest}
    assert expected <= fired


def test_scan_on_empty_file_returns_no_findings(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text('{"Records": []}')
    assert scan(str(path)) == []
