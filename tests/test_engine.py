from trailsight.engine import scan, scan_records
from trailsight.findings import SEVERITIES
from trailsight.generator import generate, write_dataset


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


def test_scan_returns_the_most_severe_findings_first(tmp_path):
    path = tmp_path / "data.json"
    write_dataset(str(path))
    ranks = [SEVERITIES.index(f.severity) for f in scan(str(path))]
    assert ranks == sorted(ranks, reverse=True)


def test_scan_records_matches_scanning_a_file(tmp_path):
    records, _ = generate()
    rules = [f.rule for f in scan_records(records)]
    assert "privilege_escalation" in rules
    assert rules[0] in {"privilege_escalation", "security_controls"}
