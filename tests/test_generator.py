from trailsight.generator import generate, write_dataset
from trailsight.events import load_events


def test_generate_returns_records_and_manifest():
    records, manifest = generate()
    assert len(records) > 20
    rules = {entry["rule"] for entry in manifest}
    assert {
        "leaked_credentials",
        "privilege_escalation",
        "recon",
        "security_controls",
        "root_usage",
        "console_mfa",
    } <= rules


def test_write_dataset_is_loadable(tmp_path):
    path = tmp_path / "data.json"
    manifest = write_dataset(str(path))
    events = load_events(str(path))
    assert len(events) > 20
    assert len(manifest) >= 6
