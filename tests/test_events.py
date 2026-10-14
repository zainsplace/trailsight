import gzip
import json

import pytest

from trailsight.events import LoadError, load_events, records_from_bytes


def test_load_events_parses_cloudtrail_record(tmp_path):
    record = {
        "eventTime": "2026-01-02T03:04:05Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "10.0.0.1",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::111:user/alice",
            "accessKeyId": "AKIA1",
        },
        "additionalEventData": {"MFAUsed": "Yes"},
        "requestParameters": {},
    }
    path = tmp_path / "trail.json"
    path.write_text(json.dumps({"Records": [record]}))

    events = load_events(str(path))

    assert len(events) == 1
    event = events[0]
    assert event.name == "ConsoleLogin"
    assert event.identity_arn == "arn:aws:iam::111:user/alice"
    assert event.identity_type == "IAMUser"
    assert event.access_key_id == "AKIA1"
    assert event.source_ip == "10.0.0.1"
    assert event.region == "eu-west-1"
    assert event.mfa_used is True
    assert event.time.year == 2026


def test_load_events_accepts_bare_list(tmp_path):
    path = tmp_path / "trail.json"
    path.write_text('[{"eventName": "ListBuckets", "eventTime": "2026-01-02T00:00:00Z"}]')
    events = load_events(str(path))
    assert events[0].name == "ListBuckets"


def test_events_from_records_matches_loading():
    from trailsight.events import events_from_records

    records = [{
        "eventTime": "2026-01-02T03:04:05Z",
        "eventName": "StopLogging",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111:user/bob"},
    }]
    events = events_from_records(records)
    assert len(events) == 1
    assert events[0].name == "StopLogging"
    assert events[0].identity_arn == "arn:aws:iam::111:user/bob"


def _write_trail(path, names, compress=False):
    payload = json.dumps({"Records": [
        {"eventName": name, "eventTime": "2026-01-02T00:00:00Z"} for name in names
    ]}).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(payload) if compress else payload)
    return path


def test_load_events_reads_gzipped_file(tmp_path):
    path = _write_trail(tmp_path / "trail.json.gz", ["ListBuckets"], compress=True)
    assert [e.name for e in load_events(str(path))] == ["ListBuckets"]


def test_load_events_detects_gzip_by_content_not_name(tmp_path):
    path = _write_trail(tmp_path / "upload.bin", ["GetUser"], compress=True)
    assert [e.name for e in load_events(str(path))] == ["GetUser"]


def test_load_events_reads_every_log_in_a_folder(tmp_path):
    _write_trail(tmp_path / "a.json", ["ListBuckets"])
    _write_trail(tmp_path / "2026" / "01" / "b.json.gz", ["GetUser"], compress=True)
    (tmp_path / "notes.txt").write_text("not a log")
    names = sorted(e.name for e in load_events(str(tmp_path)))
    assert names == ["GetUser", "ListBuckets"]


def test_load_events_skips_digest_files_in_a_folder(tmp_path):
    _write_trail(tmp_path / "a.json", ["ListBuckets"])
    digest = tmp_path / "CloudTrail-Digest" / "111_CloudTrail-Digest_x.json.gz"
    digest.parent.mkdir()
    digest.write_bytes(gzip.compress(b'{"digestStartTime": "2026"}'))
    assert [e.name for e in load_events(str(tmp_path))] == ["ListBuckets"]


def test_load_events_combines_several_paths(tmp_path):
    first = _write_trail(tmp_path / "a.json", ["ListBuckets"])
    second = _write_trail(tmp_path / "b.json.gz", ["GetUser"], compress=True)
    names = sorted(e.name for e in load_events([str(first), str(second)]))
    assert names == ["GetUser", "ListBuckets"]


def test_load_events_reports_a_missing_path(tmp_path):
    with pytest.raises(LoadError, match="does not exist"):
        load_events(str(tmp_path / "nope.json"))


def test_load_events_reports_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{bad")
    with pytest.raises(LoadError, match="bad.json does not look like a CloudTrail"):
        load_events(str(path))


def test_load_events_reports_json_without_records(tmp_path):
    path = tmp_path / "other.json"
    path.write_text('{"something": "else"}')
    with pytest.raises(LoadError, match="does not look like a CloudTrail"):
        load_events(str(path))


def test_load_events_reports_a_folder_with_no_logs(tmp_path):
    (tmp_path / "notes.txt").write_text("hi")
    with pytest.raises(LoadError, match="no CloudTrail log files"):
        load_events(str(tmp_path))


def test_records_from_bytes_reads_plain_and_gzipped():
    payload = b'{"Records": [{"eventName": "GetUser"}]}'
    assert records_from_bytes(payload, "a") == [{"eventName": "GetUser"}]
    assert records_from_bytes(gzip.compress(payload), "a") == [{"eventName": "GetUser"}]


def test_load_events_reports_a_corrupt_gzip_file(tmp_path):
    path = tmp_path / "trail.json.gz"
    path.write_bytes(b"\x1f\x8bnot really gzip")
    with pytest.raises(LoadError, match="not a valid gzip file"):
        load_events(str(path))
