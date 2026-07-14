import json

from trailsight.events import load_events


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
