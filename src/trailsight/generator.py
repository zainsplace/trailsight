import json


def _record(name, arn, itype="IAMUser", ip="10.0.0.5", region="eu-west-1",
            key="AKIANORMAL", params=None, error=None, mfa="Yes",
            source="iam.amazonaws.com", time="2026-01-01T09:00:00Z"):
    record = {
        "eventTime": time,
        "eventName": name,
        "eventSource": source,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userIdentity": {"type": itype, "arn": arn, "accessKeyId": key},
        "additionalEventData": {"MFAUsed": mfa},
        "requestParameters": params or {},
    }
    if error:
        record["errorCode"] = error
    return record


def generate():
    alice = "arn:aws:iam::111:user/alice"
    bob = "arn:aws:iam::111:user/bob"
    root = "arn:aws:iam::111:root"
    records = []
    manifest = []

    for hour in range(9, 17):
        records.append(_record("GetCallerIdentity", alice,
                               time=f"2026-01-01T{hour:02d}:00:00Z"))
        records.append(_record("ListBuckets", alice, source="s3.amazonaws.com",
                               time=f"2026-01-01T{hour:02d}:05:00Z"))

    records.append(_record("ConsoleLogin", alice, source="signin.amazonaws.com",
                           mfa="Yes", time="2026-01-01T08:00:00Z"))

    records.append(_record("GetObject", alice, source="s3.amazonaws.com",
                           key="AKIALEAK", ip="10.0.0.5",
                           time="2026-01-02T02:00:00Z"))
    records.append(_record("GetObject", alice, source="s3.amazonaws.com",
                           key="AKIALEAK", ip="203.0.113.9",
                           time="2026-01-02T02:03:00Z"))
    manifest.append({"rule": "leaked_credentials", "identity": alice})

    records.append(_record("AttachUserPolicy", bob,
                           params={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                                   "userName": "bob"},
                           time="2026-01-02T03:00:00Z"))
    manifest.append({"rule": "privilege_escalation", "identity": bob})

    for minute in range(0, 40, 2):
        records.append(_record("DescribeInstances", bob, source="ec2.amazonaws.com",
                               time=f"2026-01-02T04:{minute:02d}:00Z"))
    manifest.append({"rule": "recon", "identity": bob})

    records.append(_record("StopLogging", bob, source="cloudtrail.amazonaws.com",
                           params={"name": "main-trail"},
                           time="2026-01-02T05:00:00Z"))
    manifest.append({"rule": "security_controls", "identity": bob})

    records.append(_record("CreateAccessKey", root, itype="Root", key=None,
                           time="2026-01-02T06:00:00Z"))
    manifest.append({"rule": "root_usage", "identity": root})

    records.append(_record("ConsoleLogin", bob, source="signin.amazonaws.com",
                           mfa="No", time="2026-01-02T07:00:00Z"))
    manifest.append({"rule": "console_mfa", "identity": bob})

    return records, manifest


def write_dataset(path):
    records, manifest = generate()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"Records": records}, handle, indent=2)
    return manifest
