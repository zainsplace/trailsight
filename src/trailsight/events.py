import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class Event:
    time: datetime
    name: str
    source: str
    region: str
    identity_arn: str
    identity_type: str
    access_key_id: str | None
    source_ip: str
    error_code: str | None
    mfa_used: bool
    request_parameters: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


def _parse_time(value):
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def event_from_record(record):
    identity = record.get("userIdentity", {})
    additional = record.get("additionalEventData", {})
    return Event(
        time=_parse_time(record.get("eventTime")),
        name=record.get("eventName", ""),
        source=record.get("eventSource", ""),
        region=record.get("awsRegion", ""),
        identity_arn=identity.get("arn", ""),
        identity_type=identity.get("type", ""),
        access_key_id=identity.get("accessKeyId"),
        source_ip=record.get("sourceIPAddress", ""),
        error_code=record.get("errorCode"),
        mfa_used=str(additional.get("MFAUsed", "")).lower() == "yes",
        request_parameters=record.get("requestParameters") or {},
        raw=record,
    )


def events_from_records(records):
    return [event_from_record(record) for record in records]


def load_events(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    records = data["Records"] if isinstance(data, dict) else data
    return events_from_records(records)
