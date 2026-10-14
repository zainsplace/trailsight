import gzip
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GZIP_MAGIC = b"\x1f\x8b"
LOG_SUFFIXES = (".json", ".json.gz")
DIGEST_MARKER = "CloudTrail-Digest"


class LoadError(Exception):
    pass


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


def records_from_bytes(data, name):
    if data.startswith(GZIP_MAGIC):
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            raise LoadError(f"{name} does not look like a CloudTrail export: "
                            "it is not a valid gzip file") from None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LoadError(f"{name} does not look like a CloudTrail export: "
                        "it is not valid JSON") from None
    records = parsed.get("Records") if isinstance(parsed, dict) else parsed
    if not isinstance(records, list):
        raise LoadError(f"{name} does not look like a CloudTrail export: "
                        "it has no list of Records")
    return records


def _log_files(folder):
    return [
        path for path in sorted(folder.rglob("*"))
        if path.is_file() and path.name.endswith(LOG_SUFFIXES)
        and DIGEST_MARKER not in path.name
    ]


def _records_from_path(path):
    path = Path(path)
    if path.is_dir():
        files = _log_files(path)
        if not files:
            raise LoadError(f"{path} contains no CloudTrail log files")
        return [record for file in files for record in _records_from_path(file)]
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise LoadError(f"{path} does not exist") from None
    except OSError as error:
        raise LoadError(f"{path} could not be read: {error.strerror}") from None
    return records_from_bytes(data, str(path))


def load_records(paths):
    if isinstance(paths, (str, Path)):
        paths = [paths]
    return [record for path in paths for record in _records_from_path(path)]


def load_events(paths):
    return events_from_records(load_records(paths))
