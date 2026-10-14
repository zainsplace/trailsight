from dataclasses import dataclass

from trailsight.events import Event

SEVERITIES = ("low", "medium", "high", "critical")
_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    identity: str
    events: list[Event]
    description: str
    explanation: str | None = None


def by_severity(findings):
    return sorted(findings, key=lambda f: -_RANK.get(f.severity, -1))


def at_least(findings, minimum):
    floor = _RANK[minimum]
    return [f for f in findings if _RANK.get(f.severity, -1) >= floor]
