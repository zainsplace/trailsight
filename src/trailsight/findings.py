from dataclasses import dataclass

from trailsight.events import Event

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    identity: str
    events: list[Event]
    description: str
