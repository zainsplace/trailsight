from datetime import timedelta

from trailsight.findings import Finding
from trailsight.rules import register

WINDOW = timedelta(hours=1)


@register
def detect(events):
    by_key = {}
    for event in events:
        if event.access_key_id:
            by_key.setdefault(event.access_key_id, []).append(event)

    findings = []
    for key, key_events in by_key.items():
        key_events.sort(key=lambda e: e.time)
        ips = {e.source_ip for e in key_events}
        if len(ips) < 2:
            continue
        span = key_events[-1].time - key_events[0].time
        if span > WINDOW:
            continue
        findings.append(Finding(
            rule="leaked_credentials",
            severity="high",
            title="Access key used from multiple locations",
            identity=key_events[0].identity_arn,
            events=key_events,
            description=(
                f"Access key {key} was used from {len(ips)} different source "
                "addresses within an hour, which suggests the key has been "
                "shared or stolen."
            ),
        ))
    return findings
