from collections import Counter
from datetime import timedelta

from trailsight.findings import Finding
from trailsight.rules import register

WINDOW = timedelta(hours=1)


def _first_burst(key_events):
    ips = Counter()
    end = 0
    for start, first in enumerate(key_events):
        while end < len(key_events) and key_events[end].time - first.time <= WINDOW:
            ips[key_events[end].source_ip] += 1
            end += 1
        if len(ips) >= 2:
            return key_events[start:end]
        ips[first.source_ip] -= 1
        if not ips[first.source_ip]:
            del ips[first.source_ip]
    return None


@register
def detect(events):
    by_key = {}
    for event in events:
        if event.access_key_id:
            by_key.setdefault(event.access_key_id, []).append(event)

    findings = []
    for key, key_events in by_key.items():
        key_events.sort(key=lambda e: e.time)
        burst = _first_burst(key_events)
        if burst is None:
            continue
        ips = {e.source_ip for e in burst}
        findings.append(Finding(
            rule="leaked_credentials",
            severity="high",
            title="Access key used from multiple locations",
            identity=burst[0].identity_arn,
            events=burst,
            description=(
                f"Access key {key} was used from {len(ips)} different source "
                "addresses within an hour, which suggests the key has been "
                "shared or stolen."
            ),
        ))
    return findings
