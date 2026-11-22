from trailsight.findings import Finding
from trailsight.rules import register
from trailsight.rules._common import made_by_aws

IGNORED = {"ConsoleLogin"}
EXAMPLES = 3


@register
def detect(events):
    days = {}
    for event in events:
        if event.identity_type != "Root" or event.name in IGNORED:
            continue
        if made_by_aws(event):
            continue
        days.setdefault((event.identity_arn, event.time.date()), []).append(event)

    findings = []
    for (identity, day), day_events in days.items():
        day_events.sort(key=lambda e: e.time)
        names = list(dict.fromkeys(e.name for e in day_events))
        shown = ", ".join(names[:EXAMPLES])
        if len(names) > EXAMPLES:
            shown += f" and {len(names) - EXAMPLES} other actions"
        calls = "call" if len(day_events) == 1 else "calls"
        findings.append(Finding(
            rule="root_usage",
            severity="high",
            title="Root account activity",
            identity=identity,
            events=day_events,
            description=(
                f"The account root identity made {len(day_events)} API {calls} "
                f"on {day.isoformat()}: {shown}. Root should be locked away and "
                "never used for day-to-day actions, so this warrants immediate "
                "review."
            ),
        ))
    return findings
