from trailsight.findings import Finding
from trailsight.rules import register

IGNORED = {"ConsoleLogin"}


@register
def detect(events):
    findings = []
    for event in events:
        if event.identity_type != "Root" or event.name in IGNORED:
            continue
        findings.append(Finding(
            rule="root_usage",
            severity="high",
            title="Root account activity",
            identity=event.identity_arn,
            events=[event],
            description=(
                f"The account root identity performed {event.name}. Root should "
                "be locked away and never used for day-to-day actions, so this "
                "warrants immediate review."
            ),
        ))
    return findings
