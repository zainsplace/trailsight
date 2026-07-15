from trailsight.findings import Finding
from trailsight.rules import register

DISABLING_EVENTS = {
    "StopLogging": "CloudTrail logging was stopped",
    "DeleteTrail": "A CloudTrail trail was deleted",
    "DeleteDetector": "GuardDuty threat detection was deleted",
    "DisassociateFromMasterAccount": "GuardDuty was disconnected from its master account",
}


@register
def detect(events):
    findings = []
    for event in events:
        summary = DISABLING_EVENTS.get(event.name)
        if not summary:
            continue
        findings.append(Finding(
            rule="security_controls",
            severity="critical",
            title="Security control disabled",
            identity=event.identity_arn,
            events=[event],
            description=(
                f"{summary} by {event.identity_arn}. Attackers disable logging "
                "and detection to hide their activity."
            ),
        ))
    return findings
