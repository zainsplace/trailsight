from trailsight.findings import Finding
from trailsight.rules import register


@register
def detect(events):
    findings = []
    for event in events:
        if event.name != "ConsoleLogin" or event.mfa_used:
            continue
        findings.append(Finding(
            rule="console_mfa",
            severity="medium",
            title="Console login without MFA",
            identity=event.identity_arn,
            events=[event],
            description=(
                f"{event.identity_arn} signed in to the console without "
                "multi-factor authentication, leaving the account one stolen "
                "password away from takeover."
            ),
        ))
    return findings
