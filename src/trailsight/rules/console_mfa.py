from trailsight.findings import Finding
from trailsight.rules import register

# Federated and role sessions sign in through an identity provider or a role
# switch. MFA happens there, and CloudTrail records MFAUsed as "No" whatever
# happened, so this rule cannot judge them.
UNJUDGEABLE_TYPES = {"AssumedRole", "FederatedUser"}


@register
def detect(events):
    findings = []
    for event in events:
        if event.name != "ConsoleLogin" or event.mfa_used:
            continue
        if event.login_result == "Failure":
            continue
        if event.identity_type in UNJUDGEABLE_TYPES:
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
