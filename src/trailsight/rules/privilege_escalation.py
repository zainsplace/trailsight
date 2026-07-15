from trailsight.findings import Finding
from trailsight.rules import register

ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}


@register
def detect(events):
    findings = []
    for event in events:
        if event.name not in ATTACH_EVENTS:
            continue
        policy = event.request_parameters.get("policyArn", "")
        if "AdministratorAccess" not in policy:
            continue
        findings.append(Finding(
            rule="privilege_escalation",
            severity="critical",
            title="Administrator policy attached",
            identity=event.identity_arn,
            events=[event],
            description=(
                f"{event.identity_arn} attached {policy} through {event.name}. "
                "Granting administrator access is a common privilege escalation "
                "step after a compromise."
            ),
        ))
    return findings
