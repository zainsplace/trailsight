from datetime import timedelta

from trailsight.findings import Finding
from trailsight.rules import register

PREFIXES = ("Describe", "List", "Get")
WINDOW = timedelta(minutes=30)
THRESHOLD = 15


@register
def detect(events):
    by_identity = {}
    for event in events:
        if event.name.startswith(PREFIXES):
            by_identity.setdefault(event.identity_arn, []).append(event)

    findings = []
    for identity, reads in by_identity.items():
        reads.sort(key=lambda e: e.time)
        for index, start in enumerate(reads):
            window = [e for e in reads[index:] if e.time - start.time <= WINDOW]
            if len(window) >= THRESHOLD:
                findings.append(Finding(
                    rule="recon",
                    severity="medium",
                    title="Reconnaissance burst",
                    identity=identity,
                    events=window,
                    description=(
                        f"{identity} made {len(window)} enumeration calls within "
                        "30 minutes, a pattern typical of an attacker mapping the "
                        "account after gaining access."
                    ),
                ))
                break
    return findings
