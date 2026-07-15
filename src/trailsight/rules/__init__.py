RULES = []


def register(rule):
    RULES.append(rule)
    return rule


def run_rules(events):
    findings = []
    for rule in RULES:
        findings.extend(rule(events))
    return findings


from trailsight.rules import leaked_credentials as _leaked_credentials  # noqa: E402,F401
from trailsight.rules import privilege_escalation as _privilege_escalation  # noqa: E402,F401
from trailsight.rules import recon as _recon  # noqa: E402,F401
from trailsight.rules import security_controls as _security_controls  # noqa: E402,F401
