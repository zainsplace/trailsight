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
