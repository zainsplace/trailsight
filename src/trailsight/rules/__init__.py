RULES = []


def register(rule):
    RULES.append(rule)
    return rule


def run_rules(events):
    findings = []
    for rule in RULES:
        findings.extend(rule(events))
    return findings
