from trailsight.findings import SEVERITIES, Finding, at_least, by_severity


def test_finding_holds_evidence_and_valid_severity():
    finding = Finding(
        rule="demo",
        severity="high",
        title="Demo",
        identity="arn:aws:iam::111:user/alice",
        events=[],
        description="A demo finding.",
    )
    assert finding.severity in SEVERITIES
    assert finding.rule == "demo"


def test_finding_explanation_defaults_to_none():
    finding = Finding(rule="root_usage", severity="high", title="Root used",
                      identity="arn:aws:iam::111:root", events=[],
                      description="Root account activity.")
    assert finding.explanation is None


def test_finding_accepts_an_explanation():
    finding = Finding(rule="root_usage", severity="high", title="Root used",
                      identity="arn:aws:iam::111:root", events=[],
                      description="Root account activity.",
                      explanation="The root account was used.")
    assert finding.explanation == "The root account was used."


def _finding(severity):
    return Finding(rule="demo", severity=severity, title="Demo",
                   identity="arn:aws:iam::111:user/alice", events=[],
                   description="A demo finding.")


def test_by_severity_puts_the_most_severe_first():
    findings = [_finding(s) for s in ("medium", "critical", "low", "high")]
    ordered = [f.severity for f in by_severity(findings)]
    assert ordered == ["critical", "high", "medium", "low"]


def test_by_severity_keeps_rule_order_within_a_severity():
    first, second = _finding("high"), _finding("high")
    ordered = by_severity([_finding("low"), first, second])
    assert ordered[0] is first and ordered[1] is second


def test_at_least_drops_findings_below_the_minimum():
    findings = [_finding(s) for s in ("low", "medium", "high", "critical")]
    kept = [f.severity for f in at_least(findings, "high")]
    assert kept == ["high", "critical"]


def test_at_least_low_keeps_everything():
    findings = [_finding(s) for s in SEVERITIES]
    assert at_least(findings, "low") == findings
