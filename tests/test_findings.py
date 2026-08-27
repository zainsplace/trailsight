from trailsight.findings import Finding, SEVERITIES


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
