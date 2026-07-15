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
