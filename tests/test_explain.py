from datetime import datetime, timezone

from trailsight.events import Event
from trailsight.explain import build_prompt
from trailsight.findings import Finding


def _event(name="StopLogging", error_code=None, access_key_id="AKIA1"):
    return Event(
        time=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc), name=name,
        source="cloudtrail.amazonaws.com", region="eu-west-1",
        identity_arn="arn:aws:iam::111:user/bob", identity_type="IAMUser",
        access_key_id=access_key_id, source_ip="10.0.0.1",
        error_code=error_code, mfa_used=True, request_parameters={}, raw={},
    )


def _finding(events=None):
    events = events if events is not None else [_event()]
    return Finding(
        rule="security_controls", severity="critical",
        title="Security control disabled", identity="arn:aws:iam::111:user/bob",
        events=events, description="CloudTrail logging was stopped.",
    )


def test_build_prompt_contains_the_structured_fields():
    prompt = build_prompt(_finding())
    assert "security_controls" in prompt
    assert "critical" in prompt
    assert "arn:aws:iam::111:user/bob" in prompt
    assert "CloudTrail logging was stopped." in prompt


def test_build_prompt_lists_every_evidence_event():
    prompt = build_prompt(_finding([_event("StopLogging"), _event("DeleteTrail")]))
    assert "StopLogging" in prompt
    assert "DeleteTrail" in prompt
    assert "10.0.0.1" in prompt
    assert "eu-west-1" in prompt


def test_build_prompt_includes_error_code_and_key_when_present():
    prompt = build_prompt(_finding([_event(error_code="AccessDenied")]))
    assert "AccessDenied" in prompt
    assert "AKIA1" in prompt


def test_build_prompt_omits_absent_optional_fields():
    prompt = build_prompt(_finding([_event(error_code=None, access_key_id=None)]))
    assert "None" not in prompt


def test_build_prompt_forbids_inventing_facts():
    prompt = build_prompt(_finding())
    assert "only" in prompt.lower()
    assert "do not invent" in prompt.lower()
