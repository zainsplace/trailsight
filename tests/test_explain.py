from datetime import datetime, timezone

import pytest

from trailsight.events import Event
from trailsight.explain import (
    ExplanationError,
    build_prompt,
    explain_all,
    explain_finding,
)
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


class FakeProvider:
    def __init__(self, text="Explanation text."):
        self.prompts = []
        self.text = text

    def complete(self, prompt):
        self.prompts.append(prompt)
        return self.text


class FailingProvider:
    def complete(self, prompt):
        raise ExplanationError("ollama is not running")


def test_explain_finding_calls_the_provider_once_with_the_prompt():
    provider = FakeProvider()
    text = explain_finding(_finding(), provider)
    assert text == "Explanation text."
    assert len(provider.prompts) == 1
    assert "StopLogging" in provider.prompts[0]


def test_explain_all_attaches_explanations():
    findings = [_finding(), _finding()]
    explained = explain_all(findings, FakeProvider())
    assert [f.explanation for f in explained] == ["Explanation text."] * 2


def test_explain_all_leaves_the_originals_untouched():
    findings = [_finding()]
    explain_all(findings, FakeProvider())
    assert findings[0].explanation is None


def test_explain_all_propagates_provider_failure():
    with pytest.raises(ExplanationError):
        explain_all([_finding()], FailingProvider())
