import json
import urllib.error
from datetime import datetime, timezone

import pytest

from trailsight.events import Event
from trailsight.explain import (
    ExplanationError,
    OllamaProvider,
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


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_ollama_provider_posts_the_prompt_and_returns_the_response(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse(b'{"response": "  Explained.  "}')

    monkeypatch.setattr("trailsight.explain.urllib.request.urlopen", fake_urlopen)
    provider = OllamaProvider(model="llama3", host="http://localhost:11434")
    assert provider.complete("prompt text") == "Explained."
    assert captured["url"] == "http://localhost:11434/api/generate"
    assert captured["body"] == {"model": "llama3", "prompt": "prompt text",
                                "stream": False}


def test_ollama_provider_raises_explanation_error_when_unreachable(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("trailsight.explain.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(ExplanationError):
        OllamaProvider().complete("prompt text")


def test_ollama_provider_raises_explanation_error_on_bad_body(monkeypatch):
    def fake_urlopen(request, timeout=None):
        return FakeResponse(b"not json")

    monkeypatch.setattr("trailsight.explain.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(ExplanationError):
        OllamaProvider().complete("prompt text")
