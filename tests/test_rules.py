from datetime import datetime, timedelta, timezone

from trailsight.rules import RULES, run_rules
from trailsight.events import Event
from trailsight.rules.leaked_credentials import detect as leaked_detect
from trailsight.rules.privilege_escalation import detect as privesc_detect


def _event(name, arn="arn:aws:iam::111:user/x", **kw):
    base = dict(
        time=datetime(2026, 1, 1, tzinfo=timezone.utc), name=name, source="",
        region="eu-west-1", identity_arn=arn, identity_type="IAMUser",
        access_key_id="AKIA1", source_ip="10.0.0.1", error_code=None,
        mfa_used=True, request_parameters={}, raw={},
    )
    base.update(kw)
    return Event(**base)


def test_run_rules_returns_a_list():
    assert isinstance(run_rules([_event("GetCallerIdentity")]), list)


def test_rules_registry_is_populated():
    assert len(RULES) >= 6


def test_leaked_credentials_fires_on_two_ips():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("GetObject", access_key_id="AKIALEAK", source_ip="10.0.0.5", time=t),
        _event("GetObject", access_key_id="AKIALEAK", source_ip="203.0.113.9",
               time=t + timedelta(minutes=3)),
    ]
    findings = leaked_detect(events)
    assert len(findings) == 1
    assert findings[0].rule == "leaked_credentials"


def test_leaked_credentials_silent_on_single_ip():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("GetObject", access_key_id="AKIANORMAL", source_ip="10.0.0.5", time=t),
        _event("GetObject", access_key_id="AKIANORMAL", source_ip="10.0.0.5",
               time=t + timedelta(minutes=3)),
    ]
    assert leaked_detect(events) == []


def test_privesc_fires_on_admin_attach():
    events = [_event("AttachUserPolicy", request_parameters={
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "userName": "bob"})]
    findings = privesc_detect(events)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_privesc_silent_on_readonly_attach():
    events = [_event("AttachUserPolicy", request_parameters={
        "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        "userName": "bob"})]
    assert privesc_detect(events) == []
