from datetime import datetime, timedelta, timezone

from trailsight.rules import RULES, run_rules
from trailsight.events import Event
from trailsight.rules.leaked_credentials import detect as leaked_detect
from trailsight.rules.privilege_escalation import detect as privesc_detect
from trailsight.rules.recon import detect as recon_detect
from trailsight.rules.security_controls import detect as controls_detect
from trailsight.rules.root_usage import detect as root_detect
from trailsight.rules.console_mfa import detect as mfa_detect


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


def test_leaked_credentials_still_fires_when_the_key_keeps_being_used():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("GetObject", access_key_id="AKIALEAK", source_ip="10.0.0.5", time=t),
        _event("GetObject", access_key_id="AKIALEAK", source_ip="203.0.113.9",
               time=t + timedelta(minutes=3)),
        _event("GetObject", access_key_id="AKIALEAK", source_ip="203.0.113.9",
               time=t + timedelta(hours=6)),
    ]
    assert len(leaked_detect(events)) == 1


def test_leaked_credentials_fires_on_a_burst_after_long_normal_use():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("GetObject", access_key_id="AKIALEAK", source_ip="10.0.0.5",
               time=t + timedelta(days=day))
        for day in range(5)
    ]
    events.append(_event("GetObject", access_key_id="AKIALEAK", source_ip="203.0.113.9",
                         time=t + timedelta(days=4, minutes=10)))
    assert len(leaked_detect(events)) == 1


def test_leaked_credentials_evidence_is_only_the_burst():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    burst = [
        _event("GetObject", access_key_id="AKIALEAK", source_ip="10.0.0.5",
               time=t + timedelta(hours=5)),
        _event("GetObject", access_key_id="AKIALEAK", source_ip="203.0.113.9",
               time=t + timedelta(hours=5, minutes=3)),
    ]
    events = [
        _event("GetObject", access_key_id="AKIALEAK", source_ip="10.0.0.5", time=t),
        *burst,
        _event("GetObject", access_key_id="AKIALEAK", source_ip="10.0.0.5",
               time=t + timedelta(hours=12)),
    ]
    assert leaked_detect(events)[0].events == burst


def test_leaked_credentials_silent_when_locations_are_hours_apart():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("GetObject", access_key_id="AKIATRAVEL", source_ip="10.0.0.5", time=t),
        _event("GetObject", access_key_id="AKIATRAVEL", source_ip="203.0.113.9",
               time=t + timedelta(hours=3)),
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


def test_recon_fires_on_enumeration_burst():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [_event("DescribeInstances", time=t + timedelta(minutes=i))
              for i in range(20)]
    findings = recon_detect(events)
    assert len(findings) == 1
    assert findings[0].rule == "recon"


def test_recon_silent_on_light_activity():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [_event("DescribeInstances", time=t + timedelta(minutes=i))
              for i in range(3)]
    assert recon_detect(events) == []


def test_controls_fires_on_stop_logging():
    findings = controls_detect([_event("StopLogging")])
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_controls_silent_on_normal_event():
    assert controls_detect([_event("GetObject")]) == []


def test_root_usage_fires_for_root_identity():
    findings = root_detect([_event("CreateAccessKey", identity_type="Root",
                                   arn="arn:aws:iam::111:root")])
    assert len(findings) == 1
    assert findings[0].rule == "root_usage"


def test_root_usage_silent_for_iam_user():
    assert root_detect([_event("CreateAccessKey", identity_type="IAMUser")]) == []


def test_mfa_fires_when_login_without_mfa():
    findings = mfa_detect([_event("ConsoleLogin", mfa_used=False)])
    assert len(findings) == 1
    assert findings[0].rule == "console_mfa"


def test_mfa_silent_when_mfa_used():
    assert mfa_detect([_event("ConsoleLogin", mfa_used=True)]) == []
