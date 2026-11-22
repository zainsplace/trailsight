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


def _root(name, time, **kw):
    return _event(name, arn="arn:aws:iam::111:root", identity_type="Root",
                  time=time, **kw)


def test_root_usage_groups_one_day_into_one_finding():
    t = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)
    events = [_root("ListUsers", t + timedelta(minutes=i)) for i in range(30)]
    findings = root_detect(events)
    assert len(findings) == 1
    assert len(findings[0].events) == 30
    assert "30 API calls on 2026-01-01" in findings[0].description


def test_root_usage_gives_each_day_its_own_finding():
    t = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)
    events = [_root("ListUsers", t), _root("ListUsers", t + timedelta(days=1))]
    assert len(root_detect(events)) == 2


def test_root_usage_ignores_calls_aws_makes_on_roots_behalf():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _root("DescribeAccountLimits", t, invoked_by="support.amazonaws.com",
              source_ip="support.amazonaws.com"),
        _root("GetBucketLocation", t, source_ip="AWS Internal"),
    ]
    assert root_detect(events) == []


def test_mfa_silent_on_failed_login():
    events = [_event("ConsoleLogin", mfa_used=False, login_result="Failure")]
    assert mfa_detect(events) == []


def test_mfa_silent_on_federated_and_role_sessions():
    events = [
        _event("ConsoleLogin", mfa_used=False, login_result="Success",
               identity_type="AssumedRole"),
        _event("ConsoleLogin", mfa_used=False, login_result="Success",
               identity_type="FederatedUser"),
    ]
    assert mfa_detect(events) == []


def test_mfa_fires_for_root_password_login():
    events = [_event("ConsoleLogin", mfa_used=False, login_result="Success",
                     identity_type="Root", arn="arn:aws:iam::111:root")]
    assert len(mfa_detect(events)) == 1


def test_leaked_credentials_ignores_aws_internal_as_a_location():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("GetObject", access_key_id="AKIAONE", source_ip="10.0.0.5", time=t),
        _event("GetObject", access_key_id="AKIAONE", source_ip="AWS Internal",
               time=t + timedelta(minutes=1)),
    ]
    assert leaked_detect(events) == []


def test_leaked_credentials_ignores_lambda():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("CreateLogStream", access_key_id="ASIALAMBDA", source_ip=ip,
               user_agent="awslambda-worker/1.0", time=t + timedelta(minutes=i))
        for i, ip in enumerate(["3.8.0.1", "3.8.0.2", "3.8.0.3"])
    ]
    assert leaked_detect(events) == []


def test_leaked_credentials_fires_on_root_sessions_from_two_places():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _root("DescribeEventAggregates", t, access_key_id="ASIAONE",
              source_ip="54.188.0.152"),
        _root("DescribeEventAggregates", t + timedelta(seconds=2),
              access_key_id="ASIATWO", source_ip="23.93.193.6"),
    ]
    findings = leaked_detect(events)
    assert len(findings) == 1
    assert "root account" in findings[0].description


def test_leaked_credentials_fires_on_console_logins_from_two_places():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("ConsoleLogin", access_key_id=None, source_ip="34.210.39.194",
               login_result="Success", time=t),
        _event("ConsoleLogin", access_key_id=None, source_ip="34.217.70.77",
               login_result="Success", time=t + timedelta(minutes=30)),
    ]
    findings = leaked_detect(events)
    assert len(findings) == 1
    assert "signed in to the console" in findings[0].description


def test_leaked_credentials_silent_on_failed_logins_from_two_places():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _event("ConsoleLogin", access_key_id=None, source_ip=ip,
               login_result="Failure", time=t + timedelta(minutes=i))
        for i, ip in enumerate(["34.210.39.194", "34.217.70.77"])
    ]
    assert leaked_detect(events) == []


def test_leaked_credentials_reports_a_root_burst_once():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        _root("ListUsers", t, access_key_id="ASIAROOT", source_ip="54.188.0.152"),
        _root("ListUsers", t + timedelta(minutes=1), access_key_id="ASIAROOT",
              source_ip="23.93.193.6"),
    ]
    assert len(leaked_detect(events)) == 1
