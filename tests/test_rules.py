from datetime import datetime, timezone

from trailsight.rules import RULES, run_rules
from trailsight.events import Event


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
