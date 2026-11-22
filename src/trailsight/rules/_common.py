import ipaddress
from functools import lru_cache


@lru_cache(maxsize=65536)
def is_ip_address(value):
    """CloudTrail puts a service name such as 'AWS Internal' or
    'support.amazonaws.com' here when AWS itself made the call."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def made_by_aws(event):
    """True when an AWS service made the call on the identity's behalf."""
    return bool(event.invoked_by) or not is_ip_address(event.source_ip)


def runs_in_lambda(event):
    """Lambda runs each invocation on whichever host is free, so a function's
    credentials legitimately appear from many addresses."""
    agent = event.user_agent
    return "awslambda-worker" in agent or "exec-env/AWS_Lambda" in agent
