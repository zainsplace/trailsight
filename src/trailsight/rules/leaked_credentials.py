from collections import Counter
from datetime import timedelta

from trailsight.findings import Finding
from trailsight.rules import register
from trailsight.rules._common import is_ip_address, runs_in_lambda

WINDOW = timedelta(hours=1)


def _first_burst(group):
    ips = Counter()
    end = 0
    for start, first in enumerate(group):
        while end < len(group) and group[end].time - first.time <= WINDOW:
            ips[group[end].source_ip] += 1
            end += 1
        if len(ips) >= 2:
            return group[start:end]
        ips[first.source_ip] -= 1
        if not ips[first.source_ip]:
            del ips[first.source_ip]
    return None


def _groups(events):
    """Credentials to watch, each with the events that used them.

    An access key is the obvious unit. Two more catch what keys miss: root
    gets a fresh temporary key for every session, and console sign-ins have
    no key at all, so both are also grouped by identity.
    """
    groups = {}
    for event in events:
        if not is_ip_address(event.source_ip) or runs_in_lambda(event):
            continue
        if event.access_key_id:
            groups.setdefault(("key", event.access_key_id), []).append(event)
        if event.name == "ConsoleLogin" and event.login_result == "Failure":
            continue
        if event.identity_type == "Root":
            groups.setdefault(("root", event.identity_arn), []).append(event)
        elif event.name == "ConsoleLogin":
            groups.setdefault(("console", event.identity_arn), []).append(event)
    return groups


def _description(kind, value, count):
    if kind == "key":
        return (f"Access key {value} was used from {count} different source "
                "addresses within an hour, which suggests the key has been "
                "shared or stolen.")
    if kind == "root":
        return (f"The root account was used from {count} different source "
                "addresses within an hour. Root should have one owner in one "
                "place, so this suggests its password or session was stolen.")
    return (f"{value} signed in to the console from {count} different source "
            "addresses within an hour, which suggests the password has been "
            "shared or stolen.")


@register
def detect(events):
    findings = []
    flagged = set()
    for (kind, value), group in sorted(_groups(events).items(),
                                       key=lambda item: item[0][0] != "key"):
        group.sort(key=lambda e: e.time)
        burst = _first_burst(group)
        if burst is None:
            continue
        identity = burst[0].identity_arn
        if kind != "key" and identity in flagged:
            continue
        flagged.add(identity)
        findings.append(Finding(
            rule="leaked_credentials",
            severity="high",
            title="Credentials used from multiple locations",
            identity=identity,
            events=burst,
            description=_description(kind, value, len({e.source_ip for e in burst})),
        ))
    return findings
