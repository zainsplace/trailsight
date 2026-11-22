"""Triage verdicts for evaluation findings.

Every finding gets one verdict, using the usual security operations terms:

    TP       true positive: the rule fired on attacker activity
    BTP      benign true positive: the rule's claim is correct, but the
             activity was authorised (the account owner, their own scanner)
    FP       false positive: the rule's claim is wrong (the login failed, AWS
             itself made the call, one "location" is not an address)
    UNCLEAR  the data cannot settle it

The criteria were written after reading the findings, so they are triage,
not a detector. Each verdict carries the reason that produced it.
"""
import ipaddress

SERVICE_AGENTS = ("aws-internal", "AWSCloudTrail", "support.amazonaws.com",
                  "signin.amazonaws.com", "AWS-SupportCenterConsole")
SERVICE_ROLES = ("AWSServiceRole", "config-role", "kubernetes")
SPLUNK_SCANNERS = ("cloudsploit", "cloudmapper", "stratus")
FLAWS_OWNER_TOOLS = ("SecurityMonkey", "Cloudsploit", "SummitRouteAudit", "user/piper")
FLAWS_CHALLENGE_IDENTITIES = ("flaws/i-", "user/backup", "user/Level", "aws:ec2-instance")


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _aws_acted(event):
    raw = event.raw
    invoked_by = raw.get("userIdentity", {}).get("invokedBy") or ""
    agent = raw.get("userAgent", "")
    return (invoked_by.endswith("amazonaws.com")
            or any(marker in agent for marker in SERVICE_AGENTS)
            or not _is_ip(event.source_ip))


def classify(source, finding):
    """Return (verdict, reason) for a finding. source is 'splunk' or 'flaws'."""
    first = finding.events[0]
    raw = first.raw
    identity = finding.identity
    rule = finding.rule

    if rule == "console_mfa":
        if (raw.get("responseElements") or {}).get("ConsoleLogin") == "Failure":
            return "FP", "login failed, so nobody signed in"
        if first.identity_type == "AssumedRole":
            return "FP", "federated or role session; MFA happens at the identity provider and is not recorded"
        if source == "flaws":
            return "BTP", "account owner signing in without MFA"
        return "TP", "successful password-only login in attack data"

    if rule == "root_usage":
        # Since root findings were grouped by day, judge the whole day, not
        # its first call. Single-call findings are judged exactly as before.
        if all(_aws_acted(e) for e in finding.events):
            return "FP", "AWS made the call on the account's behalf"
        if source == "flaws":
            return "BTP", "account owner using root"
        return "TP", "root API call in attack data"

    if rule == "leaked_credentials":
        real_ips = {e.source_ip for e in finding.events if _is_ip(e.source_ip)}
        if len(real_ips) < 2:
            return "FP", "only one real address; the other 'location' is AWS itself"
        if "awslambda-worker" in raw.get("userAgent", ""):
            return "FP", "Lambda runs invocations on different hosts, so its key changes address"
        if source == "flaws" and any(m in identity for m in FLAWS_CHALLENGE_IDENTITIES):
            return "TP", "challenge credentials leaked by design, used from several places"
        if source == "flaws":
            return "BTP", "account owner"
        return "UNCLEAR", "two real addresses, no ground truth for the key"

    if rule == "recon":
        names = {e.name for e in finding.events}
        if any(m in identity for m in SERVICE_ROLES):
            return "FP", "AWS service or cluster automation"
        if source == "splunk":
            if any(m in identity for m in SPLUNK_SCANNERS):
                return "TP", "simulated attacker enumerating the account"
            if len(names) == 1:
                return "TP", f"real attack, but bulk {next(iter(names))} is collection, not reconnaissance"
            return "UNCLEAR", "administrator activity in the dataset background"
        if any(m in identity for m in FLAWS_OWNER_TOOLS):
            return "BTP", "the owner's own audit tool or console session"
        return "TP", "challenge player enumerating the account"

    if rule == "security_controls":
        if first.error_code:
            return "TP", "attempt was denied, but the finding text says it happened"
        if source == "flaws":
            return "BTP", "account owner"
        return "TP", "logging or detection disabled in attack data"

    if rule == "privilege_escalation":
        if source == "flaws":
            return "BTP", "account owner"
        return "TP", "administrator policy attached in attack data"

    return "UNCLEAR", "no triage criteria for this rule"


def tally(rows):
    """Count verdicts per rule. rows are dicts with 'rule' and 'verdict'."""
    table = {}
    for row in rows:
        counts = table.setdefault(row["rule"], {"TP": 0, "BTP": 0, "FP": 0, "UNCLEAR": 0})
        counts[row["verdict"]] += 1
    return table
