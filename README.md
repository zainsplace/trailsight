# TrailSight

Self-hostable, explainable threat detection for AWS CloudTrail.

> Status: early development. The detection engine is being built in the open,
> one piece at a time. See the roadmap below for what works today and what is
> coming next.

TrailSight reads AWS CloudTrail activity and flags identity and API level
attacks that commonly hit small AWS accounts. Every finding will come with the
evidence that triggered it, and can optionally be explained in plain English by
a language model of your choice, including a local one.

It is free, runs entirely on your own machine, and does not send your logs
anywhere unless you explicitly turn on explanations.

## Why

GuardDuty is a black box, and Wiz and Datadog are priced for companies.
TrailSight is for the solo developer or small team that wants to understand what
is happening in their AWS account without paying for an enterprise platform or
handing their logs to a vendor.

## What it will detect

- Leaked credentials: one access key used from multiple locations in a short time
- Privilege escalation: an administrator policy attached to a principal
- Reconnaissance: bursts of enumeration calls
- Disabled security controls: CloudTrail or GuardDuty turned off
- Root account activity
- Console logins without MFA

## Design

The detection pipeline and its principles are documented in
[docs/design.md](docs/design.md). In short: deterministic rules and, later,
per-identity anomaly detection do the detecting; a language model only ever
explains findings that have already been made. It never decides what is a
threat, so the tool is trustworthy with explanations switched off.

## Roadmap

- **v0.1** (in progress) — CloudTrail loader, synthetic attack dataset, the core
  detection rules, optional explanations, and a command line interface
- **v0.2** — per-identity anomaly detection for novel behaviour
- **v0.3** — reading CloudTrail directly from S3 and CloudWatch
- **v0.4** — a self-hosted dashboard for continuous monitoring

## Development

Requires Python 3.12 or newer.

    git clone https://github.com/zainsplace/trailsight
    cd trailsight
    python -m pip install -e . pytest ruff
    python -m ruff check src tests
    python -m pytest

## License

MIT. See [LICENSE](LICENSE).
