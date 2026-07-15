# TrailSight

Self-hostable, explainable threat detection for AWS CloudTrail.

> Status: early development. The detection engine and command line interface
> work today. Anomaly detection, reading logs straight from AWS, and a dashboard
> are on the roadmap below.

TrailSight reads AWS CloudTrail activity and flags identity and API level
attacks that commonly hit small AWS accounts. Every finding comes with the
evidence that triggered it and a plain-English summary of why it matters. An
optional language-model layer that writes fuller explanations, including with a
local model, is on the roadmap.

It is free, runs entirely on your own machine, and does not send your logs
anywhere unless you explicitly turn on explanations.

## Why

GuardDuty is a black box, and Wiz and Datadog are priced for companies.
TrailSight is for the solo developer or small team that wants to understand what
is happening in their AWS account without paying for an enterprise platform or
handing their logs to a vendor.

## What it detects

- Leaked credentials: one access key used from multiple locations in a short time
- Privilege escalation: an administrator policy attached to a principal
- Reconnaissance: bursts of enumeration calls
- Disabled security controls: CloudTrail or GuardDuty turned off
- Root account activity
- Console logins without MFA

## Usage

Requires Python 3.12 or newer. Install once from a clone:

    python -m pip install -e .

Generate a synthetic dataset with planted attacks, then scan it:

    trailsight generate --output demo.json
    trailsight scan --input demo.json

Scan a real CloudTrail export and get JSON output:

    trailsight scan --input your-cloudtrail.json --format json

A scan exits with status 1 when it finds something and 0 when the trail is
clean, so it can gate a script or CI job. If the `trailsight` command is not on
your PATH, use `python -m trailsight.cli` in its place.

### Dashboard

For a visual view, install the optional dashboard and run the local server:

    python -m pip install -e ".[dashboard]"
    trailsight serve

Then open http://127.0.0.1:5000, upload a CloudTrail file or click "Load demo
data", and read the findings as severity-coloured cards. The server runs on your
machine only; nothing is uploaded anywhere.

## Design

The detection pipeline and its principles are documented in
[docs/design.md](docs/design.md). In short: deterministic rules and, later,
per-identity anomaly detection do the detecting; a language model only ever
explains findings that have already been made. It never decides what is a
threat, so the tool is trustworthy with explanations switched off.

## Roadmap

- **v0.1** — CloudTrail loader, synthetic attack dataset, the six core detection
  rules, and a command line interface (done); an optional language-model
  explanation layer (next)
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
