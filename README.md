# Trailsight

[![CI](https://github.com/zainsplace/trailsight/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zainsplace/trailsight/actions/workflows/ci.yml)

Self-hostable, explainable threat detection for AWS CloudTrail.

> Status: early development. The detection engine, the command line interface,
> the explanation layer, and the dashboard work today. Anomaly detection and
> reading logs straight from AWS are on the roadmap below.

Trailsight reads AWS CloudTrail activity and flags identity and API level
attacks that commonly hit small AWS accounts. Every finding comes with the
evidence that triggered it and a plain-English summary of why it matters. An
optional language-model layer writes fuller explanations, and it can run against
a local model.

It is free and runs entirely on your own machine. Detection is fully offline.
Explanations are optional, off by default, and with a local model through Ollama
they are offline too, so your logs never leave your machine at all.

## Why

GuardDuty is a black box, and Wiz and Datadog are priced for companies.
Trailsight is for the solo developer or small team that wants to understand what
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

### Explanations

Every finding already ships with the evidence that triggered it and a
plain-English summary. Explanations add a fuller account written by a language
model: what happened, why it is suspicious, and how to respond.

The model never decides what is a threat. It is only ever given a finding the
rules have already made, along with that finding's evidence, and asked to
explain it. Turn explanations off and the findings are unchanged.

Explanations are off by default and need a local model. Install
[Ollama](https://ollama.com), pull a model, then pass `--explain`:

    ollama pull llama3
    trailsight scan --input demo.json --explain

Point it at a different model or host if you need to:

    trailsight scan --input demo.json --explain --ollama-model mistral
    trailsight scan --input demo.json --explain --ollama-host http://localhost:11434

Nothing leaves your machine: the prompt goes to Ollama on localhost. In the
dashboard, each finding has an Explain button that does the same thing for that
one finding. If Ollama is not running, findings are still reported in full and
only the explanation is missing.

## Design

The detection pipeline and its principles are documented in
[docs/design.md](docs/design.md). In short: deterministic rules and, later,
per-identity anomaly detection do the detecting; a language model only ever
explains findings that have already been made. It never decides what is a
threat, so the tool is trustworthy with explanations switched off.

## Roadmap

- **v0.1** — CloudTrail loader, synthetic attack dataset, the six core detection
  rules, a command line interface, and an optional language-model explanation
  layer (done)
- **v0.2** — per-identity anomaly detection for novel behaviour
- **v0.3** — reading CloudTrail directly from S3 and CloudWatch
- **v0.4** — continuous monitoring in the dashboard, which currently scans a file
  at a time (the dashboard itself shipped early, in v0.1)

## Development

Requires Python 3.12 or newer.

    git clone https://github.com/zainsplace/trailsight
    cd trailsight
    python -m pip install -e . pytest ruff
    python -m ruff check src tests
    python -m pytest

## License

MIT. See [LICENSE](LICENSE).
