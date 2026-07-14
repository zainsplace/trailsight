# TrailSight — Design

Status: draft
Date: 2026-07-14

## Summary

TrailSight is a self-hostable threat detection tool for AWS CloudTrail. It reads
CloudTrail activity, detects identity and API level attacks, and explains each
finding in plain English. It is aimed at solo developers and small teams who
cannot justify enterprise tooling and find the built-in options opaque.

The tool is free, runs entirely on the user's own infrastructure, and explains
why every finding was raised rather than emitting an unexplained severity score.

## Problem

Small AWS users are poorly served by the current options:

- GuardDuty is cheap and built in, but it is a black box. It tells you the
  severity, not the reasoning, and it cannot be self-hosted or extended.
- Wiz and Datadog are powerful but priced for companies, not individuals.
- Open-source options (Panther, Falco) are strong but heavy to run and aimed at
  teams with dedicated security staff.

The result is that a solo developer or a three-person startup on AWS typically
runs nothing, or runs GuardDuty and ignores the alerts because they cannot tell
which ones matter or why.

## Target user

A solo developer or small team running workloads on AWS, comfortable on the
command line, without a security budget or a dedicated security engineer. They
want to know when something dangerous happens in their account, in language they
can act on, without sending their logs to a third party.

## Positioning

TrailSight wins on three things the incumbents do not offer together:

- Free and open source.
- Fully self-hostable. Nothing leaves the user's infrastructure.
- Explainable. Every finding comes with a plain-English account of what
  happened, why it is suspicious, and how to respond.

It does not try to match the breadth of enterprise platforms. It does one data
source (CloudTrail) and one threat class (identity and API abuse) well.

## Non-goals

- Not a posture or misconfiguration scanner (CSPM). TrailSight detects activity,
  not static configuration.
- Not a multi-cloud tool. AWS only.
- Not an agent-based runtime tool. It reads logs; it does not run inside
  workloads.
- Not a managed service. The user runs it themselves.

## Architecture

The system is a pipeline. CloudTrail events enter one end and explained findings
leave the other. Each stage is an independent, testable unit.

```
CloudTrail source  ->  Loader  ->  [ Rule engine | Baseline engine ]
                                          |            |
                                          +-----+------+
                                                v
                                          Correlator
                                                v
                                        Explanation layer
                                                v
                                    Findings + explanations
```

Units and their single responsibilities:

- **Loader** reads CloudTrail events from a source (local JSON files, S3, or the
  synthetic generator) and normalizes them into one internal event model.
  Nothing downstream depends on where the logs came from.
- **Rule engine** runs deterministic detectors for known high-confidence
  attacks. Each rule emits a finding with the evidence that triggered it.
- **Baseline engine** learns each identity's normal behaviour (which APIs,
  regions, times, and source IPs it usually uses) and scores new activity for
  anomaly. This catches novel behaviour that rules do not cover.
- **Correlator** merges and deduplicates findings and attaches context, so one
  incident does not surface as dozens of separate alerts.
- **Explanation layer** turns a finding into a plain-English explanation using a
  language model, strictly grounded in the finding's evidence.
- **Output** presents findings. A CLI report first, a self-hosted dashboard
  later.

The language model sits at the end of the pipeline, downstream of detection.
Detection is performed by code that can be tested deterministically. The model
only explains findings that detection has already made. It never decides whether
something is a threat.

## Detection

### Rules

The rule engine ships with a set of detectors for the attacks that most commonly
hit small AWS accounts:

- Use of long-lived credentials from a new or unexpected source.
- Privilege escalation (for example attaching an administrator policy to a
  principal).
- Reconnaissance and enumeration bursts (many describe/list calls in a short
  window).
- Disabling of security controls (stopping CloudTrail logging, disabling
  GuardDuty, deleting log buckets).
- Impossible-travel and unusual-region sign-in patterns.

Each rule is a self-contained function over the normalized events and shared
context. It returns a finding with a type, a severity, and the exact events that
triggered it.

### Baseline (later)

The baseline engine builds a per-identity model of normal behaviour and scores
new events for how far they deviate. It uses standard anomaly detection rather
than a large model, so it is cheap to run and its output is inspectable. This is
introduced after the rule engine is solid.

## Explanation layer

The explanation layer is optional and constrained. It is what makes TrailSight
explainable, and it is designed so that the model assists without being relied
upon.

- The model is only ever called on a finding the detection engine has already
  produced. It cannot create findings.
- It receives structured evidence, not raw logs to judge: the finding type, the
  triggering events, the identity, and the rule's description. It is never asked
  whether something is malicious.
- Its task is narrow: produce "what happened", "why it is suspicious", and "how
  to respond", using only the provided evidence. The prompt forbids inventing
  facts.
- Every explanation is traceable to the structured finding. The finding stands
  on its own (severity and evidence) with explanations turned off, so the tool
  is never dependent on the model being correct.
- The layer is provider-agnostic and supports a local model through Ollama, so
  privacy-conscious users are not forced to send logs to a third party. It is
  off by default and requires no API key to use the rest of the tool.

## Data strategy

Development and testing use public CloudTrail attack datasets plus a synthetic
event generator written for the project. The generator produces normal activity
interleaved with labelled attack scenarios, so detection accuracy can be
measured against known ground truth. The tool reads real CloudTrail (local
export, S3, or CloudWatch) for actual use.

This keeps development at zero cost, safe, and reproducible, and it means every
detector can be tested against events whose correct outcome is known.

## Form factor and roadmap

The tool is built and released in slices. Each slice is a working, postable
increment.

- **v0.1** — Loader (local JSON), synthetic generator, rule engine with the core
  detectors, optional explanation layer behind a flag, CLI output (JSON and
  readable text), tests, and a README stating the full vision.
- **v0.2** — Baseline/anomaly engine.
- **v0.3** — Real CloudTrail sources (S3, CloudWatch).
- **v0.4** — Self-hosted dashboard (Docker) with continuous ingestion.

## v0.1 scope

The first release is a genuinely working tool, not a skeleton:

- Read CloudTrail events from local JSON files into the normalized model.
- Generate synthetic data: normal activity plus labelled scenarios for leaked
  credential use, privilege escalation, reconnaissance, and disabling of
  security controls.
- Run roughly six to eight rules covering those scenarios.
- Output findings as JSON and as readable text, with evidence.
- Optionally attach plain-English explanations when the flag is set and a model
  (hosted or local) is configured.
- Ship tests proving each rule fires on its scenario and stays silent on normal
  traffic.

## Testing

Detection is proven against labelled data. For every rule there is a test that
the rule fires on its attack scenario and a test that it does not fire on normal
activity. Accuracy is reported as detections against known ground truth, not
asserted.

The explanation layer is tested by mocking the model and checking that it is
only ever called with a real finding and its evidence, and that the tool
produces complete findings with explanations disabled.

## Tech stack

- Python, standard library first, minimal dependencies.
- Standard anomaly detection for the baseline engine (introduced in v0.2).
- Provider-agnostic model access with a local option via Ollama.
- Packaged with a src layout, tests, and CI from the first release.

## Success criteria

- A solo AWS user can run TrailSight against their CloudTrail logs and get
  findings they understand and can act on, without paying for anything or
  sending their logs elsewhere.
- Every detector's accuracy is demonstrable against labelled data.
- The tool is useful with the explanation layer switched off, and clearer with
  it on.
