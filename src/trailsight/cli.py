import argparse
import json

from trailsight.engine import scan
from trailsight.generator import write_dataset


def _finding_to_dict(finding):
    return {
        "rule": finding.rule,
        "severity": finding.severity,
        "title": finding.title,
        "identity": finding.identity,
        "description": finding.description,
        "evidence": [
            {"time": e.time.isoformat(), "name": e.name, "source_ip": e.source_ip,
             "region": e.region}
            for e in finding.events
        ],
    }


def _print_text(findings):
    if not findings:
        print("No findings. The trail looks clean.")
        return
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.title}")
        print(f"  rule: {finding.rule}")
        print(f"  identity: {finding.identity}")
        print(f"  {finding.description}")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="trailsight")
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate", help="Write a synthetic dataset")
    generate.add_argument("--output", required=True)

    scanner = sub.add_parser("scan", help="Scan a CloudTrail JSON file")
    scanner.add_argument("--input", required=True)
    scanner.add_argument("--format", choices=["json", "text"], default="text")

    args = parser.parse_args(argv)

    if args.command == "generate":
        write_dataset(args.output)
        print(f"Wrote synthetic dataset to {args.output}")
        return 0

    findings = scan(args.input)

    if args.format == "json":
        print(json.dumps([_finding_to_dict(f) for f in findings], indent=2))
    else:
        _print_text(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
