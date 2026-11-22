"""Run Trailsight against Splunk's attack_data CloudTrail samples.

Ground truth is evaluation/labels.csv, written from each dataset's name and
contents before any rule was run. Findings are written to
evaluation/results/splunk_findings.json for triage.

    python evaluation/fetch_data.py
    python evaluation/run_splunk.py
"""
import csv
import json
from pathlib import Path

from trailsight.engine import scan_records

from triage import classify, tally

HERE = Path(__file__).parent
DATA = HERE / "data" / "splunk"
RESULTS = HERE / "results"


def read_ndjson(path):
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def main():
    RESULTS.mkdir(exist_ok=True)
    labels = list(csv.DictReader((HERE / "labels.csv").open(encoding="utf-8")))
    rows, all_findings = [], []
    for label in labels:
        if label["scope"] == "excluded":
            continue
        records = read_ndjson(DATA / label["dataset"])
        findings = scan_records(records)
        rules = sorted({f.rule for f in findings})
        expected = label["expected_rule"]
        rows.append({
            "dataset": label["dataset"],
            "scope": label["scope"],
            "expected_rule": expected,
            "adjacent_to": label["adjacent_to"],
            "events": len(records),
            "findings": len(findings),
            "rules_fired": rules,
            "detected": expected in rules if expected else None,
        })
        for f in findings:
            verdict, reason = classify("splunk", f)
            all_findings.append({
                "verdict": verdict,
                "reason": reason,
                "dataset": label["dataset"],
                "rule": f.rule,
                "severity": f.severity,
                "identity": f.identity,
                "event_names": sorted({e.name for e in f.events}),
                "source_ips": sorted({e.source_ip for e in f.events}),
                "description": f.description,
            })

    (RESULTS / "splunk_triage.json").write_text(json.dumps(tally(all_findings), indent=2))
    (RESULTS / "splunk_datasets.json").write_text(json.dumps(rows, indent=2))
    (RESULTS / "splunk_findings.json").write_text(json.dumps(all_findings, indent=2))

    inscope = [r for r in rows if r["scope"] == "in"]
    hit = sum(r["detected"] for r in inscope)
    print(f"In-scope datasets detected: {hit}/{len(inscope)}")
    for r in inscope:
        mark = "HIT " if r["detected"] else "MISS"
        print(f"  {mark} {r['expected_rule']:20} {r['dataset'][:70]}")
    out = [r for r in rows if r["scope"] == "out"]
    fired = [r for r in out if r["findings"]]
    print(f"Out-of-scope datasets with any finding: {len(fired)}/{len(out)}")
    for r in fired:
        print(f"  {r['rules_fired']} {r['dataset'][:70]}")
    print(f"Total findings: {len(all_findings)}")
    for rule, counts in tally(all_findings).items():
        print(f"  {rule:20} {counts}")


if __name__ == "__main__":
    main()
