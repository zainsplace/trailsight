"""Run Trailsight over the public flaws.cloud CloudTrail logs.

The logs come from flaws.cloud and flaws2.cloud, public AWS security
challenges, so most traffic is strangers attacking a deliberately weak
account. There are no labels, so this measures speed and alert volume, and
draws a fixed random sample of findings per rule for manual triage.

    python evaluation/fetch_data.py
    python evaluation/run_flaws.py            # timings
    python evaluation/run_flaws.py --memory   # peak memory (slower)
"""
import json
import random
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path

from trailsight.events import events_from_records, load_records
from trailsight.rules import RULES

from triage import classify, tally

HERE = Path(__file__).parent
DATA = HERE / "data" / "flaws" / "flaws_cloudtrail_logs"
RESULTS = HERE / "results"
SAMPLE_PER_RULE = 10
SEED = 20261122


def main():
    RESULTS.mkdir(exist_ok=True)
    measure_memory = "--memory" in sys.argv
    if measure_memory:
        tracemalloc.start()
    started = time.perf_counter()
    records = load_records(DATA)
    loaded = time.perf_counter()
    events = events_from_records(records)
    parsed = time.perf_counter()

    findings, rule_seconds = [], {}
    for rule in RULES:
        name = rule.__module__.rsplit(".", 1)[-1]
        t = time.perf_counter()
        out = rule(events)
        rule_seconds[name] = round(time.perf_counter() - t, 2)
        findings.extend(out)
    finished = time.perf_counter()
    peak_mb = tracemalloc.get_traced_memory()[1] / 1e6 if measure_memory else None

    by_rule = Counter(f.rule for f in findings)
    identities = {r: len({f.identity for f in findings if f.rule == r}) for r in by_rule}
    detect_seconds = finished - parsed
    summary = {
        "events": len(events),
        "first_event": min(e.time for e in events).isoformat(),
        "last_event": max(e.time for e in events).isoformat(),
        "load_seconds": round(loaded - started, 1),
        "parse_seconds": round(parsed - loaded, 1),
        "detect_seconds": round(detect_seconds, 1),
        "detect_events_per_second": round(len(events) / detect_seconds),
        "end_to_end_events_per_second": round(len(events) / (finished - started)),
        "peak_memory_mb": round(peak_mb) if peak_mb else None,
        "rule_seconds": rule_seconds,
        "findings": len(findings),
        "findings_per_1000_events": round(1000 * len(findings) / len(events), 2),
        "findings_by_rule": dict(by_rule.most_common()),
        "distinct_identities_by_rule": identities,
    }
    verdicts = [dict(zip(("verdict", "reason"), classify("flaws", f)), rule=f.rule)
                for f in findings]
    summary["triage"] = tally(verdicts)
    root_days = {(f.identity, f.events[0].time.date()) for f, v in zip(findings, verdicts)
                 if f.rule == "root_usage" and v["verdict"] == "BTP"}
    summary["root_usage_distinct_days"] = len(root_days)
    reasons = {}
    for v in verdicts:
        key = f"{v['rule']} {v['verdict']}: {v['reason']}"
        reasons[key] = reasons.get(key, 0) + 1
    summary["triage_reasons"] = dict(sorted(reasons.items()))
    (RESULTS / "flaws_summary.json").write_text(json.dumps(summary, indent=2))

    rng = random.Random(SEED)
    sample = []
    for rule in sorted(by_rule):
        pool = [f for f in findings if f.rule == rule]
        for f in rng.sample(pool, min(SAMPLE_PER_RULE, len(pool))):
            first = f.events[0].raw
            verdict, reason = classify("flaws", f)
            sample.append({
                "verdict": verdict,
                "reason": reason,
                "rule": f.rule,
                "identity": f.identity,
                "time": f.events[0].time.isoformat(),
                "event_count": len(f.events),
                "event_names": sorted({e.name for e in f.events})[:8],
                "source_ips": sorted({e.source_ip for e in f.events})[:6],
                "error_codes": sorted({e.error_code or "" for e in f.events}),
                "user_agent": first.get("userAgent", "")[:120],
                "invoked_by": first.get("userIdentity", {}).get("invokedBy"),
                "login_result": (first.get("responseElements") or {}).get("ConsoleLogin"),
            })
    (RESULTS / "flaws_sample.json").write_text(json.dumps(sample, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
