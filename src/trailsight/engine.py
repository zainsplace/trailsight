from trailsight.events import events_from_records, load_events
from trailsight.findings import by_severity
from trailsight.rules import run_rules


def scan_records(records):
    return by_severity(run_rules(events_from_records(records)))


def scan(paths):
    return by_severity(run_rules(load_events(paths)))
