from trailsight.events import load_events
from trailsight.rules import run_rules


def scan(path):
    return run_rules(load_events(path))
