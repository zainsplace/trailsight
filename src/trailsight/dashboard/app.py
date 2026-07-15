import json

from flask import Flask, render_template, request

from trailsight.events import events_from_records
from trailsight.generator import generate
from trailsight.rules import run_rules

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _scan_records(records):
    findings = run_rules(events_from_records(records))
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


def _summary(findings):
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {"total": len(findings), "by_severity": counts}


def _render_results(records):
    findings = _scan_records(records)
    return render_template("results.html", findings=findings,
                           summary=_summary(findings))


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/scan")
    def scan():
        upload = request.files.get("logfile")
        if upload is None:
            return render_template("index.html",
                                   error="Choose a CloudTrail JSON file to scan.")
        try:
            data = json.loads(upload.read().decode("utf-8"))
            records = data["Records"] if isinstance(data, dict) else data
            if not isinstance(records, list):
                raise ValueError
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, KeyError):
            return render_template(
                "index.html",
                error="That does not look like a CloudTrail JSON export.")
        return _render_results(records)

    @app.get("/demo")
    def demo():
        records, _ = generate()
        return _render_results(records)

    return app
