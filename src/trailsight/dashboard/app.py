import json
import uuid

from flask import Flask, jsonify, render_template, request

from trailsight.events import events_from_records
from trailsight.explain import ExplanationError, OllamaProvider, explain_finding
from trailsight.generator import generate
from trailsight.rules import run_rules

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RECENT_SCANS = 8

_scans = {}


def _store(findings):
    scan_id = uuid.uuid4().hex
    _scans[scan_id] = findings
    while len(_scans) > RECENT_SCANS:
        del _scans[next(iter(_scans))]
    return scan_id


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
                           summary=_summary(findings),
                           scan_id=_store(findings))


def create_app(ollama_model="llama3", ollama_host="http://localhost:11434"):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
    app.config["OLLAMA_MODEL"] = ollama_model
    app.config["OLLAMA_HOST"] = ollama_host

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

    @app.post("/explain")
    def explain():
        payload = request.get_json(silent=True) or {}
        findings = _scans.get(payload.get("scan_id"))
        index = payload.get("index")
        if findings is None or not isinstance(index, int) or not (
                0 <= index < len(findings)):
            return jsonify({"error": "That finding is no longer available. "
                                     "Run the scan again."}), 404
        provider = OllamaProvider(model=app.config["OLLAMA_MODEL"],
                                  host=app.config["OLLAMA_HOST"])
        try:
            return jsonify({"explanation": explain_finding(findings[index],
                                                           provider)})
        except ExplanationError as error:
            return jsonify({"error": str(error)}), 503

    return app
