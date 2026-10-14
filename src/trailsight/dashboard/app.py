import uuid

from flask import Flask, jsonify, render_template, request

from trailsight.engine import scan_records
from trailsight.events import LoadError, records_from_bytes
from trailsight.explain import ExplanationError, OllamaProvider, explain_finding
from trailsight.generator import generate

RECENT_SCANS = 8

_scans = {}


def _store(findings):
    scan_id = uuid.uuid4().hex
    _scans[scan_id] = findings
    while len(_scans) > RECENT_SCANS:
        del _scans[next(iter(_scans))]
    return scan_id


def _summary(findings):
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {"total": len(findings), "by_severity": counts}


def _render_results(records):
    findings = scan_records(records)
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
        uploads = [u for u in request.files.getlist("logfile") if u.filename]
        if not uploads:
            return render_template("index.html",
                                   error="Choose a CloudTrail file to scan.")
        try:
            records = [record for upload in uploads
                       for record in records_from_bytes(upload.read(),
                                                        upload.filename)]
        except LoadError as error:
            return render_template("index.html", error=str(error))
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
