from pathlib import Path
from functools import wraps

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from file_ingestion import LogFileReader
from investigation_service import InvestigationService
from log_parser import LogParser
from reporting import ReportExporter
from repository import LogRepository
from scoring import CompositeRiskScorer, EventClassifier, EventScoringService, HeuristicRiskScorer, LstmRiskScorer
from summary import InvestigationSummary


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "forensics.db"

repository = LogRepository(DB_PATH)
summary_builder = InvestigationSummary()
report_exporter = ReportExporter()
file_reader = LogFileReader()
investigation_service = InvestigationService(
    parser=LogParser(),
    scoring_service=EventScoringService(
        risk_scorer=CompositeRiskScorer(LstmRiskScorer(), HeuristicRiskScorer()),
        classifier=EventClassifier(),
    ),
    repository=repository,
    summary_builder=summary_builder,
)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.secret_key = "cyber-forensics-demo-secret"

USERS = {
    "admin1": {
        "password_hash": generate_password_hash("admin123"),
        "role": "Administrator",
    },
    "manager1": {
        "password_hash": generate_password_hash("manager123"),
        "role": "Investigation Manager",
    },
}


def init_db():
    repository.initialize()


def request_filters():
    return {
        "search": request.args.get("search", ""),
        "verdict": request.args.get("verdict", ""),
        "severity": request.args.get("severity", ""),
        "source_ip": request.args.get("source_ip", ""),
        "event_type": request.args.get("event_type", ""),
    }


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith("/upload") or request.path.startswith("/get") or request.path.startswith("/export") or request.path.startswith("/clear"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)

    return wrapped_view


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = USERS.get(username)

        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("index.html", username=session["username"], role=session["role"])


@app.post("/upload_logs")
@login_required
def upload_logs():
    payload = request.get_json(force=True)
    logs = payload.get("logs", "")
    case_name = payload.get("case_name") or "Default Investigation"
    result = investigation_service.ingest(logs, case_name)
    return jsonify({"status": "processed", "summary": result["summary"], "events": result["events"][:50]})


@app.post("/upload_file")
@login_required
def upload_file():
    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return jsonify({"error": "No log file was uploaded."}), 400

    case_name = request.form.get("case_name") or uploaded_file.filename or "Uploaded System Logs"

    try:
        logs = file_reader.read(uploaded_file.filename, uploaded_file.read())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    result = investigation_service.ingest(logs, case_name)
    return jsonify({"status": "processed", "summary": result["summary"], "events": result["events"][:50]})


@app.get("/get_results")
@login_required
def get_results():
    limit = min(max(int(request.args.get("limit", 250)), 1), 1000)
    return jsonify(investigation_service.search(request_filters(), limit=limit))


@app.get("/export/<file_type>")
@login_required
def export_report(file_type):
    result = investigation_service.search(request_filters(), limit=1000)
    summary = result["summary"]
    events = result["events"]

    if file_type == "json":
        return Response(
            report_exporter.json_report(summary, events),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=forensic_report.json"},
        )

    if file_type == "csv":
        return Response(
            report_exporter.csv_report(events),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=forensic_report.csv"},
        )

    if file_type == "pdf":
        return Response(
            report_exporter.pdf_report(summary, events),
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=forensic_report.pdf"},
        )

    return Response("Unsupported export type", status=400)


@app.delete("/clear_logs")
@login_required
def clear_logs():
    repository.clear()
    return jsonify({"status": "cleared"})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
