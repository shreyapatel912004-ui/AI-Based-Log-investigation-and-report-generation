# AI-Based Log Investigation and Alert System

This project is a cyber-forensics dashboard for ingesting logs, parsing events, detecting suspicious activity with an AI model, preserving evidence with hash chaining, filtering investigations, and exporting reports.

For full project explanation, architecture, workflow, SOLID design, database schema, and usage guide, read:

```text
PROJECT_DOCUMENTATION.md
```

## Features

- Web dashboard for log investigation
- Login and logout for demo investigator users
- Multi-line log ingestion
- File upload for text-based real logs: `.log`, `.txt`, `.csv`, `.json`, `.jsonl`, `.xml`, `.out`
- Structured parsing for IP address, timestamp, severity, and event type
- AI-assisted attack scoring using the existing LSTM model and scaler
- Heuristic fallback scoring if the model cannot load
- Explainable alert reasons for investigator review
- SQLite storage in `data/forensics.db`
- SHA-256 chain-of-custody hash for every stored log
- Search and filters by verdict, severity, source IP, event type, and raw text
- Charts for verdict distribution and top source IPs
- Export reports as JSON, CSV, and PDF

## Run

```powershell
cd C:\Users\HP\Desktop\project
venv\Scripts\python.exe main.py
```

Open:

```text
http://127.0.0.1:5000/
```


## Real System Logs

You can upload downloaded system logs if they are text-based. Linux auth logs, Apache/Nginx access logs, firewall text exports, endpoint agent logs, CSV logs, JSON logs, JSONL logs, and XML exports are supported.

Windows `.evtx` files are binary. Export them from Windows Event Viewer as XML, CSV, or TXT first, then upload the exported file.

## Main Files

- `main.py` - Flask routes and dependency wiring
- `app.py` - alternate Flask launcher that imports `main.py`
- `backend/` - parsing, scoring, storage, report generation, and investigation services
- `frontend/templates/` - dashboard and login HTML templates
- `frontend/static/` - dashboard JavaScript and CSS
- `ml_model/` - saved AI model, scaler, and NumPy evaluation assets
- `data/` - SQLite database and sample log files
- `scripts/` - model evaluation, inference, and sample-log generation helpers
- `docs/PROJECT_DOCUMENTATION.md` - full project documentation

## SOLID Design

- Single Responsibility: parsing, scoring, storage, reporting, and web routing are separate modules.
- Open/Closed: new parsers, scorers, or exporters can be added without rewriting Flask routes.
- Liskov Substitution: any class implementing `RiskScorer` can replace the current LSTM or heuristic scorer.
- Interface Segregation: the scoring interface only exposes `score`, while storage and reporting have their own focused APIs.
- Dependency Inversion: `InvestigationService` depends on injected parser, scorer, repository, and summary components instead of constructing everything internally.

## Suggested Demo Flow

1. Open the dashboard.
2. Paste or use the sample logs.
3. Click `Analyze Logs`.
4. Show total logs, alerts, attacks, risk score, charts, and timeline.
5. Filter by `ATTACK` or a source IP.
6. Export the report as PDF, CSV, or JSON.

## Model Evaluation

To benchmark the saved ML model against the included NumPy dataset:

```powershell
venv\Scripts\python.exe evaluate_model.py
```

The script prints accuracy, F1 score, confusion matrix, and a classification report.
