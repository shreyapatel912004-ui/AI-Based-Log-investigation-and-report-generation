# AI-Based Log Investigation and Alert System

This project is a cyber-forensics dashboard for ingesting logs, parsing events, detecting suspicious activity with an AI model, correlating forensic evidence into incident timelines, preserving evidence with hash chaining, filtering investigations, asking natural-language case questions, and exporting reports.

For full project explanation, architecture, workflow, SOLID design, database schema, and usage guide, read:

```text
docs/PROJECT_DOCUMENTATION.md
```

## Features

- Web dashboard for log investigation
- Strong login/logout flow backed by SQLite users and hashed passwords
- Single-analyst case creation and case-based log segregation
- Manual log type selection for generic, firewall, authentication, endpoint, and Windows exported event logs
- Multi-line log ingestion
- File upload for text-based real logs: `.log`, `.txt`, `.csv`, `.json`, `.jsonl`, `.xml`, `.out`
- Structured parsing for IP address, timestamp, severity, and event type
- Forensic entity extraction for users, hosts, files, processes, emails, domains, apps, IPs, and transfer channels
- AI-assisted attack scoring using the existing LSTM model and scaler
- Heuristic fallback scoring if the model cannot load
- Scenario-aware correlation for cross-device file transfer and ransomware timelines
- Interactive incident timeline with phase labels, extracted evidence, confidence, and risk
- Lightweight natural-language case query endpoint for questions about file transfer, ransomware, suspicious IPs, and attacks
- Explainable alert reasons for investigator review
- SQLite storage in `data/forensics.db`
- SHA-256 chain-of-custody hash for every stored log
- Search and filters by verdict, severity, source IP, event type, and raw text
- Charts for verdict distribution and top source IPs
- Export reports as JSON, CSV, and PDF
- Enterprise/SIEM exports for Elasticsearch/OpenSearch Bulk NDJSON, Splunk HEC, CEF, LEEF, and normalized NDJSON
- Optional push connectors for configured Splunk HEC and Elasticsearch/OpenSearch endpoints
- Built-in hackathon demo datasets for Scenario 1 and Scenario 2

## Authentication

User accounts are stored in SQLite inside `data/forensics.db`. Passwords are stored as Werkzeug password hashes, not plain text. On startup, the app creates default demo users if they do not already exist:

| Username | Password | Role |
| --- | --- | --- |
| `admin1` | `admin123` | Administrator |
| `manager1` | `manager123` | Investigation Manager |
| `analyst1` | `analyst123` | Analyst |

The login flow keeps `session["username"]` and `session["role"]` available for protected routes and case-scoped actions. Basic failed-login protection blocks authentication after repeated failed attempts.

## Case Segregation

The dashboard supports a simple single-analyst case workflow. An analyst creates or selects a case before uploading, pasting, searching, exporting, or clearing logs.

All investigation log operations are scoped by `case_id`:

- Pasted logs use `POST /cases/<case_id>/upload_logs`
- File uploads use `POST /cases/<case_id>/upload_file`
- Results use `GET /cases/<case_id>/results`
- Timeline reconstruction uses `GET /cases/<case_id>/timeline`
- Natural-language case questions use `POST /cases/<case_id>/ask`
- SIEM/storage export uses `GET /cases/<case_id>/integrations/export/<target>`
- Optional connector push uses `POST /cases/<case_id>/integrations/push/<target>`
- Exports use `GET /cases/<case_id>/export/<file_type>`
- Clear logs uses `DELETE /cases/<case_id>/logs`

There is no multi-user case assignment or role-based case permission logic in the current version. Authentication protects access to the app, while case segregation ensures Case A logs, summaries, exports, and clear actions do not affect Case B.

## Run

```powershell
cd "D:\log project\AI-Based-Log-investigation-and-report-generation"
.\venv\Scripts\python.exe main.py
```

Open:

```text
http://127.0.0.1:5000/
```


## Real System Logs

You can upload downloaded logs if they are text-based. Before analyzing, choose the closest log type in the dashboard:

| Log type option | Use for |
| --- | --- |
| `Generic / current mixed logs` | Existing mixed log analysis, web logs, syslog-style text, CSV/JSON/XML text exports |
| `Firewall logs` | UFW/firewall/router/proxy traffic logs with block, allow, source IP, protocol, and port fields |
| `Authentication logs` | SSH, Linux auth, login/logout, failed password, invalid user, and privilege activity logs |
| `Endpoint logs` | Process activity, PowerShell/cmd execution, USB, file activity, malware, and endpoint-agent logs |
| `Windows exported event logs` | Windows Event Viewer data exported as TXT, CSV, XML, or JSON-style text |

Windows `.evtx` files are binary. Export them from Windows Event Viewer as XML, CSV, or TXT first, then upload the exported file.

## Scenario Timeline and Query Features

The dashboard includes a forensic reconstruction layer designed for the two hackathon testing scenarios.

| Scenario | Current support |
| --- | --- |
| Scenario 1: Windows computer to Android mobile file transfer | Extracts file names, users, hosts, USB/MTP activity, Bluetooth transfer, email attachment evidence, source IPs, and builds a cross-device file-transfer timeline |
| Scenario 2: Ransomware infection | Extracts downloaded payloads, suspicious process execution, PowerShell activity, ransomware indicators, encrypted files, ransom-note creation, and command-and-control IP evidence |

The dashboard has quick-load buttons:

- `Scenario 1` loads `data/scenario_1_data_transfer_logs.log`
- `Scenario 2` loads `data/scenario_2_ransomware_logs.log`

After analyzing a scenario, the `Incident timeline` panel shows chronological phases such as `File Access`, `Device Transfer`, `Outbound Transfer`, `Initial Download`, `Suspicious Execution`, and `Encryption Activity`.

The `Ask this case` panel supports questions such as:

- `How did the file leave the system?`
- `When did ransomware start?`
- `Show suspicious IPs`
- `Show attack events`

## Enterprise and SIEM Integration

SQLite remains the default local evidence store for the PoC. For future enterprise deployment, the project now includes SIEM-ready export and push adapters.

Supported export targets:

| Target | Purpose |
| --- | --- |
| `elastic` | Elasticsearch/OpenSearch Bulk NDJSON |
| `splunk` | Splunk HTTP Event Collector JSON events |
| `cef` | Common Event Format for ArcSight/SIEM forwarding |
| `leef` | IBM QRadar LEEF format |
| `ndjson` | Generic normalized event stream |

Optional push connectors are enabled through environment variables:

| Connector | Required environment variables |
| --- | --- |
| Splunk HEC | `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` |
| Elasticsearch/OpenSearch | `ELASTIC_BULK_URL` |

Optional variables:

- `SPLUNK_INDEX`
- `ELASTIC_API_KEY`
- `ELASTIC_BASIC_AUTH`
- `SIEM_PUSH_TIMEOUT_SECONDS`

The dashboard `Integrations` section can download payloads even when no enterprise endpoint is configured. Push buttons return a clear configuration error until the required environment variables are set.

## Main Files

- `main.py` - Flask routes and dependency wiring
- `app.py` - alternate Flask launcher that imports `main.py`
- `backend/` - authentication, parsing, scoring, storage, report generation, and investigation services
- `backend/auth_service.py` - authentication checks, session creation, and logout handling
- `backend/user_repository.py` - SQLite user storage, password hashing, and default user seeding
- `backend/repository.py` - case storage, case-scoped log queries, and chain-of-custody hashes
- `backend/forensic_correlation.py` - forensic entity extraction, timeline reconstruction, scenario inference, and natural-language case query handling
- `backend/enterprise_integrations.py` - SIEM/export adapters for Elastic/OpenSearch, Splunk HEC, CEF, LEEF, and NDJSON
- `frontend/templates/` - dashboard and login HTML templates
- `frontend/static/` - dashboard JavaScript and CSS
- `ml_model/` - saved AI model, scaler, and NumPy evaluation assets
- `data/` - SQLite database, audit log, sample logs, and scenario demo datasets
- `scripts/` - model evaluation, inference, and sample-log generation helpers
- `docs/PROJECT_DOCUMENTATION.md` - full project documentation

## SOLID Design

- Single Responsibility: parsing, scoring, storage, reporting, and web routing are separate modules.
- Open/Closed: new parsers, scorers, or exporters can be added without rewriting Flask routes.
- Liskov Substitution: any class implementing `RiskScorer` can replace the current LSTM or heuristic scorer.
- Interface Segregation: the scoring interface only exposes `score`, while storage and reporting have their own focused APIs.
- Dependency Inversion: `InvestigationService` depends on injected parser, scorer, repository, and summary components instead of constructing everything internally.

## Suggested Demo Flow

1. Login with an existing demo user.
2. Create `Case A`.
3. Click `Scenario 1`, then click `Analyze Logs`.
4. Review the cross-device file-transfer timeline and ask `How did the file leave the system?`.
5. Create `Case B`.
6. Click `Scenario 2`, then click `Analyze Logs`.
7. Review the ransomware infection timeline and ask `When did ransomware start?`.
8. Confirm each case keeps separate logs, timelines, summaries, and exports.
9. Export each case separately as PDF, CSV, or JSON.

## Model Evaluation

To benchmark the saved ML model against the included NumPy dataset:

```powershell
.\venv\Scripts\python.exe scripts\evaluate_model.py
```

The script prints accuracy, F1 score, confusion matrix, and a classification report.
