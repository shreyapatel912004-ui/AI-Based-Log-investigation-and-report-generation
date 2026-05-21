# AI-Based Log Investigation and Alert System

## 1. Project Overview

This project is an AI-based cyber forensics log investigation framework. It helps investigators upload system, server, firewall, endpoint, application, and security logs, then automatically parses them, stores them, analyzes them using AI-assisted detection, highlights suspicious events, and generates downloadable investigation reports.

The project is designed for the problem statement:

**Artificial Intelligence based Log Investigation Framework for Next-Generation Cyber Forensics**

The system reduces manual log investigation effort by providing:

- A web-based investigation dashboard
- Login/logout access for investigator users
- Log ingestion from pasted text or uploaded files
- Parsing of real-world style logs
- AI-assisted anomaly and attack detection
- Search and filtering tools
- SQLite-based evidence storage
- Chain-of-custody hash preservation
- Exportable reports in JSON, CSV, and PDF formats
- Explainable alert reasons for investigator understanding

## 2. Problem Statement Alignment

The original problem statement requires a framework that can ingest, parse, analyze, correlate, and report logs for cyber forensic investigation.

This project covers the major deliverables as follows:

| Requirement | Project Implementation |
| --- | --- |
| Web-Based Dashboard | Flask dashboard with upload, filters, charts, timeline, and exports |
| Secure User Access | Flask session login/logout with `admin1` and `manager1` demo users |
| Log Ingestion and Parsing | Textarea upload and file upload for `.log`, `.txt`, `.csv`, `.json`, `.jsonl`, `.xml`, `.out` |
| Database Storage Layer | SQLite database named `data/forensics.db` |
| AI Correlation and Inference Engine | LSTM model scoring plus rule-based forensic scoring |
| Filtering and Search Tools | Filter by verdict, severity, source IP, event type, and raw log search |
| Automated Reporting | Export as PDF, CSV, and JSON |
| Chain of Custody | SHA-256 hash chaining for stored logs |
| Explainable AI | Each event includes an explanation field |
| Graphical Representation | Dashboard metrics and Chart.js visualizations |

Optional/future items:

- LLM natural language query interface
- SIEM/SOAR integration
- Cloud deployment and distributed storage
- Advanced benchmark dashboard

## 3. Main Features

### 3.1 User Login

The dashboard is protected by a simple Flask session login system.

Demo users:

| Username | Password | Role |
| --- | --- | --- |
| `admin1` | `admin123` | Administrator |
| `manager1` | `manager123` | Investigation Manager |

After login, the dashboard displays the signed-in username and role in the header. The user can end the session using the `Logout` button.

### 3.2 Log Ingestion

The system accepts logs in two ways:

1. Paste logs directly into the dashboard textarea.
2. Upload a text-based log file.

Supported upload formats:

- `.log`
- `.txt`
- `.csv`
- `.json`
- `.jsonl`
- `.xml`
- `.out`

Important Windows note:

Raw Windows `.evtx` files are binary and cannot be parsed directly as text. Windows Event Viewer logs should first be exported as XML, CSV, or TXT, then uploaded into this system.

### 3.3 Log Parsing

The parser extracts key investigation fields:

- Line number
- Timestamp
- Source IP address
- Severity
- Event type
- Raw log text
- ML feature vector

The parser can recognize realistic log styles such as:

- Linux SSH authentication logs
- Firewall/UFW block logs
- Apache/Nginx-style access logs
- Windows Security Event export text
- Endpoint agent logs
- JSON security logs

### 3.4 AI-Assisted Risk Scoring

The project uses a hybrid scoring approach:

1. **LSTM Model Scoring**
   - Uses the existing `ml_model/attack_detection_model.h5`
   - Uses `ml_model/scaler.pkl`
   - Generates a model-based risk score

2. **Heuristic Forensic Scoring**
   - Detects known suspicious patterns
   - Handles obvious dangerous indicators
   - Works as fallback if the model cannot load

3. **Composite Scoring**
   - Combines AI score and rule-based score
   - Uses the higher risk signal
   - Prevents obvious threats from being under-scored
   - Performs batch inference for uploaded files, which is faster than scoring one log line at a time

### 3.5 Event Classification

Each log event is classified into one of three verdicts:

- `NORMAL`
- `SUSPICIOUS`
- `ATTACK`

Examples:

- Failed SSH login from unknown IP: `SUSPICIOUS`
- PowerShell encoded command: `ATTACK`
- Firewall block from hostile IP: `SUSPICIOUS` or `ATTACK`
- Critical deletion of log files: `ATTACK`

### 3.6 Explainable Alerting

Each event includes an explanation. This helps investigators understand why a log was flagged.

Example explanation:

```text
ATTACK: severity=WARNING, source_ip=45.83.12.9, event_type=authentication, authentication or access failure; risk=47.0%
```

This supports explainable AI expectations from the problem statement.

### 3.7 Evidence Storage

Logs are stored in SQLite inside:

```text
data/forensics.db
```

Each stored event contains:

- Case name
- Line number
- Ingestion time
- Event time
- Source IP
- Severity
- Event type
- Risk score
- Verdict
- Explanation
- Model source
- Raw log
- Previous hash
- Integrity hash

### 3.8 Chain of Custody

The project uses SHA-256 hash chaining to preserve evidence integrity.

Each log hash is calculated from:

```text
previous_hash + raw_log
```

This means if one stored log is modified, the hash chain will no longer match. This helps demonstrate tamper-awareness and chain-of-custody preservation.

### 3.9 Dashboard

The dashboard provides:

- Case name input
- File upload
- Direct log paste textarea
- Analyze button
- Clear stored logs button
- Search and investigation filters
- Summary metrics
- Verdict distribution chart
- Top source IP chart
- Investigation timeline table
- Export buttons

Summary metrics:

- Total logs
- Alerts
- Attacks
- Average risk

### 3.10 Filtering and Search

The investigator can filter by:

- Raw log text
- Verdict
- Severity
- Source IP
- Event type

This helps in finding specific incident patterns quickly.

### 3.11 Report Generation

Reports can be exported in:

- JSON
- CSV
- PDF

Reports contain investigation summary and event details.

## 4. System Architecture

The project follows a modular architecture based on SOLID principles.

```text
User Browser
    |
    v
Flask Web App (main.py)
    |
    v
Investigation Service
    |
    +--> Log Parser
    +--> AI and Heuristic Scoring
    +--> Event Classifier
    +--> SQLite Repository
    +--> Summary Builder
    +--> Report Exporter
```

## 5. Component Explanation

### 5.1 `main.py`

Purpose:

- Starts the Flask web application
- Defines API routes
- Connects services together

Main routes:

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Open dashboard |
| `/login` | GET/POST | User login |
| `/logout` | GET | User logout |
| `/upload_logs` | POST | Analyze pasted logs |
| `/upload_file` | POST | Analyze uploaded log file |
| `/get_results` | GET | Fetch filtered investigation results |
| `/export/<file_type>` | GET | Download JSON, CSV, or PDF report |
| `/clear_logs` | DELETE | Clear stored logs |

### 5.2 `domain.py`

Purpose:

- Defines shared data structures
- Keeps log/event data consistent across the project

Main classes:

- `ParsedLog`
- `ScoredEvent`

### 5.3 `log_parser.py`

Purpose:

- Converts raw logs into structured parsed events
- Extracts timestamps, IPs, severity, event type, and ML features

Main class:

- `LogParser`

Important methods:

- `parse`
- `extract_timestamp`
- `detect_severity`
- `detect_event_type`
- `build_features`

### 5.4 `scoring.py`

Purpose:

- Handles AI scoring, rule-based scoring, classification, and explanation

Main classes:

- `RiskScorer`
- `LstmRiskScorer`
- `HeuristicRiskScorer`
- `CompositeRiskScorer`
- `EventClassifier`
- `EventScoringService`

### 5.5 `repository.py`

Purpose:

- Handles database operations
- Stores investigation logs
- Applies chain-of-custody hashing

Main class:

- `LogRepository`

Main methods:

- `initialize`
- `save_events`
- `query_events`
- `clear`
- `chain_hash`

### 5.6 `investigation_service.py`

Purpose:

- Coordinates the complete investigation workflow

Main class:

- `InvestigationService`

Main methods:

- `ingest`
- `search`

Workflow:

1. Receive logs
2. Parse logs
3. Score each event
4. Store events
5. Build summary
6. Return results

### 5.7 `summary.py`

Purpose:

- Builds dashboard summary data

Main class:

- `InvestigationSummary`

Outputs:

- Total logs
- Alerts
- Attack count
- Suspicious count
- Normal count
- Verdict counts
- Severity counts
- Event type counts
- Top source IPs
- Average risk
- Highest risk

### 5.8 `reporting.py`

Purpose:

- Generates downloadable reports

Main class:

- `ReportExporter`

Report formats:

- JSON
- CSV
- PDF

### 5.9 `file_ingestion.py`

Purpose:

- Reads uploaded log files
- Validates supported extensions
- Handles text decoding
- Blocks unsupported binary `.evtx` files with a helpful message

Main class:

- `LogFileReader`

### 5.10 Frontend Files

#### `frontend/templates/index.html`

Defines the dashboard layout.

#### `frontend/static/script.js`

Handles:

- Log upload
- File upload
- Result fetching
- Chart rendering
- Export actions
- Table rendering

#### `frontend/static/style.css`

Defines dashboard styling and responsive layout.

## 6. Workflow

### 6.1 Pasted Log Workflow

```text
User pastes logs
    |
Clicks Analyze Logs
    |
Frontend sends logs to /upload_logs
    |
Flask sends logs to InvestigationService
    |
LogParser extracts fields
    |
ScoringService assigns risk and verdict
    |
Repository stores events with hashes
    |
Summary is generated
    |
Dashboard updates charts and table
```

### 6.0 Login Workflow

```text
User opens dashboard
    |
If not authenticated, user is redirected to /login
    |
User enters admin1/admin123 or manager1/manager123
    |
Flask stores username and role in session
    |
Dashboard and API routes become available
    |
User clicks Logout to clear session
```

### 6.2 File Upload Workflow

```text
User chooses log file
    |
Clicks Upload File
    |
Frontend sends file to /upload_file
    |
LogFileReader decodes file
    |
InvestigationService analyzes logs
    |
Repository stores evidence
    |
Dashboard displays results
```

### 6.3 Report Workflow

```text
User applies filters
    |
Clicks JSON / CSV / PDF
    |
Frontend calls /export/<file_type>
    |
Backend fetches filtered events
    |
ReportExporter generates report
    |
Browser downloads file
```

## 7. SOLID Principles Used

### 7.1 Single Responsibility Principle

Each module has one main responsibility:

- `log_parser.py` parses logs
- `scoring.py` scores and classifies events
- `repository.py` stores events
- `reporting.py` exports reports
- `main.py` handles web routes

### 7.2 Open/Closed Principle

The system is open for extension but closed for unnecessary modification.

Examples:

- A new ML model can be added by creating another `RiskScorer`
- A new export format can be added in `ReportExporter`
- New event types can be added in `log_parser.py`

### 7.3 Liskov Substitution Principle

Any class implementing `RiskScorer` can replace the existing scorer.

For example:

- `LstmRiskScorer`
- `HeuristicRiskScorer`
- Future `LLMRiskScorer`
- Future `SIEMRiskScorer`

### 7.4 Interface Segregation Principle

Classes expose only focused methods:

- Scorers expose `score`
- Repository exposes storage methods
- Report exporter exposes report methods

No class is forced to implement unrelated behavior.

### 7.5 Dependency Inversion Principle

`InvestigationService` depends on injected components:

- Parser
- Scoring service
- Repository
- Summary builder

This makes the workflow flexible and easier to test.

## 8. AI/ML Model Usage

The project uses existing model files:

```text
ml_model/attack_detection_model.h5
ml_model/scaler.pkl
```

The model receives an 11-feature vector:

1. Login attempts
2. Access hour
3. Session duration level
4. Numeric IP address
5. File access
6. File deletion
7. Network activity
8. Process activity
9. Suspicious command
10. Remote login
11. USB activity

The features are scaled using `ml_model/scaler.pkl`, reshaped for LSTM input, and passed into the Keras model.

The final score is combined with heuristic scoring so obvious forensic indicators are not missed.

### 8.1 Model Evaluation

The file `evaluate_model.py` benchmarks the saved ML model using:

```text
ml_model/X_lstm_final (1).npy
ml_model/y_labels_final (1).npy
```

It reports:

- Best threshold
- F1 score
- Accuracy
- Confusion matrix
- Classification report

Run it with:

```powershell
venv\Scripts\python.exe evaluate_model.py
```

### 8.2 Efficiency Improvement

The project keeps the original student-built ML model unchanged. Efficiency is improved in a simple way:

- The model is loaded once and reused.
- Uploaded log files are scored in batches instead of one line at a time.
- Simple forensic rules support the ML model for obvious suspicious patterns.

This keeps the approach understandable for a third-year student project while still making real log analysis faster and more reliable.

## 9. Example Realistic Logs

### Linux SSH Log

```text
May 19 10:13:01 ubuntu-server sshd[433]: Failed password for invalid user root from 45.83.12.9 port 39412 ssh2
```

### Firewall Log

```text
2026-05-19 10:13:08 firewall01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:1f:2a:3b SRC=45.83.12.9 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=39416 DPT=22
```

### Apache/Web Attack Log

```text
192.168.1.20 - - [19/May/2026:10:14:03 +0530] "GET /login.php?id=1' OR '1'='1 HTTP/1.1" 500 612 "-" "sqlmap/1.8"
```

### Windows Security Export Text

```text
2026-05-19 10:14:18 WinEventLog: Security: 4688: Microsoft-Windows-Security-Auditing: New Process Created: Account Name: guest Process Command Line: powershell.exe -EncodedCommand SQBFAFgA
```

### JSON Security Log

```json
{"timestamp":"2026-05-19T10:16:21+05:30","host":"web01","severity":"ERROR","event":"authentication_failure","src_ip":"45.83.12.9","user":"admin","message":"Multiple failed login attempts detected"}
```

## 10. How to Run

Open PowerShell:

```powershell
cd C:\Users\HP\Desktop\project
venv\Scripts\python.exe main.py
```

Open in browser:

```text
http://127.0.0.1:5000/
```

## 11. How to Use

### Option 1: Analyze Pasted Logs

1. Open the dashboard.
2. Paste logs into the textarea.
3. Enter a case name.
4. Click `Analyze Logs`.
5. Review metrics, charts, and investigation timeline.
6. Export report if needed.

### Option 2: Analyze Uploaded Logs

1. Open the dashboard.
2. Click `Choose File`.
3. Select a supported log file.
4. Click `Upload File`.
5. Review results.
6. Export PDF, CSV, or JSON.

### Option 3: Filter Investigation Results

Use filters for:

- Search text
- Verdict
- Severity
- Source IP
- Event type

Then export the filtered results.

## 12. Database Schema

Table name:

```text
logs
```

Columns:

| Column | Purpose |
| --- | --- |
| `id` | Unique event ID |
| `case_name` | Investigation/case name |
| `line_no` | Original line number from upload |
| `ingested_at` | Time log entered the system |
| `event_time` | Timestamp extracted from log |
| `source_ip` | Extracted source IP |
| `severity` | Detected severity |
| `event_type` | Detected event category |
| `risk_score` | Risk percentage |
| `verdict` | NORMAL/SUSPICIOUS/ATTACK |
| `explanation` | Reason for verdict |
| `model_source` | LSTM or heuristic |
| `raw_log` | Original log line |
| `previous_hash` | Previous event hash |
| `integrity_hash` | Current event SHA-256 hash |

## 13. Security and Forensic Considerations

### Data Privacy

The project runs locally by default. Uploaded logs are stored in local SQLite storage.

### Access Control

The dashboard and investigation API routes require login. This is a project-level demonstration of access control using Flask sessions and two demo users.

### Tamper Awareness

Hash chaining helps detect modification of stored logs.

### Explainability

Every alert includes reasons such as:

- Severity level
- Source IP
- Event type
- Failed authentication
- Suspicious command
- Web attack signature
- Destructive file activity

### Evidence Preservation

The raw log line is preserved exactly in the database.

## 14. Limitations

Current limitations:

- Raw `.evtx` files must be exported first as XML, CSV, or TXT.
- LLM natural language querying is not yet implemented.
- SIEM/SOAR integration is not yet implemented.
- The PDF report is simple and text-based.
- The ML model quality depends on the dataset used to train the existing `.h5` model.
- Large enterprise-scale log volumes may require PostgreSQL, Elasticsearch, or cloud storage instead of SQLite.

## 15. Future Enhancements

Recommended future improvements:

- Add LLM query box for natural language investigation
- Add  role-based access
- Add hash-chain verification endpoint
- Add advanced PDF report formatting
- Add timeline visualizations
- Add MITRE ATT&CK mapping
- Add SIEM export connectors
- Add cloud deployment support
- Add benchmarking dashboard
- Add support for direct `.evtx` parsing using a specialized library

## 16. Conclusion

This project implements a practical AI-based log investigation and alert system for cyber forensics. It allows investigators to ingest real logs, parse important fields, detect suspicious activity, preserve logs with integrity hashes, search and filter evidence, view graphical summaries, and export investigation reports.

The system is modular, follows SOLID principles, and can be extended with more parsers, AI models, report types, and enterprise integrations.
