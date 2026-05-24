# AI-Based Log Investigation and Alert System

## 1. Project Overview

This project is an AI-based cyber forensics log investigation framework. It helps investigators upload system, server, firewall, endpoint, application, and security logs, then automatically parses them, stores them, analyzes them using AI-assisted detection, correlates related evidence into incident timelines, highlights suspicious events, answers case questions, and generates downloadable investigation reports.

The project is designed for the problem statement:

**Artificial Intelligence based Log Investigation Framework for Next-Generation Cyber Forensics**

The system reduces manual log investigation effort by providing:

- A web-based investigation dashboard
- Strong login/logout access for investigator users
- Single-analyst case creation and case-based evidence segregation
- Manual log type selection for generic, firewall, authentication, endpoint, and Windows exported event logs
- Log ingestion from pasted text or uploaded files
- Parsing of real-world style logs
- AI-assisted anomaly and attack detection
- Forensic entity extraction for users, hosts, files, processes, emails, domains, apps, IPs, and transfer channels
- Scenario-aware event correlation for file-transfer and ransomware investigations
- Chronological incident timeline reconstruction
- Search and filtering tools
- Lightweight natural-language case questions
- Enterprise/SIEM export adapters for Splunk HEC, Elasticsearch/OpenSearch, CEF, LEEF, and NDJSON
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
| Secure User Access | SQLite-backed users, hashed passwords, Flask sessions, and failed-login tracking |
| Case-Based Investigation Separation | Single analyst can create/select cases; logs, searches, summaries, exports, and clear actions are scoped by `case_id` |
| Log Ingestion and Parsing | Manual log type selection plus textarea/file upload for `.log`, `.txt`, `.csv`, `.json`, `.jsonl`, `.xml`, `.out` |
| Database Storage Layer | SQLite database named `data/forensics.db` |
| AI Correlation and Inference Engine | LSTM model scoring, rule-based forensic scoring, entity extraction, and scenario-aware correlation |
| Filtering and Search Tools | Filter by verdict, severity, source IP, event type, and raw log search |
| Automated Reporting | Export as PDF, CSV, and JSON |
| SIEM/SOAR Readiness | Exports SIEM-ready payloads and can push to configured Splunk HEC or Elasticsearch/OpenSearch endpoints |
| Chain of Custody | SHA-256 hash chaining for stored logs |
| Explainable AI | Each event includes an explanation field |
| Graphical Representation | Dashboard metrics, Chart.js visualizations, and incident timeline reconstruction |
| Optional LLM Prompt Integration | Lightweight natural-language query panel for case questions; can be upgraded to an external LLM later |

Optional/future items:

- External LLM/RAG integration for deeper natural-language investigation
- Full bidirectional SIEM/SOAR playbook automation
- Cloud deployment and distributed storage
- Advanced benchmark dashboard

## 3. Main Features

### 3.1 Strong Authentication

The dashboard is protected by a Flask session login system backed by SQLite user records. User passwords are stored as Werkzeug password hashes instead of plain text.

Default demo users are created automatically when the database is initialized:

| Username | Password | Role |
| --- | --- | --- |
| `admin1` | `admin123` | Administrator |
| `manager1` | `manager123` | Investigation Manager |
| `analyst1` | `analyst123` | Analyst |

After login, the app stores the authenticated identity in:

```python
session["username"]
session["role"]
```

These session values protect the dashboard, API routes, and case-scoped actions. The authentication layer also tracks failed login attempts and blocks authentication after repeated failures.

Relevant files:

- `backend/user_repository.py` stores users, password hashes, roles, failed attempts, and login timestamps.
- `backend/auth_service.py` validates credentials and manages session creation/logout.
- `main.py` wires authentication into the Flask routes.

### 3.2 Log Ingestion

The system accepts logs in two ways:

1. Paste logs directly into the dashboard textarea.
2. Upload a text-based log file.

Before analysis, the user selects the log type manually so the backend uses the matching parser instead of guessing.

Supported parser options:

| Log type option | Use for |
| --- | --- |
| `Generic / current mixed logs` | Existing mixed log analysis, web logs, syslog-style text, CSV/JSON/XML text exports |
| `Firewall logs` | UFW/firewall/router/proxy traffic logs with block, allow, source IP, protocol, and port fields |
| `Authentication logs` | SSH, Linux auth, login/logout, failed password, invalid user, and privilege activity logs |
| `Endpoint logs` | Process activity, PowerShell/cmd execution, USB, file activity, malware, and endpoint-agent logs |
| `Windows exported event logs` | Windows Event Viewer data exported as TXT, CSV, XML, or JSON-style text |

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

### 3.3 Case Segregation

The current application uses a simple single-analyst case model. An authenticated analyst creates or selects a case before starting analysis.

Minimum case fields:

- `id`
- `title`
- `description`
- `status`
- `created_at`

Every stored log event belongs to one selected `case_id`. The backend requires the selected case for pasted log analysis, file upload analysis, result fetching, filters, JSON/CSV/PDF export, and clearing stored logs.

Important rule:

```text
Every log query includes case_id.
```

This prevents global dashboard, result, and export queries. Clearing logs deletes only the selected case logs.

The system intentionally does not implement assigned analysts, case owners, role-based case access, or multi-user case permissions in the current version.

### 3.4 Log Parsing

The parser extracts key investigation fields:

- Line number
- Timestamp
- Source IP address
- Severity
- Event type
- Raw log text
- ML feature vector

The selected log type controls which parser is used:

- `GenericLogParser`
- `FirewallLogParser`
- `AuthLogParser`
- `EndpointLogParser`
- `WindowsEventLogParser`

All parser outputs are normalized into the same `ParsedLog` structure so the existing scoring, summary, storage, filtering, and export logic can continue to work.

The parser can recognize realistic log styles such as:

- Linux SSH authentication logs
- Firewall/UFW block logs
- Apache/Nginx-style access logs
- Windows Security Event export text
- Endpoint agent logs
- JSON security logs

### 3.5 AI-Assisted Risk Scoring

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

### 3.6 Event Classification

Each log event is classified into one of three verdicts:

- `NORMAL`
- `SUSPICIOUS`
- `ATTACK`

Examples:

- Failed SSH login from unknown IP: `SUSPICIOUS`
- PowerShell encoded command: `ATTACK`
- Firewall block from hostile IP: `SUSPICIOUS` or `ATTACK`
- Critical deletion of log files: `ATTACK`

### 3.7 Explainable Alerting

Each event includes an explanation. This helps investigators understand why a log was flagged.

Example explanation:

```text
ATTACK: severity=WARNING, source_ip=45.83.12.9, event_type=authentication, authentication or access failure; risk=47.0%
```

This supports explainable AI expectations from the problem statement.

### 3.8 Forensic Entity Extraction

After parsed events are scored and stored, the correlation layer extracts additional forensic evidence from each raw log line.

Extracted entities include:

- Users and account names
- Hostnames and device names
- File paths and document names
- Process and application names
- Email addresses
- Domains and URLs
- Source IPs
- USB, Bluetooth, email, network, and Android transfer channels

This is implemented in:

```text
backend/forensic_correlation.py
```

The entity extractor helps convert raw log text into investigator-friendly evidence. For example, a single event may reveal that user `rahul` copied `client_list_copy.xlsx` to Android device `ANDROID-73K9` through USB/MTP.

### 3.9 Scenario-Aware Correlation and Timeline Reconstruction

The project now includes a forensic correlation engine that builds a chronological incident timeline from all stored events in a selected case.

The engine infers one of these investigation views:

- `Cross-Device File Transfer Timeline`
- `Ransomware Infection Timeline`
- `General Forensic Timeline`

Timeline events are assigned phase labels such as:

- `Access Event`
- `File Access`
- `Device Transfer`
- `Outbound Transfer`
- `Initial Download`
- `Suspicious Execution`
- `Encryption Activity`
- `Persistence or Impact`
- `Attack Indicator`
- `Suspicious Indicator`

Each timeline item includes:

- Event time
- Source IP
- Verdict
- Risk score
- Confidence score
- Phase label
- Extracted users, hosts, files, processes, apps, emails, and channels
- Original raw log evidence

The selected case timeline is available through:

```text
GET /cases/<case_id>/timeline
```

### 3.10 Natural-Language Case Queries

The dashboard includes a lightweight natural-language investigation panel named `Ask this case`.

The current implementation is local and rule-guided. It does not require an external LLM API, but it provides the same investigator-facing workflow expected from optional prompt integration.

Supported question types include:

- File movement and exfiltration questions
- Ransomware infection and encryption questions
- Suspicious IP/source-address questions
- Attack and alert questions

Example questions:

```text
How did the file leave the system?
When did ransomware start?
Show suspicious IPs
Show attack events
```

The backend endpoint is:

```text
POST /cases/<case_id>/ask
```

### 3.11 Evidence Storage

Logs are stored in SQLite inside:

```text
data/forensics.db
```

Each stored event contains:

- Case ID
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

### 3.12 Chain of Custody

The project uses SHA-256 hash chaining to preserve evidence integrity.

Each log hash is calculated from:

```text
previous_hash + raw_log
```

This means if one stored log is modified, the hash chain will no longer match. This helps demonstrate tamper-awareness and chain-of-custody preservation.

The selected case can be verified through:

```text
GET /cases/<case_id>/verify_chain
```

The dashboard also includes a `Verify Chain` button. Verification checks the selected case only and reports whether the stored hash chain is valid.

### 3.13 Dashboard

The dashboard provides:

- Case dropdown
- New case name input
- Create case button
- Selected case label
- Log type dropdown
- File upload
- Direct log paste textarea
- Analyze button
- Clear stored logs button
- Verify Chain button
- Search and investigation filters
- Summary metrics
- Verdict distribution chart
- Top source IP chart
- Scenario 1 and Scenario 2 quick-load buttons
- Incident timeline panel
- Extracted entity strip
- Natural-language case question panel
- Investigation timeline table
- Export buttons

Summary metrics:

- Total logs
- Alerts
- Attacks
- Average risk

### 3.14 Filtering and Search

The investigator can filter by:

- Raw log text
- Verdict
- Severity
- Source IP
- Event type

This helps in finding specific incident patterns quickly.

### 3.15 Scenario Datasets

The project includes two synthetic hackathon-ready datasets under the `data` directory.

| Dataset | Purpose |
| --- | --- |
| `data/scenario_1_data_transfer_logs.log` | Reconstructs confidential file transfer from a Windows organization computer to an Android phone through USB/MTP, followed by Bluetooth and email exfiltration evidence |
| `data/scenario_2_ransomware_logs.log` | Reconstructs ransomware infection from payload download to execution, PowerShell activity, shadow-copy deletion, file encryption, ransom-note creation, and command-and-control traffic |

These datasets can be loaded directly from the dashboard using the `Scenario 1` and `Scenario 2` buttons.

### 3.16 Report Generation

Reports can be exported in:

- JSON
- CSV
- PDF

Reports contain investigation summary and event details.

### 3.17 Enterprise Storage and SIEM Integration

The project keeps SQLite as the default local evidence store for hackathon/demo usage. This avoids requiring a running enterprise stack on every machine while still preserving evidence, cases, reports, and chain-of-custody hashes.

For future enterprise deployment, the project now includes an integration adapter layer:

```text
backend/enterprise_integrations.py
```

Supported export targets:

| Target | Output |
| --- | --- |
| `elastic` | Elasticsearch/OpenSearch Bulk NDJSON |
| `splunk` | Splunk HTTP Event Collector JSON events |
| `cef` | Common Event Format text lines |
| `leef` | IBM QRadar LEEF text lines |
| `ndjson` | Generic normalized event stream |

Export endpoint:

```text
GET /cases/<case_id>/integrations/export/<target>
```

Connector status endpoint:

```text
GET /cases/<case_id>/integrations
```

Optional push endpoints:

```text
POST /cases/<case_id>/integrations/push/splunk
POST /cases/<case_id>/integrations/push/elastic
```

Push connectors are disabled until environment variables are configured.

| Connector | Required environment variables | Optional environment variables |
| --- | --- | --- |
| Splunk HEC | `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` | `SPLUNK_INDEX`, `SIEM_PUSH_TIMEOUT_SECONDS` |
| Elasticsearch/OpenSearch | `ELASTIC_BULK_URL` | `ELASTIC_API_KEY`, `ELASTIC_BASIC_AUTH`, `SIEM_PUSH_TIMEOUT_SECONDS` |

This design gives the project a credible enterprise path:

- Keep local SQLite for tamper-aware PoC storage.
- Export normalized forensic events to SIEM tools.
- Push directly to Splunk or Elasticsearch/OpenSearch when endpoints are available.
- Preserve chain-of-custody hashes in exported records.
- Avoid hard dependency on paid or cloud infrastructure during demonstration.

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
    +--> Forensic Correlation Engine
    +--> Report Exporter
    +--> Enterprise Integration Exporter
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
| `/cases` | GET | List available investigation cases |
| `/cases` | POST | Create a new investigation case |
| `/cases/<case_id>/upload_logs` | POST | Analyze pasted logs for a selected case |
| `/cases/<case_id>/upload_file` | POST | Analyze uploaded log file for a selected case |
| `/cases/<case_id>/results` | GET | Fetch filtered investigation results for a selected case |
| `/cases/<case_id>/timeline` | GET | Build a scenario-aware forensic timeline for a selected case |
| `/cases/<case_id>/ask` | POST | Answer a natural-language investigation question for a selected case |
| `/cases/<case_id>/export/<file_type>` | GET | Download JSON, CSV, or PDF report for a selected case |
| `/cases/<case_id>/integrations` | GET | Show SIEM connector status and supported export formats |
| `/cases/<case_id>/integrations/export/<target>` | GET | Download SIEM-ready payloads for Elastic, Splunk, CEF, LEEF, or NDJSON |
| `/cases/<case_id>/integrations/push/<target>` | POST | Push selected case events to configured Splunk or Elasticsearch/OpenSearch endpoint |
| `/cases/<case_id>/verify_chain` | GET | Verify selected case chain-of-custody hashes |
| `/cases/<case_id>/logs` | DELETE | Clear logs for a selected case |

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

Main classes:

- `LogParser`
- `GenericLogParser`
- `FirewallLogParser`
- `AuthLogParser`
- `EndpointLogParser`
- `WindowsEventLogParser`

Important methods:

- `parse`
- `extract_timestamp`
- `detect_severity`
- `detect_event_type`
- `build_features`

`LogParser` acts as a registry/dispatcher. It receives the selected log type from the route and delegates parsing to the matching typed parser.

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
- Stores investigation cases and case-scoped logs
- Applies chain-of-custody hashing

Main class:

- `LogRepository`

Main methods:

- `initialize`
- `create_case`
- `list_cases`
- `get_case`
- `case_exists`
- `save_events`
- `query_events`
- `clear_case_logs`
- `chain_hash`

All log storage and retrieval methods are scoped through `case_id`.

### 5.6 `investigation_service.py`

Purpose:

- Coordinates the complete investigation workflow

Main class:

- `InvestigationService`

Main methods:

- `ingest`
- `search`

Workflow:

1. Receive logs and selected `case_id`
2. Parse logs
3. Score each event
4. Store events under the selected case
5. Build summary from selected case events
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

### 5.8 `forensic_correlation.py`

Purpose:

- Extracts higher-level forensic entities from stored logs
- Correlates related events across files, IPs, users, hosts, apps, and transfer channels
- Infers whether the case resembles a file-transfer investigation, ransomware investigation, or general timeline
- Produces the dashboard incident timeline
- Answers lightweight natural-language case questions

Main classes:

- `ForensicEntityExtractor`
- `ForensicCorrelationEngine`

Important methods:

- `extract`
- `build_timeline`
- `answer_query`

The correlation engine is intentionally separate from parsing and scoring. This keeps low-level event detection independent from higher-level forensic reconstruction.

### 5.9 `reporting.py`

Purpose:

- Generates downloadable reports

Main class:

- `ReportExporter`

Report formats:

- JSON
- CSV
- PDF

### 5.10 `enterprise_integrations.py`

Purpose:

- Maps stored forensic events into normalized enterprise event records
- Generates SIEM-ready export formats
- Pushes events to configured enterprise endpoints
- Keeps integration logic separate from the core investigation pipeline

Main classes:

- `EnterpriseEventMapper`
- `EnterpriseExporter`
- `EnterprisePushClient`

Supported formats:

- Elasticsearch/OpenSearch Bulk NDJSON
- Splunk HEC JSON events
- CEF
- LEEF
- Generic NDJSON

### 5.11 `file_ingestion.py`

Purpose:

- Reads uploaded log files
- Validates supported extensions
- Handles text decoding
- Blocks unsupported binary `.evtx` files with a helpful message

Main class:

- `LogFileReader`

### 5.12 Frontend Files

#### `frontend/templates/index.html`

Defines the dashboard layout.

#### `frontend/static/script.js`

Handles:

- Case loading and selection
- Case creation
- Log upload
- File upload
- Result fetching
- Scenario demo loading
- Timeline fetching and rendering
- Natural-language case query rendering
- SIEM/export button handling
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
Selects or creates a case
    |
Selects log type
    |
Clicks Analyze Logs
    |
Frontend sends logs to /cases/<case_id>/upload_logs
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
User enters a seeded database user such as admin1/admin123
    |
AuthService verifies the password hash through UserRepository
    |
Failed attempts are reset on success or incremented on failure
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
Selects or creates a case
    |
Selects log type
    |
Clicks Upload File
    |
Frontend sends file to /cases/<case_id>/upload_file
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
Frontend calls /cases/<case_id>/export/<file_type>
    |
Backend fetches filtered events for the selected case
    |
ReportExporter generates report
    |
Browser downloads file
```

### 6.4 Timeline Reconstruction Workflow

```text
User analyzes logs inside a selected case
    |
Stored events are fetched for the selected case
    |
ForensicCorrelationEngine extracts entities from raw logs
    |
Related files, users, IPs, hosts, apps, and channels are grouped
    |
The case is classified as file-transfer, ransomware, or general timeline
    |
Events are sorted chronologically and assigned forensic phase labels
    |
Dashboard displays the incident timeline and entity summary
```

### 6.5 Natural-Language Query Workflow

```text
User asks a question in the Ask this case panel
    |
Frontend sends POST /cases/<case_id>/ask
    |
Backend rebuilds the selected case timeline
    |
Question keywords select file-transfer, ransomware, IP, or attack evidence
    |
Dashboard displays a short answer and matching timeline events
```

### 6.6 Enterprise Export Workflow

```text
User selects a case
    |
User clicks an integration export button
    |
Backend fetches filtered case events
    |
EnterpriseExporter maps events into a normalized schema
    |
Payload is generated as Elastic Bulk, Splunk HEC, CEF, LEEF, or NDJSON
    |
Browser downloads the SIEM-ready payload
```

### 6.7 Optional SIEM Push Workflow

```text
Administrator sets SIEM environment variables
    |
User selects a case
    |
User clicks Push Splunk or Push Elastic
    |
Backend generates the matching enterprise payload
    |
EnterprisePushClient sends the payload to the configured endpoint
    |
Audit log records success or failure metadata
```

### 6.8 Hackathon Scenario Workflows

Scenario 1 demonstrates transfer of confidential files from a Windows computer to an Android mobile phone.

```text
Windows login
    |
Confidential file opened and copied
    |
Android phone connected through USB/MTP
    |
File copied to Android storage
    |
File opened on Android
    |
Bluetooth transfer recorded
    |
Email with attachment sent externally
    |
Firewall records outbound SMTP traffic and IP evidence
```

Scenario 2 demonstrates ransomware infection and encryption.

```text
Payload downloaded
    |
Suspicious process executed
    |
PowerShell encoded command launched
    |
Malware/ransomware alert generated
    |
Shadow copies deleted
    |
Files encrypted with locked extension
    |
Ransom note created
    |
Outbound command-and-control traffic blocked
```

## 7. SOLID Principles Used

### 7.1 Single Responsibility Principle

Each module has one main responsibility:

- `log_parser.py` parses logs
- `scoring.py` scores and classifies events
- `repository.py` stores cases and case-scoped events
- `user_repository.py` stores user accounts and authentication metadata
- `auth_service.py` validates credentials and manages sessions
- `forensic_correlation.py` extracts entities and reconstructs timelines
- `reporting.py` exports reports
- `enterprise_integrations.py` maps and exports events to SIEM formats
- `main.py` handles web routes

### 7.2 Open/Closed Principle

The system is open for extension but closed for unnecessary modification.

Examples:

- A new ML model can be added by creating another `RiskScorer`
- A new export format can be added in `ReportExporter`
- New event types can be added in `log_parser.py`
- New scenario-specific correlation rules can be added in `ForensicCorrelationEngine`
- New SIEM connectors can be added through `EnterpriseExporter` or `EnterprisePushClient`

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

The file `scripts/evaluate_model.py` benchmarks the saved ML model using:

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
.\venv\Scripts\python.exe scripts\evaluate_model.py
```

### 8.2 Efficiency Improvement

The project keeps the original student-built ML model unchanged. Efficiency is improved in a simple way:

- The model is loaded once and reused.
- Uploaded log files are scored in batches instead of one line at a time.
- Simple forensic rules support the ML model for obvious suspicious patterns.

This keeps the approach understandable for a third-year student project while still making real log analysis faster and more reliable.

### 8.3 Correlation and Inference Layer

The AI/ML scoring layer determines whether individual events are normal, suspicious, or attack-like. The forensic correlation layer then performs case-level inference.

Current inference capabilities:

- Detects likely file-transfer/exfiltration cases when logs contain file access, USB/MTP, Bluetooth, email, attachment, or outbound network evidence.
- Detects likely ransomware cases when logs contain payload download, suspicious execution, PowerShell, malware/ransomware indicators, shadow-copy deletion, encrypted files, or ransom-note evidence.
- Links events that share files, IPs, and users.
- Produces confidence values based on risk score, verdict, and extracted evidence richness.

This gives investigators both low-level event scoring and high-level incident reconstruction.

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

### Scenario 1 File Transfer Log

```text
2026-05-18 09:12:27 WIN-ORG-07 MTPTransfer user=rahul copied C:\Users\rahul\Desktop\client_list_copy.xlsx to Android device serial=ANDROID-73K9 path=/sdcard/Download/client_list_copy.xlsx channel=USB
```

### Scenario 2 Ransomware Log

```text
2026-05-19 14:06:21 WIN-FIN-12 FileAudit ransomware encrypted C:\Finance\payroll.xlsx to C:\Finance\payroll.xlsx.locked
```

## 10. How to Run

Open PowerShell:

```powershell
cd "D:\log project\AI-Based-Log-investigation-and-report-generation"
.\venv\Scripts\python.exe main.py
```

Open in browser:

```text
http://127.0.0.1:5000/
```

Default login options:

| Username | Password | Role |
| --- | --- | --- |
| `admin1` | `admin123` | Administrator |
| `manager1` | `manager123` | Investigation Manager |
| `analyst1` | `analyst123` | Analyst |

## 11. How to Use

### Option 1: Analyze Pasted Logs

1. Open the dashboard.
2. Create or select a case.
3. Select the log type.
4. Paste logs into the textarea.
5. Click `Analyze Logs`.
6. Review case-specific metrics, charts, and investigation timeline.
7. Export the selected case report if needed.

### Option 2: Analyze Uploaded Logs

1. Open the dashboard.
2. Create or select a case.
3. Select the log type.
4. Click `Choose File`.
5. Select a supported log file.
6. Review case-specific results.
7. Export PDF, CSV, or JSON for the selected case.

### Option 3: Filter Investigation Results

Use filters for:

- Search text
- Verdict
- Severity
- Source IP
- Event type

Then export the filtered results.

### Option 4: Run Scenario 1 File-Transfer Demo

1. Open the dashboard.
2. Create a case such as `Scenario 1 - File Transfer`.
3. Click `Scenario 1`.
4. Click `Analyze Logs`.
5. Review the incident timeline.
6. Ask `How did the file leave the system?`
7. Export the report if needed.

### Option 5: Run Scenario 2 Ransomware Demo

1. Open the dashboard.
2. Create a case such as `Scenario 2 - Ransomware`.
3. Click `Scenario 2`.
4. Click `Analyze Logs`.
5. Review the infection timeline.
6. Ask `When did ransomware start?`
7. Export the report if needed.

## 12. Database Schema

Table name:

```text
users
```

Columns:

| Column | Purpose |
| --- | --- |
| `id` | Unique user ID |
| `username` | Login username |
| `password_hash` | Werkzeug password hash |
| `role` | User role shown in the dashboard and used by protected logic |
| `is_active` | Whether the account can authenticate |
| `failed_attempts` | Failed login counter |
| `created_at` | User creation timestamp |
| `last_login_at` | Last successful login timestamp |

Table name:

```text
cases
```

Columns:

| Column | Purpose |
| --- | --- |
| `id` | Unique case ID |
| `title` | Case title/name |
| `description` | Optional case description |
| `status` | Case status |
| `created_at` | Case creation timestamp |

Table name:

```text
logs
```

Columns:

| Column | Purpose |
| --- | --- |
| `id` | Unique event ID |
| `case_id` | Case that owns this log event |
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

The dashboard and investigation API routes require login. Users are stored in SQLite and authenticated through password hashes. The app keeps the active identity in the Flask session, including username and role, and rejects unauthenticated API requests with `401` JSON responses.

Case access is intentionally simple in this single-analyst version: if the case exists, authenticated users can use it. The project does not currently enforce assigned users, case owners, or role-based case permissions.

Session cookies are configured with:

- `HttpOnly`
- `SameSite=Lax`
- `Secure=True` when `FLASK_ENV=production`

The authentication layer also tracks failed attempts and blocks login after repeated failures.

### CSRF Protection

POST, PUT, PATCH, and DELETE requests require a CSRF token. The login form includes a hidden token, and the dashboard sends the token in the `X-CSRF-Token` header for mutating API calls.

This protects actions such as:

- Creating cases
- Uploading pasted logs
- Uploading files
- Clearing case logs

### Security Headers

Every response includes browser hardening headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- `Cache-Control: no-store`
- `Content-Security-Policy`

### Audit Trail

Sensitive actions are written to:

```text
data/audit.log
```

The audit log records metadata only. It does not copy raw uploaded or pasted log contents.

Audited actions include:

- Login success and failure
- Logout
- Case creation
- Pasted log upload
- File upload
- Report export
- Chain verification
- Natural-language case query metadata
- Clearing case logs

### Upload Safety

The application limits request/upload size with `MAX_CONTENT_LENGTH`. The default limit is 5 MB and can be changed with the `MAX_UPLOAD_BYTES` environment variable.

Uploaded filenames are sanitized before validation and audit logging. Raw uploaded files are not saved to disk by the application; they are decoded and analyzed in memory.

### Compliance Notes

This project includes several controls that support a basic forensic and compliance story:

| Area | Current implementation |
| --- | --- |
| Access control | Login-protected dashboard and API routes |
| Password storage | Werkzeug password hashes in SQLite |
| Session protection | HttpOnly cookies, SameSite=Lax, timeout, production Secure flag |
| CSRF protection | Required token for mutating requests |
| Evidence separation | Case-scoped storage, search, export, and clear actions |
| Evidence integrity | SHA-256 hash chaining plus verification endpoint |
| Auditability | Metadata audit log for sensitive actions |
| Data minimization | Audit log avoids storing raw evidence content |
| Forensic reconstruction | Local entity extraction and timeline correlation without sending logs to an external AI service |
| Enterprise handoff | SIEM payload export and optional push connectors preserve event hashes |
| Upload control | Extension checks, `.evtx` blocking, size limit, filename sanitization |

Known compliance limitations:

- This is a local student/project system, not a certified forensic platform.
- SQLite is suitable for demos and small investigations, but larger deployments should use managed database storage with backups and access controls.
- Audit log retention, log rotation, and administrator review workflow are not fully implemented.
- Multi-user case permissions are intentionally out of scope for the current single-analyst version.

### Tamper Awareness

Hash chaining helps detect modification of stored logs.

### Explainability

Every alert includes reasons and every timeline event includes extracted supporting evidence. Explanations may include:

- Severity level
- Source IP
- Event type
- Failed authentication
- Suspicious command
- Web attack signature
- Destructive file activity
- File-transfer channel
- Ransomware/encryption phase

### Evidence Preservation

The raw log line is preserved exactly in the database.

## 14. Limitations

Current limitations:

- Raw `.evtx` files must be exported first as XML, CSV, or TXT.
- Natural-language querying is currently rule-guided and local; external LLM/RAG integration is not yet implemented.
- SIEM export and basic push are implemented, but full SOAR playbook automation is not yet implemented.
- The PDF report is simple and text-based.
- The ML model quality depends on the dataset used to train the existing `.h5` model.
- Timeline correlation is scenario-aware but still heuristic; certified forensic validation would require broader real-world datasets and examiner review.
- Large enterprise-scale log volumes may require PostgreSQL, Elasticsearch, or cloud storage instead of SQLite.

## 15. Future Enhancements

Recommended future improvements:

- Upgrade the local natural-language query panel with LLM/RAG support
- Add role-based case access if the project later expands to multiple analysts
- Add richer correlation rules for cloud, IAM, EDR, proxy, and mobile forensic logs
- Add PostgreSQL/Elasticsearch as primary storage backends for large deployments
- Add advanced PDF report formatting
- Add MITRE ATT&CK mapping to timeline phases
- Add bidirectional SIEM/SOAR actions such as ticket creation and containment playbooks
- Add cloud deployment support
- Add benchmarking dashboard
- Add support for direct `.evtx` parsing using a specialized library

## 16. Conclusion

This project implements a practical AI-based log investigation and alert system for cyber forensics. It allows investigators to ingest real logs, parse important fields, detect suspicious activity, correlate events into scenario-aware timelines, preserve logs with integrity hashes, ask case questions, search and filter evidence, view graphical summaries, and export investigation reports.

The system is modular, follows SOLID principles, and can be extended with more parsers, AI models, report types, and enterprise integrations.
