import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional


class EnterpriseEventMapper:
    def to_common_event(self, event: Dict, case: Optional[Dict] = None) -> Dict:
        case = case or {}
        return {
            "case_id": event.get("case_id") or case.get("id"),
            "case_name": event.get("case_name") or case.get("title"),
            "event_id": event.get("id"),
            "line_no": event.get("line_no"),
            "event_time": event.get("event_time") or event.get("timestamp") or event.get("ingested_at"),
            "ingested_at": event.get("ingested_at"),
            "source_ip": event.get("source_ip") or "unknown",
            "severity": event.get("severity") or "INFO",
            "event_type": event.get("event_type") or "general",
            "risk_score": event.get("risk_score") or 0,
            "verdict": event.get("verdict") or "NORMAL",
            "explanation": event.get("explanation") or "",
            "model_source": event.get("model_source") or "",
            "raw_log": event.get("raw_log") or "",
            "integrity_hash": event.get("integrity_hash") or "",
            "previous_hash": event.get("previous_hash") or "",
            "framework": "ai-log-forensics",
        }

    def severity_number(self, severity: str, verdict: str) -> int:
        if verdict == "ATTACK":
            return 9
        if verdict == "SUSPICIOUS":
            return 6
        return {
            "CRITICAL": 9,
            "ALERT": 8,
            "ERROR": 6,
            "WARNING": 5,
            "NOTICE": 3,
            "INFO": 2,
            "DEBUG": 1,
        }.get((severity or "").upper(), 2)

    def epoch_time(self, value: Optional[str]) -> float:
        if not value:
            return datetime.now(timezone.utc).timestamp()
        normalized = value.replace("Z", "+00:00").replace(" ", "T")
        try:
            return datetime.fromisoformat(normalized).timestamp()
        except ValueError:
            return datetime.now(timezone.utc).timestamp()


class EnterpriseExporter:
    SUPPORTED_FORMATS = {
        "elastic": "Elasticsearch/OpenSearch Bulk NDJSON",
        "splunk": "Splunk HEC JSON events",
        "cef": "Common Event Format",
        "leef": "IBM QRadar LEEF",
        "ndjson": "Generic normalized NDJSON",
    }

    def __init__(self, mapper: Optional[EnterpriseEventMapper] = None):
        self.mapper = mapper or EnterpriseEventMapper()

    def export(self, target: str, case: Dict, events: List[Dict]) -> str:
        target = target.lower()
        common_events = [self.mapper.to_common_event(event, case) for event in events]

        if target == "elastic":
            return self.elastic_bulk(common_events)
        if target == "splunk":
            return self.splunk_hec(common_events)
        if target == "cef":
            return self.cef(common_events)
        if target == "leef":
            return self.leef(common_events)
        if target == "ndjson":
            return self.ndjson(common_events)
        raise ValueError("Unsupported integration export target.")

    def ndjson(self, events: List[Dict]) -> str:
        return "\n".join(json.dumps(event, sort_keys=True) for event in events) + ("\n" if events else "")

    def elastic_bulk(self, events: List[Dict]) -> str:
        lines = []
        for event in events:
            index_name = f"forensics-case-{event.get('case_id') or 'unknown'}"
            event_id = event.get("event_id") or event.get("integrity_hash") or None
            action = {"index": {"_index": index_name}}
            if event_id is not None:
                action["index"]["_id"] = str(event_id)
            lines.append(json.dumps(action, sort_keys=True))
            lines.append(json.dumps(event, sort_keys=True))
        return "\n".join(lines) + ("\n" if lines else "")

    def splunk_hec(self, events: List[Dict]) -> str:
        lines = []
        for event in events:
            payload = {
                "time": self.mapper.epoch_time(event.get("event_time")),
                "host": event.get("case_name") or "ai-log-forensics",
                "source": "ai-log-forensics",
                "sourcetype": "ai_forensics:log",
                "index": os.environ.get("SPLUNK_INDEX", "main"),
                "event": event,
            }
            lines.append(json.dumps(payload, sort_keys=True))
        return "\n".join(lines) + ("\n" if lines else "")

    def cef(self, events: List[Dict]) -> str:
        lines = []
        for event in events:
            severity = self.mapper.severity_number(event.get("severity"), event.get("verdict"))
            name = self._escape_cef(event.get("event_type") or "forensic_event")
            extension = {
                "src": event.get("source_ip") or "unknown",
                "cs1Label": "case",
                "cs1": event.get("case_name") or "",
                "cs2Label": "verdict",
                "cs2": event.get("verdict") or "",
                "cs3Label": "integrity_hash",
                "cs3": event.get("integrity_hash") or "",
                "msg": event.get("explanation") or event.get("raw_log") or "",
            }
            extension_text = " ".join(f"{key}={self._escape_cef(str(value))}" for key, value in extension.items())
            lines.append(f"CEF:0|AI Log Forensics|Investigation Framework|1.0|{event.get('event_type')}|{name}|{severity}|{extension_text}")
        return "\n".join(lines) + ("\n" if lines else "")

    def leef(self, events: List[Dict]) -> str:
        lines = []
        for event in events:
            severity = self.mapper.severity_number(event.get("severity"), event.get("verdict"))
            fields = {
                "devTime": event.get("event_time") or "",
                "src": event.get("source_ip") or "unknown",
                "sev": severity,
                "cat": event.get("event_type") or "general",
                "usrName": event.get("case_name") or "",
                "riskScore": event.get("risk_score") or 0,
                "verdict": event.get("verdict") or "",
                "integrityHash": event.get("integrity_hash") or "",
                "msg": event.get("explanation") or event.get("raw_log") or "",
            }
            field_text = "\t".join(f"{key}={str(value).replace(chr(9), ' ')}" for key, value in fields.items())
            lines.append(f"LEEF:2.0|AI Log Forensics|Investigation Framework|1.0|{event.get('event_type') or 'event'}|\t{field_text}")
        return "\n".join(lines) + ("\n" if lines else "")

    def _escape_cef(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


class EnterprisePushClient:
    def __init__(self, exporter: EnterpriseExporter):
        self.exporter = exporter

    def status(self) -> Dict:
        return {
            "splunk": {
                "configured": bool(os.environ.get("SPLUNK_HEC_URL") and os.environ.get("SPLUNK_HEC_TOKEN")),
                "required_env": ["SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN"],
                "optional_env": ["SPLUNK_INDEX"],
            },
            "elastic": {
                "configured": bool(os.environ.get("ELASTIC_BULK_URL")),
                "required_env": ["ELASTIC_BULK_URL"],
                "optional_env": ["ELASTIC_API_KEY", "ELASTIC_BASIC_AUTH"],
            },
        }

    def push(self, target: str, case: Dict, events: List[Dict]) -> Dict:
        target = target.lower()
        if target == "splunk":
            return self._push_splunk(case, events)
        if target == "elastic":
            return self._push_elastic(case, events)
        raise ValueError("Unsupported push target.")

    def _push_splunk(self, case: Dict, events: List[Dict]) -> Dict:
        url = os.environ.get("SPLUNK_HEC_URL")
        token = os.environ.get("SPLUNK_HEC_TOKEN")
        if not url or not token:
            raise ValueError("Splunk push is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN.")

        payload = self.exporter.export("splunk", case, events)
        return self._post(url, payload, {"Authorization": f"Splunk {token}", "Content-Type": "application/json"})

    def _push_elastic(self, case: Dict, events: List[Dict]) -> Dict:
        url = os.environ.get("ELASTIC_BULK_URL")
        if not url:
            raise ValueError("Elasticsearch/OpenSearch push is not configured. Set ELASTIC_BULK_URL.")

        headers = {"Content-Type": "application/x-ndjson"}
        if os.environ.get("ELASTIC_API_KEY"):
            headers["Authorization"] = f"ApiKey {os.environ['ELASTIC_API_KEY']}"
        elif os.environ.get("ELASTIC_BASIC_AUTH"):
            headers["Authorization"] = f"Basic {os.environ['ELASTIC_BASIC_AUTH']}"

        payload = self.exporter.export("elastic", case, events)
        return self._post(url, payload, headers)

    def _post(self, url: str, payload: str, headers: Dict[str, str]) -> Dict:
        timeout = float(os.environ.get("SIEM_PUSH_TIMEOUT_SECONDS", "8"))
        request = urllib.request.Request(url, data=payload.encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                return {"ok": 200 <= response.status < 300, "status_code": response.status, "response": body[:2000]}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return {"ok": False, "status_code": exc.code, "response": body[:2000]}
        except urllib.error.URLError as exc:
            return {"ok": False, "status_code": 0, "response": str(exc.reason)}
