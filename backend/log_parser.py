import ipaddress
import re
from collections import Counter
from datetime import datetime
from typing import List, Optional

from .domain import ParsedLog


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b")
APACHE_TIME_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})")
SYSLOG_TIME_RE = re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")

SEVERITY_WORDS = {
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "fatal": "CRITICAL",
    "error": "ERROR",
    "err": "ERROR",
    "warning": "WARNING",
    "warn": "WARNING",
    "alert": "ALERT",
    "block": "WARNING",
    "blocked": "WARNING",
    "notice": "NOTICE",
    "info": "INFO",
    "debug": "DEBUG",
}

EVENT_KEYWORDS = {
    "web_attack": ["sqlmap", "union select", "' or '1'='1", "login.php", "wp-login", "xss", "csrf"],
    "authentication": ["login", "logon", "auth", "password", "credential", "ssh", "rdp"],
    "file_activity": ["file", "delete", "deleted", "modify", "chmod", "write"],
    "network": ["connection", "connect", "firewall", "port", "dns", "http", "tcp", "udp"],
    "malware": ["malware", "virus", "trojan", "ransomware", "payload"],
    "privilege": ["sudo", "admin", "root", "privilege", "elevat"],
    "process": ["process", "cmd", "powershell", "bash", "script", "exec"],
    "usb": ["usb", "removable"],
}

SUSPICIOUS_TERMS = [
    "failed",
    "failure",
    "denied",
    "unauthorized",
    "bruteforce",
    "brute force",
    "exploit",
    "injection",
    "malware",
    "ransomware",
    "powershell",
    "encodedcommand",
    "cmd.exe",
    "wget",
    "curl",
    "sqlmap",
    "union select",
    "' or '1'='1",
    "invalid user",
    "ufw block",
    "delete",
    "deleted",
    "sudo",
]


class LogParser:
    def parse(self, logs: str) -> List[ParsedLog]:
        lines = [line.strip() for line in logs.splitlines() if line.strip()]
        ip_counts = Counter(IP_RE.findall("\n".join(lines)))
        return [self._parse_line(line_no, line, ip_counts) for line_no, line in enumerate(lines, start=1)]

    def _parse_line(self, line_no: int, line: str, ip_counts: Counter) -> ParsedLog:
        ip_match = IP_RE.search(line)
        source_ip = ip_match.group(0) if ip_match else "unknown"
        timestamp = self.extract_timestamp(line)
        severity = self.detect_severity(line)
        event_type = self.detect_event_type(line)

        return ParsedLog(
            line_no=line_no,
            timestamp=timestamp,
            source_ip=source_ip,
            severity=severity,
            event_type=event_type,
            raw_log=line,
            features=self.build_features(line, source_ip, ip_counts[source_ip]),
        )

    def extract_timestamp(self, line: str) -> Optional[str]:
        iso_match = ISO_TIME_RE.search(line)
        if iso_match:
            return iso_match.group(0).replace("T", " ")

        apache_match = APACHE_TIME_RE.search(line)
        if apache_match:
            try:
                return datetime.strptime(apache_match.group(1), "%d/%b/%Y:%H:%M:%S").isoformat(sep=" ")
            except ValueError:
                return apache_match.group(1)

        syslog_match = SYSLOG_TIME_RE.search(line)
        if syslog_match:
            return syslog_match.group(1)

        return None

    def detect_severity(self, line: str) -> str:
        lowered = line.lower()
        for word, severity in SEVERITY_WORDS.items():
            if re.search(rf"\b{re.escape(word)}\b", lowered):
                return severity
        if any(term in lowered for term in SUSPICIOUS_TERMS):
            return "WARNING"
        return "INFO"

    def detect_event_type(self, line: str) -> str:
        lowered = line.lower()
        for event_type, keywords in EVENT_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                return event_type
        return "general"

    def build_features(self, line: str, source_ip: str, repeated_ip_count: int) -> List[float]:
        lowered = line.lower()
        hour = 12
        timestamp = self.extract_timestamp(line)
        if timestamp:
            hour_match = re.search(r"\b(\d{2}):\d{2}:\d{2}\b", timestamp)
            if hour_match:
                hour = int(hour_match.group(1))

        login_attempts = max(repeated_ip_count, 1 if any(term in lowered for term in ["login", "auth", "ssh"]) else 0)
        session_level = min(10, max(1, len(line) // 40))
        file_access = int(any(term in lowered for term in ["file", "read", "open", "download"]))
        file_delete = int(any(term in lowered for term in ["delete", "deleted", "remove", "rm "]))
        network_activity = min(10, 1 + sum(term in lowered for term in ["connect", "port", "tcp", "udp", "http", "dns"]))
        process_activity = min(10, sum(term in lowered for term in ["process", "cmd", "powershell", "bash", "exec"]))
        suspicious_cmd = int(any(term in lowered for term in ["powershell", "cmd.exe", "wget", "curl", "base64", "chmod"]))
        remote_login = int(any(term in lowered for term in ["ssh", "rdp", "remote"]))
        usb_activity = int("usb" in lowered or "removable" in lowered)

        return [
            float(login_attempts),
            float(hour),
            float(session_level),
            float(self.ip_to_number(source_ip)),
            float(file_access),
            float(file_delete),
            float(network_activity),
            float(process_activity),
            float(suspicious_cmd),
            float(remote_login),
            float(usb_activity),
        ]

    def ip_to_number(self, source_ip: str) -> int:
        try:
            return int(ipaddress.ip_address(source_ip))
        except ValueError:
            return 0
