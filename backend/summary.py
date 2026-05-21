from collections import Counter
from typing import Dict, Iterable


class InvestigationSummary:
    def build(self, events: Iterable[Dict]) -> Dict:
        events = list(events)
        verdict_counts = Counter(event["verdict"] for event in events)
        severity_counts = Counter(event["severity"] for event in events)
        event_type_counts = Counter(event["event_type"] for event in events)
        ip_counter = Counter(event["source_ip"] for event in events if event["source_ip"] != "unknown")
        high_risk = [event for event in events if event["verdict"] in {"ATTACK", "SUSPICIOUS"}]

        return {
            "total_logs": len(events),
            "alerts": len(high_risk),
            "attacks": verdict_counts.get("ATTACK", 0),
            "suspicious": verdict_counts.get("SUSPICIOUS", 0),
            "normal": verdict_counts.get("NORMAL", 0),
            "verdict_counts": dict(verdict_counts),
            "severity_counts": dict(severity_counts),
            "event_type_counts": dict(event_type_counts),
            "top_ips": dict(ip_counter.most_common(8)),
            "average_risk": round(sum(event["risk_score"] for event in events) / len(events), 2) if events else 0,
            "highest_risk": max((event["risk_score"] for event in events), default=0),
        }
