import csv
import io
import json
from datetime import datetime
from typing import Dict, List


class ReportExporter:
    def json_report(self, summary: Dict, events: List[Dict]) -> str:
        return json.dumps({"summary": summary, "events": events}, indent=2)

    def csv_report(self, events: List[Dict]) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(events[0].keys()) if events else ["message"])
        writer.writeheader()
        if events:
            writer.writerows(events)
        else:
            writer.writerow({"message": "No events found"})
        return output.getvalue()

    def pdf_report(self, summary: Dict, events: List[Dict]) -> bytes:
        lines = [
            "AI Log Investigation Report",
            f"Generated: {datetime.utcnow().isoformat(timespec='seconds')}Z",
            "",
            f"Total logs: {summary['total_logs']}",
            f"Alerts: {summary['alerts']}",
            f"Attacks: {summary['attacks']}",
            f"Average risk: {summary['average_risk']}%",
            "",
            "Top Events:",
        ]
        for event in events[:80]:
            lines.append(
                f"#{event['id']} {event['verdict']} {event['risk_score']}% "
                f"{event['source_ip']} {event['severity']} {event['event_type']} - {event['raw_log'][:90]}"
            )

        text = "\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 10 Tf 50 780 Td 14 TL ({text.replace(chr(10), ') Tj T* (')}) Tj ET"
        objects = [
            "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
            "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
            "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
            "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
            f"5 0 obj << /Length {len(stream.encode('latin-1', errors='replace'))} >> stream\n{stream}\nendstream endobj",
        ]
        body = "%PDF-1.4\n"
        offsets = [0]
        for obj in objects:
            offsets.append(len(body.encode("latin-1", errors="replace")))
            body += obj + "\n"
        xref_at = len(body.encode("latin-1", errors="replace"))
        body += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
        for offset in offsets[1:]:
            body += f"{offset:010d} 00000 n \n"
        body += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF"
        return body.encode("latin-1", errors="replace")
