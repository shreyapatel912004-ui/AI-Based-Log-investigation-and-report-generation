import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from domain import ScoredEvent


class LogRepository:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def initialize(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_name TEXT NOT NULL,
                    line_no INTEGER NOT NULL,
                    ingested_at TEXT NOT NULL,
                    event_time TEXT,
                    source_ip TEXT,
                    severity TEXT,
                    event_type TEXT,
                    risk_score REAL,
                    verdict TEXT,
                    explanation TEXT,
                    model_source TEXT,
                    raw_log TEXT NOT NULL,
                    previous_hash TEXT,
                    integrity_hash TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_case ON logs(case_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_verdict ON logs(verdict)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)")
            self._ensure_column(conn, "logs", "explanation", "TEXT")

    def save_events(self, case_name: str, events: List[ScoredEvent]):
        ingested_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        with self._connect() as conn:
            previous_hash = self._latest_hash(conn)
            for event in events:
                integrity_hash = self.chain_hash(event.raw_log, previous_hash)
                conn.execute(
                    """
                    INSERT INTO logs (
                        case_name, line_no, ingested_at, event_time, source_ip, severity,
                        event_type, risk_score, verdict, explanation, model_source, raw_log,
                        previous_hash, integrity_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_name,
                        event.line_no,
                        ingested_at,
                        event.timestamp,
                        event.source_ip,
                        event.severity,
                        event.event_type,
                        event.risk_score,
                        event.verdict,
                        event.explanation,
                        event.model_source,
                        event.raw_log,
                        previous_hash,
                        integrity_hash,
                    ),
                )
                previous_hash = integrity_hash

    def query_events(self, filters: Dict, limit: int = 250) -> List[Dict]:
        clauses = []
        values = []

        if filters.get("search"):
            clauses.append("raw_log LIKE ?")
            values.append(f"%{filters['search']}%")
        if filters.get("verdict"):
            clauses.append("verdict = ?")
            values.append(filters["verdict"])
        if filters.get("severity"):
            clauses.append("severity = ?")
            values.append(filters["severity"])
        if filters.get("source_ip"):
            clauses.append("source_ip = ?")
            values.append(filters["source_ip"])
        if filters.get("event_type"):
            clauses.append("event_type = ?")
            values.append(filters["event_type"])

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM logs
                {where}
                ORDER BY id DESC
                LIMIT ?
                """,
                values,
            ).fetchall()

        return [dict(row) for row in rows]

    def clear(self):
        with self._connect() as conn:
            conn.execute("DELETE FROM logs")

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _latest_hash(self, conn) -> str:
        previous = conn.execute("SELECT integrity_hash FROM logs ORDER BY id DESC LIMIT 1").fetchone()
        return previous["integrity_hash"] if previous else ""

    def chain_hash(self, raw_log: str, previous_hash: str = "") -> str:
        payload = f"{previous_hash}|{raw_log}".encode("utf-8", errors="replace")
        return hashlib.sha256(payload).hexdigest()

    def _ensure_column(self, conn, table_name: str, column_name: str, column_type: str):
        columns = [row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()]
        if column_name not in columns:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
