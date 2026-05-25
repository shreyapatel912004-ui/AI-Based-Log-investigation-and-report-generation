import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from flask import request, session


class AuditLogger:
    def __init__(self, audit_path: Path):
        if os.environ.get("VERCEL"):
            self.audit_path = Path("/tmp/audit.log")
        else:
            self.audit_path = Path(audit_path)

    def record(self, action: str, status: str = "success", details: Optional[Dict] = None):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "status": status,
            "username": session.get("username", "anonymous"),
            "role": session.get("role", "anonymous"),
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip(),
            "method": request.method,
            "path": request.path,
            "details": details or {},
        }
        with self.audit_path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(entry, sort_keys=True) + "\n")


def apply_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    return response


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_token_from_request() -> str:
    return (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
        or (request.get_json(silent=True) or {}).get("csrf_token")
        or ""
    )


def is_valid_csrf() -> bool:
    expected = session.get("csrf_token")
    supplied = csrf_token_from_request()
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))
