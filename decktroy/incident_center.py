#!/usr/bin/env python3
"""DECKTROY Incident Center (defensive case management)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_FILE = Path("decktroy_incidents.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict[str, Any]:
    if not DB_FILE.exists():
        return {"created_at": utc_now(), "incidents": []}
    try:
        return json.loads(DB_FILE.read_text(encoding="utf-8"))
    except Exception:  # pylint: disable=broad-except
        return {"created_at": utc_now(), "incidents": []}


def _save(data: dict[str, Any]) -> None:
    DB_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def list_incidents() -> list[dict[str, Any]]:
    return _load().get("incidents", [])


def create_incident(title: str, severity: str, source: str, details: str, tags: list[str] | None = None) -> dict[str, Any]:
    data = _load()
    incidents = data.get("incidents", [])
    incident_id = f"INC-{len(incidents)+1:06d}"
    incident = {
        "id": incident_id,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "status": "open",
        "title": title,
        "severity": severity,
        "source": source,
        "details": details,
        "tags": tags or [],
        "timeline": [{"ts": utc_now(), "event": "incident_created", "detail": title}],
        "evidence": [],
    }
    incidents.append(incident)
    data["incidents"] = incidents
    _save(data)
    return incident


def update_incident_status(incident_id: str, status: str, note: str = "") -> dict[str, Any] | None:
    data = _load()
    incidents = data.get("incidents", [])
    for inc in incidents:
        if inc.get("id") == incident_id:
            inc["status"] = status
            inc["updated_at"] = utc_now()
            inc.setdefault("timeline", []).append({"ts": utc_now(), "event": "status_update", "detail": note or status})
            _save(data)
            return inc
    return None


def add_evidence(incident_id: str, file_path: str, note: str = "") -> dict[str, Any] | None:
    data = _load()
    incidents = data.get("incidents", [])
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return None

    content = p.read_bytes()
    sha = hashlib.sha256(content).hexdigest()

    for inc in incidents:
        if inc.get("id") == incident_id:
            ev = {
                "path": str(p),
                "sha256": sha,
                "size": len(content),
                "captured_at": utc_now(),
                "note": note,
            }
            inc.setdefault("evidence", []).append(ev)
            inc.setdefault("timeline", []).append({"ts": utc_now(), "event": "evidence_added", "detail": str(p)})
            inc["updated_at"] = utc_now()
            _save(data)
            return inc
    return None


def create_from_guard_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    created: list[dict[str, Any]] = []
    for alert in alerts:
        title = f"{alert.get('category','alert')} from {alert.get('source_ip','unknown')}"
        details = alert.get("detail", "")
        tags = [alert.get("category", "unknown"), "connection-guard"]
        inc = create_incident(
            title=title,
            severity=alert.get("severity", "medium"),
            source="connection_guard",
            details=details,
            tags=tags,
        )
        created.append(inc)
    return created
