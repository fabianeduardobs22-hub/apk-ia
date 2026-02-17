import hashlib
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import AuditLog


def _calculate_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_action(db: Session, user_id: int, action: str, metadata: dict | None = None) -> AuditLog:
    metadata = metadata or {}
    last_entry = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    previous_hash = last_entry.current_hash if last_entry else "GENESIS"
    timestamp = datetime.utcnow()

    canonical_metadata = json.dumps(metadata, sort_keys=True)
    current_hash = _calculate_hash(f"{user_id}|{action}|{canonical_metadata}|{timestamp.isoformat()}|{previous_hash}")

    entry = AuditLog(
        user_id=user_id,
        action=action,
        details=canonical_metadata,
        timestamp=timestamp,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
