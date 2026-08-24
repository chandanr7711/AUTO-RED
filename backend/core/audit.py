"""
Audit trail.

Every scan request - authorized or denied - gets written here.
No update/delete function is exposed on purpose; treat it as append-only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models.database import AuditLog


def record_event(
    db: Session,
    *,
    target: str,
    action: str,
    authorized: bool,
    reason: str,
    requested_by: str = "unknown",
) -> AuditLog:
    entry = AuditLog(
        timestamp=datetime.now(timezone.utc),
        target=target,
        action=action,
        authorized=authorized,
        reason=reason,
        requested_by=requested_by,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
