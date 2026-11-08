"""Repository for SecurityLog database operations.

Encapsulates all direct database queries for security logs.
"""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.security_log import SecurityLog


class LogRepository:
    """Data-access layer for SecurityLog records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_all(
        self,
        skip: int = 0,
        limit: int = 25,
        severity: Any | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
    ) -> list[SecurityLog]:
        """Retrieve a paginated, optionally filtered list of logs."""
        query = self.db.query(SecurityLog)

        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity).lower()
            query = query.filter(SecurityLog.severity == sev_val)
        if event_type:
            query = query.filter(SecurityLog.event_type == event_type)
        if source_ip:
            query = query.filter(SecurityLog.source_ip == str(source_ip))

        return query.order_by(SecurityLog.timestamp.desc()).offset(skip).limit(limit).all()

    def count(
        self,
        severity: Any | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
    ) -> int:
        """Count logs matching the given filters."""
        query = self.db.query(func.count(SecurityLog.id))

        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity).lower()
            query = query.filter(SecurityLog.severity == sev_val)
        if event_type:
            query = query.filter(SecurityLog.event_type == event_type)
        if source_ip:
            query = query.filter(SecurityLog.source_ip == str(source_ip))

        return query.scalar() or 0

    def get_by_id(self, log_id: int) -> SecurityLog | None:
        """Retrieve a single log by its primary key."""
        return self.db.query(SecurityLog).filter(SecurityLog.id == log_id).first()

    def create(self, log_data: dict) -> SecurityLog:
        """Insert a new security log record."""
        if "timestamp" not in log_data or log_data["timestamp"] is None:
            log_data["timestamp"] = datetime.now(timezone.utc)
        log = SecurityLog(**log_data)
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)
        return log

    def delete(self, log_id: int) -> bool:
        """Delete a log record by ID. Returns True if deleted."""
        log = self.get_by_id(log_id)
        if log is None:
            return False
        self.db.delete(log)
        self.db.commit()
        return True
