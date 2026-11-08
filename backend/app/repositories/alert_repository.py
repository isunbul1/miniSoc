"""Repository for SecurityAlert database operations.

Encapsulates all direct database queries for security alerts.
"""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.models.security_alert import SecurityAlert


class AlertRepository:
    """Data-access layer for SecurityAlert records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_all(
        self,
        skip: int = 0,
        limit: int = 25,
        severity: Any | None = None,
        status: Any | None = None,
    ) -> list[SecurityAlert]:
        """Retrieve a paginated, optionally filtered list of alerts."""
        query = self.db.query(SecurityAlert).options(
            joinedload(SecurityAlert.mitre_technique)
        )

        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity).lower()
            query = query.filter(SecurityAlert.severity == sev_val)
        if status:
            stat_val = status.value if hasattr(status, "value") else str(status).lower()
            query = query.filter(SecurityAlert.status == stat_val)

        return (
            query.order_by(SecurityAlert.detection_time.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def count(
        self,
        severity: Any | None = None,
        status: Any | None = None,
    ) -> int:
        """Count alerts matching the given filters."""
        query = self.db.query(func.count(SecurityAlert.id))

        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity).lower()
            query = query.filter(SecurityAlert.severity == sev_val)
        if status:
            stat_val = status.value if hasattr(status, "value") else str(status).lower()
            query = query.filter(SecurityAlert.status == stat_val)

        return query.scalar() or 0

    def get_by_id(self, alert_id: int) -> SecurityAlert | None:
        """Retrieve a single alert by its primary key, with MITRE technique loaded."""
        return (
            self.db.query(SecurityAlert)
            .options(joinedload(SecurityAlert.mitre_technique))
            .filter(SecurityAlert.id == alert_id)
            .first()
        )

    def create(self, alert_data: dict) -> SecurityAlert:
        """Insert a new security alert record."""
        if "detection_time" not in alert_data or alert_data["detection_time"] is None:
            alert_data["detection_time"] = datetime.now(timezone.utc)
        alert = SecurityAlert(**alert_data)
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def update(self, alert_id: int, update_data: dict) -> SecurityAlert | None:
        """Update an existing alert. Returns None if not found."""
        alert = self.get_by_id(alert_id)
        if alert is None:
            return None

        for key, value in update_data.items():
            if value is not None:
                setattr(alert, key, value)

        self.db.commit()
        self.db.refresh(alert)
        return alert

    def delete(self, alert_id: int) -> bool:
        """Delete an alert record by ID. Returns True if deleted."""
        alert = (
            self.db.query(SecurityAlert)
            .filter(SecurityAlert.id == alert_id)
            .first()
        )
        if alert is None:
            return False
        self.db.delete(alert)
        self.db.commit()
        return True
