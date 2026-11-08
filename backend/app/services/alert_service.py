"""Service layer for SecurityAlert business logic.

Sits between the API router and the repository, applying
business rules and validation before delegating to data-access.
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.enums import AlertSeverity, AlertStatus
from app.repositories.alert_repository import AlertRepository
from app.repositories.mitre_repository import MitreRepository
from app.schemas.security_alert import (
    SecurityAlertCreate,
    SecurityAlertListResponse,
    SecurityAlertResponse,
    SecurityAlertUpdate,
)


class AlertService:
    """Business logic for security alert operations."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repo = AlertRepository(db)
        self.mitre_repo = MitreRepository(db)

    def get_alerts(
        self,
        skip: int = 0,
        limit: int = 25,
        severity: AlertSeverity | None = None,
        status: AlertStatus | None = None,
    ) -> SecurityAlertListResponse:
        """Return a paginated list of security alerts."""
        alerts = self.repo.get_all(
            skip=skip,
            limit=limit,
            severity=severity,
            status=status,
        )
        total = self.repo.count(severity=severity, status=status)
        return SecurityAlertListResponse(
            items=[SecurityAlertResponse.model_validate(alert) for alert in alerts],
            total=total,
            skip=skip,
            limit=limit,
        )

    def get_alert_by_id(self, alert_id: int) -> SecurityAlertResponse | None:
        """Return a single alert or None if not found."""
        alert = self.repo.get_by_id(alert_id)
        if alert is None:
            return None
        return SecurityAlertResponse.model_validate(alert)

    def create_alert(self, data: SecurityAlertCreate) -> SecurityAlertResponse:
        """Create a new security alert with foreign key validation."""
        if data.mitre_technique_id is not None:
            technique = self.mitre_repo.get_by_id(data.mitre_technique_id)
            if technique is None:
                raise HTTPException(
                    status_code=422,
                    detail=f"MITRE technique with id {data.mitre_technique_id} does not exist",
                )
        alert = self.repo.create(data.model_dump())
        return SecurityAlertResponse.model_validate(alert)

    def update_alert(
        self, alert_id: int, data: SecurityAlertUpdate
    ) -> SecurityAlertResponse | None:
        """Partially update an alert. Returns None if not found."""
        update_data = data.model_dump(exclude_unset=True)
        if not update_data:
            return self.get_alert_by_id(alert_id)
        alert = self.repo.update(alert_id, update_data)
        if alert is None:
            return None
        return SecurityAlertResponse.model_validate(alert)

    def delete_alert(self, alert_id: int) -> bool:
        """Delete an alert by ID. Returns True if deleted."""
        return self.repo.delete(alert_id)
