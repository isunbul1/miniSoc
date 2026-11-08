"""Service layer for SecurityLog business logic.

Sits between the API router and the repository, applying
business rules before delegating to the data-access layer.
"""

from sqlalchemy.orm import Session

from app.core.enums import LogSeverity
from app.repositories.log_repository import LogRepository
from app.schemas.security_log import (
    SecurityLogCreate,
    SecurityLogListResponse,
    SecurityLogResponse,
)


class LogService:
    """Business logic for security log operations."""

    def __init__(self, db: Session) -> None:
        self.repo = LogRepository(db)

    def get_logs(
        self,
        skip: int = 0,
        limit: int = 25,
        severity: LogSeverity | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
    ) -> SecurityLogListResponse:
        """Return a paginated list of security logs."""
        logs = self.repo.get_all(
            skip=skip,
            limit=limit,
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
        )
        total = self.repo.count(
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
        )
        return SecurityLogListResponse(
            items=[SecurityLogResponse.model_validate(log) for log in logs],
            total=total,
            skip=skip,
            limit=limit,
        )

    def get_log_by_id(self, log_id: int) -> SecurityLogResponse | None:
        """Return a single log or None if not found."""
        log = self.repo.get_by_id(log_id)
        if log is None:
            return None
        return SecurityLogResponse.model_validate(log)

    def create_log(self, data: SecurityLogCreate) -> SecurityLogResponse:
        """Create a new security log entry."""
        log = self.repo.create(data.model_dump())
        return SecurityLogResponse.model_validate(log)

    def delete_log(self, log_id: int) -> bool:
        """Delete a log by ID. Returns True if deleted."""
        return self.repo.delete(log_id)
