"""Pydantic schemas for SecurityAlert request/response validation."""

from datetime import datetime, timezone

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_serializer,
    field_validator,
)

from app.core.enums import AlertSeverity, AlertStatus


class SecurityAlertCreate(BaseModel):
    """Schema for creating a new security alert."""

    title: str = Field(..., min_length=1, max_length=200)
    description: str | None = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN
    source_ip: IPvAnyAddress | None = None
    rule_id: str | None = None
    incident_start: datetime | None = None
    incident_key: str | None = None
    detection_time: datetime | None = None
    mitre_technique_id: int | None = None

    @field_serializer("source_ip")
    def serialize_source_ip(self, v: IPvAnyAddress | None, _info) -> str | None:
        return str(v) if v is not None else None


class SecurityAlertUpdate(BaseModel):
    """Schema for partially updating a security alert.

    Strictly forbids any fields other than status, severity, and description.
    """

    status: AlertStatus | None = None
    severity: AlertSeverity | None = None
    description: str | None = None

    model_config = ConfigDict(extra="forbid")


class MitreTechniqueNested(BaseModel):
    """Minimal MITRE technique info embedded in alert responses."""

    id: int
    technique_id: str
    technique_name: str
    tactic: str

    model_config = ConfigDict(from_attributes=True)


class SecurityAlertResponse(BaseModel):
    """Schema for returning a security alert with normalized UTC timestamp."""

    id: int
    title: str
    description: str | None
    severity: AlertSeverity
    status: AlertStatus
    source_ip: str | None
    rule_id: str | None = None
    incident_start: datetime | None = None
    incident_key: str | None = None
    detection_time: datetime
    mitre_technique_id: int | None
    mitre_technique: MitreTechniqueNested | None = None

    @field_validator("detection_time", "incident_start", mode="after")
    @classmethod
    def normalize_utc_timestamp(cls, v: datetime | None) -> datetime | None:
        """Ensure naive datetimes from SQLite are normalized to timezone-aware UTC."""
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    model_config = ConfigDict(from_attributes=True)


class SecurityAlertListResponse(BaseModel):
    """Paginated list of security alerts."""

    items: list[SecurityAlertResponse]
    total: int
    skip: int
    limit: int
