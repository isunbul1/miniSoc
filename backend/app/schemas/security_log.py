"""Pydantic schemas for SecurityLog request/response validation."""

from datetime import datetime, timezone

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_serializer,
    field_validator,
)

from app.core.enums import LogSeverity


class SecurityLogCreate(BaseModel):
    """Schema for creating a new security log entry."""

    timestamp: datetime | None = None
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    destination_port: int | None = Field(None, ge=0, le=65535)
    username: str | None = Field(None, max_length=100)
    event_type: str = Field(..., min_length=1, max_length=50)
    description: str | None = None
    severity: LogSeverity = LogSeverity.INFO
    command_line: str | None = None
    raw_log: str | None = None

    @field_serializer("source_ip", "destination_ip")
    def serialize_ips(self, v: IPvAnyAddress, _info) -> str:
        return str(v)


class SecurityLogResponse(BaseModel):
    """Schema for returning a security log entry with normalized UTC timestamp."""

    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int | None = None
    username: str | None = None
    event_type: str
    description: str | None = None
    severity: LogSeverity
    command_line: str | None = None
    raw_log: str | None = None

    @field_validator("timestamp", mode="after")
    @classmethod
    def normalize_utc_timestamp(cls, v: datetime) -> datetime:
        """Ensure naive datetimes from SQLite are normalized to timezone-aware UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    model_config = ConfigDict(from_attributes=True)


class SecurityLogListResponse(BaseModel):
    """Paginated list of security logs."""

    items: list[SecurityLogResponse]
    total: int
    skip: int
    limit: int
