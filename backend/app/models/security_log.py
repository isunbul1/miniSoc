"""SecurityLog ORM model.

Represents raw security events ingested by the SOC platform.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum as SQLEnum,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import LogSeverity
from app.db.database import Base


class SecurityLog(Base):
    """A single security event log entry."""

    __tablename__ = "security_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[LogSeverity] = mapped_column(
        SQLEnum(LogSeverity, native_enum=False, validate_strings=True),
        nullable=False,
        default=LogSeverity.INFO,
    )
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "destination_port IS NULL OR (destination_port >= 0 AND destination_port <= 65535)",
            name="check_valid_destination_port",
        ),
        Index("ix_security_logs_timestamp", "timestamp"),
        Index("ix_security_logs_severity", "severity"),
        Index("ix_security_logs_source_ip", "source_ip"),
        Index("ix_security_logs_event_type", "event_type"),
        Index("ix_security_logs_destination_port", "destination_port"),
    )

    def __repr__(self) -> str:
        return f"<SecurityLog(id={self.id}, event_type={self.event_type}, severity={self.severity})>"
