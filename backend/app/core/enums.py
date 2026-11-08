"""Domain enums for MiniSOC.

Single source of truth for severity and alert status definitions across
Pydantic schemas and SQLAlchemy ORM models.
"""

from enum import Enum


class LogSeverity(str, Enum):
    """Severity levels for raw security event logs.

    Log severity includes 'info' because security logs capture routine
    telemetry (e.g., successful user logins, health checks, network flows)
    essential for audit trails and baseline behavioral analysis, even when
    no threat is present.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# General alias
Severity = LogSeverity


class AlertSeverity(str, Enum):
    """Severity levels for security alerts.

    Alert severity deliberately excludes 'info' because alerts signify
    actionable security anomalies or threat rule detections requiring
    analyst triage and mitigation. Benign telemetry should never trigger
    an alert, preventing alert fatigue in the SOC.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Lifecycle states of a security alert during investigation."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
