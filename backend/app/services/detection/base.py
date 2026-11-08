"""Base classes and data contracts for the MiniSOC threat detection engine."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.core.enums import AlertSeverity
from app.models.security_log import SecurityLog


@dataclass
class DetectionAlertDraft:
    """Represents a potential alert produced by a detection rule."""

    rule_id: str
    technique_id: str
    title: str
    description: str
    severity: AlertSeverity
    source_ip: str | None
    incident_start: datetime
    detection_time: datetime
    window: timedelta
    event_count: int = 1
    incident_fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.incident_fingerprint:
            start_str = (
                self.incident_start.isoformat() if self.incident_start else "none"
            )
            self.incident_fingerprint = (
                f"{self.rule_id}:{self.source_ip or 'unknown'}:{start_str}"
            )


class BaseDetectionRule(ABC):
    """Abstract base class that all threat detection rules must implement.

    Adheres to the Open/Closed Principle: new rules can be added to the engine
    without modifying the DetectionEngine execution logic.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., 'RULE-T1110')."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable rule name."""
        pass

    @property
    @abstractmethod
    def mitre_technique_id(self) -> str:
        """Associated MITRE ATT&CK technique code (e.g., 'T1110')."""
        pass

    @property
    @abstractmethod
    def default_severity(self) -> AlertSeverity:
        """Default severity assigned to alerts created by this rule."""
        pass

    @abstractmethod
    def evaluate(self, logs: list[SecurityLog]) -> list[DetectionAlertDraft]:
        """Scan a chronological list of logs and yield alert drafts."""
        pass
