"""Tests for SQLAlchemy ORM model creation, representations, and relationships."""

from app.core.enums import AlertSeverity, AlertStatus, LogSeverity
from app.models.mitre_technique import MitreTechnique
from app.models.security_alert import SecurityAlert
from app.models.security_log import SecurityLog


def test_create_security_log_model(db_session):
    """Test creating and persisting a SecurityLog instance with LogSeverity."""
    log = SecurityLog(
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        username="admin",
        event_type="auth_failure",
        description="Multiple failed login attempts",
        severity=LogSeverity.HIGH,
        raw_log="Failed password for invalid user admin from 192.168.1.50 port 44122 ssh2",
    )
    db_session.add(log)
    db_session.commit()

    assert log.id is not None
    assert log.timestamp is not None
    assert log.source_ip == "192.168.1.50"
    assert log.severity == LogSeverity.HIGH
    assert "<SecurityLog" in repr(log)


def test_create_mitre_technique_model(db_session):
    """Test creating and persisting a MitreTechnique instance."""
    technique = MitreTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        description="Password guessing and brute force.",
    )
    db_session.add(technique)
    db_session.commit()

    assert technique.id is not None
    assert technique.technique_id == "T1110"
    assert "<MitreTechnique" in repr(technique)


def test_create_security_alert_with_mitre_relationship(db_session):
    """Test alert creation linked to a MITRE technique via relationship."""
    technique = MitreTechnique(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        description="PowerShell abuse.",
    )
    db_session.add(technique)
    db_session.commit()

    alert = SecurityAlert(
        title="Suspicious PowerShell Execution",
        description="Base64 encoded command detected",
        severity=AlertSeverity.CRITICAL,
        status=AlertStatus.OPEN,
        source_ip="10.0.0.15",
        mitre_technique_id=technique.id,
    )
    db_session.add(alert)
    db_session.commit()

    assert alert.id is not None
    assert alert.mitre_technique is not None
    assert alert.mitre_technique.technique_id == "T1059"
    assert len(technique.alerts) == 1
    assert technique.alerts[0].title == "Suspicious PowerShell Execution"
