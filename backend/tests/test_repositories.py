"""Tests for repository data-access layer."""

from app.core.enums import AlertSeverity, AlertStatus, LogSeverity
from app.repositories.alert_repository import AlertRepository
from app.repositories.log_repository import LogRepository
from app.repositories.mitre_repository import MitreRepository


def test_log_repository_crud(db_session):
    """Test CRUD operations on LogRepository."""
    repo = LogRepository(db_session)

    # Create
    log = repo.create({
        "source_ip": "10.0.1.5",
        "destination_ip": "10.0.1.1",
        "username": "user1",
        "event_type": "port_scan",
        "description": "Port scan detected",
        "severity": LogSeverity.MEDIUM,
        "raw_log": "SYN scan against ports 20-100",
    })
    assert log.id is not None
    assert log.event_type == "port_scan"

    # Get by ID
    fetched = repo.get_by_id(log.id)
    assert fetched is not None
    assert fetched.source_ip == "10.0.1.5"

    # Get all & count
    logs = repo.get_all(limit=10)
    assert len(logs) == 1
    assert repo.count() == 1

    # Filtered
    assert repo.count(severity=LogSeverity.MEDIUM) == 1
    assert repo.count(severity=LogSeverity.HIGH) == 0

    # Delete
    deleted = repo.delete(log.id)
    assert deleted is True
    assert repo.get_by_id(log.id) is None
    assert repo.delete(9999) is False


def test_alert_repository_crud(db_session):
    """Test CRUD operations on AlertRepository."""
    repo = AlertRepository(db_session)

    # Create
    alert = repo.create({
        "title": "SQL Injection Attempt",
        "description": "UNION SELECT detected in URI",
        "severity": AlertSeverity.HIGH,
        "status": AlertStatus.OPEN,
        "source_ip": "198.51.100.4",
    })
    assert alert.id is not None
    assert alert.status == AlertStatus.OPEN

    # Update
    updated = repo.update(alert.id, {"status": AlertStatus.INVESTIGATING, "severity": AlertSeverity.CRITICAL})
    assert updated is not None
    assert updated.status == AlertStatus.INVESTIGATING
    assert updated.severity == AlertSeverity.CRITICAL

    # Non-existent update
    assert repo.update(9999, {"status": AlertStatus.RESOLVED}) is None

    # Get all & count
    assert repo.count(status=AlertStatus.INVESTIGATING) == 1
    assert repo.count(status=AlertStatus.OPEN) == 0

    # Delete
    assert repo.delete(alert.id) is True
    assert repo.get_by_id(alert.id) is None
    assert repo.delete(9999) is False


def test_mitre_repository_crud(db_session):
    """Test CRUD operations on MitreRepository."""
    repo = MitreRepository(db_session)

    technique = repo.create({
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services.",
    })
    assert technique.id is not None

    by_id = repo.get_by_id(technique.id)
    assert by_id is not None

    by_tech_id = repo.get_by_technique_id("T1046")
    assert by_tech_id is not None
    assert by_tech_id.technique_name == "Network Service Discovery"

    assert repo.get_by_technique_id("T9999") is None

    all_techs = repo.get_all(tactic="Discovery")
    assert len(all_techs) == 1
    assert repo.count(tactic="Discovery") == 1
    assert repo.count(tactic="Execution") == 0
