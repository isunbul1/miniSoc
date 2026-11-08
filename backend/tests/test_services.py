"""Unit tests for the Service layer."""

from app.core.enums import AlertSeverity, AlertStatus, LogSeverity
from app.repositories.mitre_repository import MitreRepository
from app.schemas.security_alert import SecurityAlertCreate, SecurityAlertUpdate
from app.schemas.security_log import SecurityLogCreate
from app.services.alert_service import AlertService
from app.services.log_service import LogService
from app.services.mitre_service import MitreService


def test_log_service(db_session):
    """Test LogService methods including pagination and filters."""
    service = LogService(db_session)

    # Create logs
    log1 = service.create_log(
        SecurityLogCreate(
            source_ip="192.168.1.10",
            destination_ip="192.168.1.1",
            username="alice",
            event_type="firewall_drop",
            severity=LogSeverity.MEDIUM,
        )
    )
    log2 = service.create_log(
        SecurityLogCreate(
            source_ip="192.168.1.20",
            destination_ip="192.168.1.1",
            username="bob",
            event_type="auth_success",
            severity=LogSeverity.INFO,
        )
    )

    # Get by ID
    fetched = service.get_log_by_id(log1.id)
    assert fetched is not None
    assert fetched.username == "alice"
    assert service.get_log_by_id(99999) is None

    # Get with pagination
    res_page = service.get_logs(skip=0, limit=1)
    assert len(res_page.items) == 1
    assert res_page.total == 2
    assert res_page.skip == 0
    assert res_page.limit == 1

    # Filter by severity
    filtered = service.get_logs(severity=LogSeverity.MEDIUM)
    assert filtered.total == 1
    assert filtered.items[0].id == log1.id

    # Delete
    assert service.delete_log(log1.id) is True
    assert service.get_log_by_id(log1.id) is None


def test_alert_service(db_session):
    """Test AlertService methods including partial updates."""
    service = AlertService(db_session)

    alert = service.create_alert(
        SecurityAlertCreate(
            title="DDoS Attack Detected",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.OPEN,
            source_ip="203.0.113.5",
        )
    )

    # Fetch
    fetched = service.get_alert_by_id(alert.id)
    assert fetched is not None
    assert fetched.title == "DDoS Attack Detected"

    # Update
    updated = service.update_alert(
        alert.id,
        SecurityAlertUpdate(status=AlertStatus.INVESTIGATING),
    )
    assert updated is not None
    assert updated.status == AlertStatus.INVESTIGATING

    # Update with empty data returns current
    same = service.update_alert(alert.id, SecurityAlertUpdate())
    assert same is not None
    assert same.status == AlertStatus.INVESTIGATING

    # Delete
    assert service.delete_alert(alert.id) is True
    assert service.delete_alert(9999) is False


def test_mitre_service(db_session):
    """Test MitreService methods."""
    # Seed technique via repository
    mitre_repo = MitreRepository(db_session)
    mitre_repo.create({
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Use of stolen credentials.",
    })

    service = MitreService(db_session)
    fetched = service.get_technique_by_technique_id("T1078")
    assert fetched is not None
    assert fetched.technique_name == "Valid Accounts"

    all_techs = service.get_techniques(tactic="Defense Evasion")
    assert all_techs.total == 1
    assert all_techs.items[0].technique_id == "T1078"
