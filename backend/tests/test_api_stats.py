"""Tests for /api/v1/stats endpoints."""

from datetime import datetime, timedelta, timezone

from app.core.enums import AlertSeverity, AlertStatus, LogSeverity
from app.db.init_db import init_db
from app.models.mitre_technique import MitreTechnique
from app.models.security_alert import SecurityAlert
from app.models.security_log import SecurityLog

BASE_TIME = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_get_stats_summary_empty_db(client, db_session):
    """Test /api/v1/stats/summary on an empty database."""
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    res = client.get("/api/v1/stats/summary")
    assert res.status_code == 200
    data = res.json()

    assert data["total_logs"] == 0
    assert data["total_alerts"] == 0
    assert data["alerts_by_severity"] == {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    assert data["alerts_by_status"] == {
        "open": 0,
        "investigating": 0,
        "resolved": 0,
        "false_positive": 0,
    }
    assert data["alerts_by_mitre"] == []
    assert data["logs_by_event_type"] == {}
    assert len(data["log_counts_per_hour"]) == 24


def test_get_stats_summary_with_data(client, db_session):
    """Test /api/v1/stats/summary returns aggregated counts accurately."""
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    tech = db_session.query(MitreTechnique).filter(MitreTechnique.technique_id == "T1110").first()

    # Ingest logs
    db_session.add(
        SecurityLog(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
    )
    db_session.add(
        SecurityLog(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
    )
    db_session.add(
        SecurityLog(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            event_type="ssh_login",
            severity=LogSeverity.INFO,
        )
    )

    # Ingest alerts
    db_session.add(
        SecurityAlert(
            title="Brute Force Alert 1",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.OPEN,
            source_ip="10.0.0.1",
            mitre_technique_id=tech.id if tech else None,
        )
    )
    db_session.add(
        SecurityAlert(
            title="Critical Account Compromise",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.INVESTIGATING,
            source_ip="10.0.0.1",
            mitre_technique_id=tech.id if tech else None,
        )
    )
    db_session.commit()

    res = client.get("/api/v1/stats/summary")
    assert res.status_code == 200
    data = res.json()

    assert data["total_logs"] == 3
    assert data["total_alerts"] == 2
    assert data["alerts_by_severity"]["high"] == 1
    assert data["alerts_by_severity"]["critical"] == 1
    assert data["alerts_by_status"]["open"] == 1
    assert data["alerts_by_status"]["investigating"] == 1
    assert data["logs_by_event_type"]["auth_failure"] == 2
    assert data["logs_by_event_type"]["ssh_login"] == 1

    if tech:
        assert len(data["alerts_by_mitre"]) >= 1
        assert data["alerts_by_mitre"][0]["technique_id"] == "T1110"
        assert data["alerts_by_mitre"][0]["count"] == 2

    assert len(data["log_counts_per_hour"]) == 24
    # The current hour should have 3 logs
    total_hourly_logs = sum(item["count"] for item in data["log_counts_per_hour"])
    assert total_hourly_logs == 3
