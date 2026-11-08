"""Tests for database initialization and model schema definitions."""

from sqlalchemy import inspect

from app.db.database import Base
from app.db.init_db import init_db
from app.models.mitre_technique import MitreTechnique
from app.models.security_alert import SecurityAlert
from app.models.security_log import SecurityLog


def test_models_registered_in_metadata():
    """Verify that all three models are registered in Base.metadata."""
    table_names = Base.metadata.tables.keys()
    assert "security_logs" in table_names
    assert "security_alerts" in table_names
    assert "mitre_techniques" in table_names


def test_security_log_columns(db_session):
    """Verify columns and types for SecurityLog table."""
    inspector = inspect(db_session.bind)
    columns = {col["name"]: col for col in inspector.get_columns("security_logs")}

    assert "id" in columns
    assert "timestamp" in columns
    assert "source_ip" in columns
    assert "destination_ip" in columns
    assert "destination_port" in columns
    assert "username" in columns
    assert "event_type" in columns
    assert "description" in columns
    assert "severity" in columns
    assert "command_line" in columns
    assert "raw_log" in columns


def test_security_alert_columns(db_session):
    """Verify columns and types for SecurityAlert table."""
    inspector = inspect(db_session.bind)
    columns = {col["name"]: col for col in inspector.get_columns("security_alerts")}

    assert "id" in columns
    assert "title" in columns
    assert "description" in columns
    assert "severity" in columns
    assert "status" in columns
    assert "source_ip" in columns
    assert "rule_id" in columns
    assert "incident_start" in columns
    assert "incident_key" in columns
    assert "detection_time" in columns
    assert "mitre_technique_id" in columns


def test_database_url_resolves_relative_to_backend_dir():
    """Verify DATABASE_URL resolves relative to backend directory regardless of working directory."""
    from pathlib import Path
    from app.core.config import BACKEND_DIR, Settings

    # Default settings instance
    s = Settings()
    expected_default = f"sqlite:///{(BACKEND_DIR / 'minisoc.db').resolve().as_posix()}"
    assert s.DATABASE_URL == expected_default

    # Explicit relative URL sqlite:///./custom.db must resolve relative to BACKEND_DIR
    custom_s = Settings(DATABASE_URL="sqlite:///./custom.db")
    expected_custom = f"sqlite:///{(BACKEND_DIR / 'custom.db').resolve().as_posix()}"
    assert custom_s.DATABASE_URL == expected_custom



def test_mitre_technique_columns(db_session):
    """Verify columns and types for MitreTechnique table."""
    inspector = inspect(db_session.bind)
    columns = {col["name"]: col for col in inspector.get_columns("mitre_techniques")}

    assert "id" in columns
    assert "technique_id" in columns
    assert "technique_name" in columns
    assert "tactic" in columns
    assert "description" in columns


def test_seed_idempotent_and_contains_t1059_001(db_session):
    """Verify that init_db seeds T1059.001 and running twice produces no duplicates."""
    engine = db_session.get_bind()
    session_factory = lambda: db_session

    init_db(target_engine=engine, session_factory=session_factory)
    count_1 = db_session.query(MitreTechnique).count()
    assert count_1 >= 6

    # Verify T1059.001 exists after seed
    technique = (
        db_session.query(MitreTechnique)
        .filter_by(technique_id="T1059.001")
        .first()
    )
    assert technique is not None
    assert technique.technique_name == "PowerShell"
    assert technique.tactic == "Execution"

    # Run seed function a second time - verify count is identical
    init_db(target_engine=engine, session_factory=session_factory)
    count_2 = db_session.query(MitreTechnique).count()
    assert count_1 == count_2


def test_global_exception_handler_sanitized_500(client):
    """Verify that an unhandled exception triggers the generic 500 handler without leaking stack trace."""
    from app.main import app

    @app.get("/api/v1/test-unhandled-error")
    def trigger_error():
        raise RuntimeError("Database connection password=supersecret leaked")

    from fastapi.testclient import TestClient
    c = TestClient(app, raise_server_exceptions=False)
    res = c.get("/api/v1/test-unhandled-error")
    assert res.status_code == 500
    assert res.json() == {"detail": "Internal server error"}
    assert "supersecret" not in res.text
    assert "Traceback" not in res.text
