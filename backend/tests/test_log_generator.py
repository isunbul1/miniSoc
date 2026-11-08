"""Unit and integration tests for the synthetic log generator."""

from app.core.config import Settings, settings
from app.services.log_generator import generate_synthetic_logs


def test_generator_reproducibility_with_seed():
    """Verify that generating logs with the same seed produces identical output."""
    logs_a = generate_synthetic_logs(seed=999)
    logs_b = generate_synthetic_logs(seed=999)

    assert len(logs_a) == len(logs_b)
    for log_a, log_b in zip(logs_a, logs_b):
        assert log_a["timestamp"] == log_b["timestamp"]
        assert log_a["source_ip"] == log_b["source_ip"]
        assert log_a["destination_port"] == log_b["destination_port"]
        assert log_a["event_type"] == log_b["event_type"]
        assert log_a["command_line"] == log_b["command_line"]


def test_default_environment_is_production_in_config():
    """Verify that the secure default for ENVIRONMENT in Settings class is 'production'."""
    raw_settings = Settings(_env_file=None)
    assert raw_settings.ENVIRONMENT == "production"


def test_generator_endpoint_in_development(client):
    """Test POST /api/v1/logs/generate succeeds with 201 in development environment."""
    original_env = settings.ENVIRONMENT
    settings.ENVIRONMENT = "development"
    try:
        response = client.post("/api/v1/logs/generate", json={"seed": 42})
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "success"
        assert data["generated_count"] > 0
        assert data["seed"] == 42
    finally:
        settings.ENVIRONMENT = original_env


def test_generator_endpoint_returns_404_when_environment_not_development(client):
    """Test POST /api/v1/logs/generate returns 404 when ENVIRONMENT is default/production."""
    original_env = settings.ENVIRONMENT
    settings.ENVIRONMENT = "production"
    try:
        response = client.post("/api/v1/logs/generate", json={"seed": 42})
        assert response.status_code == 404
        assert response.json()["detail"] == "Not found"
    finally:
        settings.ENVIRONMENT = original_env
