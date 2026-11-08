"""Tests for /api/v1/alerts endpoints."""


def test_create_and_get_alert(client):
    """Test creating an alert and fetching it."""
    payload = {
        "title": "Brute Force Detected",
        "description": "50 failed login attempts within 1 minute",
        "severity": "high",
        "status": "open",
        "source_ip": "203.0.113.195",
    }
    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 201
    alert_id = response.json()["id"]
    assert response.json()["severity"] == "high"

    # Get by ID
    get_res = client.get(f"/api/v1/alerts/{alert_id}")
    assert get_res.status_code == 200
    assert get_res.json()["title"] == "Brute Force Detected"


def test_create_alert_invalid_severity(client):
    """Test creating an alert with invalid severity returns 422."""
    payload = {
        "title": "Suspicious Port Scan",
        "severity": "info",  # Alert severity deliberately excludes 'info'
    }
    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 422


def test_create_alert_invalid_status(client):
    """Test creating an alert with invalid status returns 422."""
    payload = {
        "title": "Suspicious Port Scan",
        "severity": "low",
        "status": "unknown_status",
    }
    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 422


def test_create_alert_nonexistent_mitre_id(client):
    """Test creating an alert with non-existent mitre_technique_id returns 422."""
    payload = {
        "title": "Unknown Threat Pattern",
        "severity": "medium",
        "status": "open",
        "mitre_technique_id": 99999,
    }
    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 422
    assert "MITRE technique with id 99999 does not exist" in response.json()["detail"]


def test_patch_alert_forbidden_field(client):
    """Test updating an alert with forbidden extra fields returns 422."""
    # Create valid alert
    res = client.post(
        "/api/v1/alerts",
        json={"title": "Data Exfiltration", "severity": "high", "status": "open"},
    )
    alert_id = res.json()["id"]

    # PATCH with forbidden 'id' field
    patch_id = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"id": 1234, "status": "resolved"},
    )
    assert patch_id.status_code == 422

    # PATCH with forbidden 'title' field
    patch_title = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"title": "New Title", "status": "resolved"},
    )
    assert patch_title.status_code == 422


def test_update_alert_valid(client):
    """Test updating allowed fields (status, severity, description)."""
    res = client.post(
        "/api/v1/alerts",
        json={"title": "Ransomware Activity", "severity": "critical", "status": "open"},
    )
    alert_id = res.json()["id"]

    # Valid PATCH
    patch_res = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={
            "status": "investigating",
            "severity": "high",
            "description": "Analyst assigned",
        },
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "investigating"
    assert patch_res.json()["severity"] == "high"
    assert patch_res.json()["description"] == "Analyst assigned"


def test_update_nonexistent_alert(client):
    """Test updating an alert that does not exist returns 404."""
    response = client.patch(
        "/api/v1/alerts/99999",
        json={"status": "resolved"},
    )
    assert response.status_code == 404


def test_list_alerts_pagination_validation(client):
    """Test pagination bounds: limit=101 and skip=-1 return 422."""
    res_limit = client.get("/api/v1/alerts?limit=101")
    assert res_limit.status_code == 422

    res_skip = client.get("/api/v1/alerts?skip=-1")
    assert res_skip.status_code == 422


def test_delete_alert(client):
    """Test deleting an alert."""
    res = client.post(
        "/api/v1/alerts",
        json={"title": "Test Alert", "severity": "low", "status": "open"},
    )
    alert_id = res.json()["id"]

    del_res = client.delete(f"/api/v1/alerts/{alert_id}")
    assert del_res.status_code == 204

    get_res = client.get(f"/api/v1/alerts/{alert_id}")
    assert get_res.status_code == 404


def test_alert_response_detection_time_timezone_aware(client):
    """Test that alert detection_time in response is timezone-aware ISO 8601 UTC ('Z' or '+00:00')."""
    res = client.post(
        "/api/v1/alerts",
        json={
            "title": "Timezone Verification Alert",
            "severity": "medium",
            "status": "open",
        },
    )
    assert res.status_code == 201
    detection_time = res.json()["detection_time"]
    assert detection_time.endswith("Z") or "+00:00" in detection_time

    get_res = client.get(f"/api/v1/alerts/{res.json()['id']}")
    assert get_res.status_code == 200
    assert get_res.json()["detection_time"].endswith("Z") or "+00:00" in get_res.json()["detection_time"]

