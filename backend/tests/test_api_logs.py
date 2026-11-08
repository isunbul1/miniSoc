"""Tests for /api/v1/logs endpoints."""


def test_create_and_get_log(client):
    """Test creating a log via POST and retrieving it via GET."""
    payload = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "username": "sec_analyst",
        "event_type": "ssh_login",
        "description": "Successful SSH login",
        "severity": "info",
        "raw_log": "Accepted publickey for sec_analyst from 192.168.1.100 port 52312",
    }

    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["source_ip"] == "192.168.1.100"
    assert data["id"] is not None
    log_id = data["id"]

    # Get by ID
    get_res = client.get(f"/api/v1/logs/{log_id}")
    assert get_res.status_code == 200
    assert get_res.json()["event_type"] == "ssh_login"

    # List logs
    list_res = client.get("/api/v1/logs")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert any(item["id"] == log_id for item in list_data["items"])


def test_get_nonexistent_log(client):
    """Test retrieving a log that does not exist returns 404."""
    response = client.get("/api/v1/logs/99999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Log not found"


def test_create_log_invalid_payload(client):
    """Test validation errors on missing required fields."""
    invalid_payload = {
        "event_type": "login",
    }
    response = client.post("/api/v1/logs", json=invalid_payload)
    assert response.status_code == 422


def test_create_log_invalid_ip(client):
    """Test invalid IP addresses return 422."""
    payload = {
        "source_ip": "999.999.999.999",
        "destination_ip": "10.0.0.1",
        "event_type": "firewall_drop",
    }
    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == 422


def test_create_log_invalid_severity(client):
    """Test invalid severity string returns 422."""
    payload = {
        "source_ip": "192.168.1.1",
        "destination_ip": "10.0.0.1",
        "event_type": "auth_failure",
        "severity": "super_critical",
    }
    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == 422


def test_list_logs_pagination_validation(client):
    """Test pagination bounds: limit=101 and skip=-1 return 422."""
    res_limit_over = client.get("/api/v1/logs?limit=101")
    assert res_limit_over.status_code == 422

    res_skip_negative = client.get("/api/v1/logs?skip=-1")
    assert res_skip_negative.status_code == 422


def test_filter_logs_by_severity_and_source_ip(client):
    """Test filtering logs by severity and source_ip."""
    client.post(
        "/api/v1/logs",
        json={
            "source_ip": "192.168.10.5",
            "destination_ip": "10.0.0.1",
            "event_type": "port_scan",
            "severity": "high",
        },
    )
    client.post(
        "/api/v1/logs",
        json={
            "source_ip": "192.168.10.6",
            "destination_ip": "10.0.0.1",
            "event_type": "port_scan",
            "severity": "low",
        },
    )

    # Filter by severity
    res_sev = client.get("/api/v1/logs?severity=high")
    assert res_sev.status_code == 200
    for item in res_sev.json()["items"]:
        assert item["severity"] == "high"

    # Filter by source_ip
    res_ip = client.get("/api/v1/logs?source_ip=192.168.10.5")
    assert res_ip.status_code == 200
    assert res_ip.json()["total"] >= 1
    for item in res_ip.json()["items"]:
        assert item["source_ip"] == "192.168.10.5"

    # Filter by both severity and source_ip
    res_both = client.get("/api/v1/logs?severity=high&source_ip=192.168.10.5")
    assert res_both.status_code == 200
    assert res_both.json()["total"] >= 1
    for item in res_both.json()["items"]:
        assert item["severity"] == "high"
        assert item["source_ip"] == "192.168.10.5"


def test_delete_log(client):
    """Test deleting a log."""
    res = client.post(
        "/api/v1/logs",
        json={
            "source_ip": "1.1.1.1",
            "destination_ip": "2.2.2.2",
            "event_type": "dns_query",
            "severity": "low",
        },
    )
    assert res.status_code == 201
    log_id = res.json()["id"]

    del_res = client.delete(f"/api/v1/logs/{log_id}")
    assert del_res.status_code == 204

    get_res = client.get(f"/api/v1/logs/{log_id}")
    assert get_res.status_code == 404

    del_again = client.delete(f"/api/v1/logs/{log_id}")
    assert del_again.status_code == 404


def test_log_response_timestamp_timezone_aware(client):
    """Test that log timestamp in response is timezone-aware ISO 8601 UTC ('Z' or '+00:00')."""
    res = client.post(
        "/api/v1/logs",
        json={
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.20",
            "event_type": "ssh_login",
            "severity": "info",
        },
    )
    assert res.status_code == 201
    timestamp = res.json()["timestamp"]
    assert timestamp.endswith("Z") or "+00:00" in timestamp

    get_res = client.get(f"/api/v1/logs/{res.json()['id']}")
    assert get_res.status_code == 200
    assert get_res.json()["timestamp"].endswith("Z") or "+00:00" in get_res.json()["timestamp"]

