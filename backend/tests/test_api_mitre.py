"""Tests for /api/v1/mitre endpoints."""

from app.models.mitre_technique import MitreTechnique


def test_list_mitre_techniques(client, db_session):
    """Test listing MITRE techniques."""
    # Seed one technique if empty
    if not db_session.query(MitreTechnique).filter_by(technique_id="T1110").first():
        db_session.add(
            MitreTechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                description="Brute force test",
            )
        )
        db_session.commit()

    response = client.get("/api/v1/mitre")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1


def test_get_mitre_technique_by_id(client, db_session):
    """Test retrieving a technique by its technique ID (e.g. T1059.001)."""
    if not db_session.query(MitreTechnique).filter_by(technique_id="T1059.001").first():
        db_session.add(
            MitreTechnique(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                description="PowerShell abuse",
            )
        )
        db_session.commit()

    response = client.get("/api/v1/mitre/T1059.001")
    assert response.status_code == 200
    assert response.json()["technique_name"] == "PowerShell"
    assert response.json()["tactic"] == "Execution"


def test_get_nonexistent_mitre_technique(client):
    """Test getting a non-existent technique returns 404."""
    response = client.get("/api/v1/mitre/T9999.999")
    assert response.status_code == 404
    assert response.json()["detail"] == "MITRE technique not found"
