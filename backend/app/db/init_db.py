"""Database initialization and seeding.

Creates all tables defined by SQLAlchemy models and seeds
initial MITRE ATT&CK reference data idempotently per technique.
"""

from sqlalchemy.orm import Session

import app.models  # noqa: F401 - ensure models are registered
from app.db.database import Base, SessionLocal, engine
from app.models.mitre_technique import MitreTechnique

INITIAL_MITRE_TECHNIQUES = [
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts.",
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
    },
    {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Endpoint Denial of Service attacks to degrade system availability.",
    },
]


def init_db(target_engine=None, session_factory=None) -> None:
    """Create tables and seed initial data idempotently per technique."""
    active_engine = target_engine or engine
    active_session_factory = session_factory or SessionLocal

    Base.metadata.create_all(bind=active_engine)

    db: Session = active_session_factory()
    try:
        for item in INITIAL_MITRE_TECHNIQUES:
            existing = (
                db.query(MitreTechnique)
                .filter(MitreTechnique.technique_id == item["technique_id"])
                .first()
            )
            if not existing:
                technique = MitreTechnique(**item)
                db.add(technique)
        db.commit()
    finally:
        db.close()
