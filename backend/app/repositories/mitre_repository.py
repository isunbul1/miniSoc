"""Repository for MitreTechnique database operations.

Encapsulates all direct database queries for MITRE ATT&CK techniques.
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.mitre_technique import MitreTechnique


class MitreRepository:
    """Data-access layer for MitreTechnique records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_all(self, tactic: str | None = None) -> list[MitreTechnique]:
        """Retrieve all MITRE techniques, optionally filtered by tactic."""
        query = self.db.query(MitreTechnique)

        if tactic:
            query = query.filter(MitreTechnique.tactic == tactic)

        return query.order_by(MitreTechnique.technique_id).all()

    def count(self, tactic: str | None = None) -> int:
        """Count techniques matching the given filter."""
        query = self.db.query(func.count(MitreTechnique.id))

        if tactic:
            query = query.filter(MitreTechnique.tactic == tactic)

        return query.scalar() or 0

    def get_by_id(self, technique_db_id: int) -> MitreTechnique | None:
        """Retrieve a single technique by its database primary key."""
        return (
            self.db.query(MitreTechnique)
            .filter(MitreTechnique.id == technique_db_id)
            .first()
        )

    def get_by_technique_id(self, technique_id: str) -> MitreTechnique | None:
        """Retrieve a single technique by its MITRE technique ID (e.g. T1059)."""
        return (
            self.db.query(MitreTechnique)
            .filter(MitreTechnique.technique_id == technique_id)
            .first()
        )

    def create(self, technique_data: dict) -> MitreTechnique:
        """Insert a new MITRE technique record."""
        technique = MitreTechnique(**technique_data)
        self.db.add(technique)
        self.db.commit()
        self.db.refresh(technique)
        return technique
