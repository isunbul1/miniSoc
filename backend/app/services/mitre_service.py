"""Service layer for MitreTechnique business logic.

Provides read operations for the MITRE ATT&CK technique catalog.
"""

from sqlalchemy.orm import Session

from app.repositories.mitre_repository import MitreRepository
from app.schemas.mitre_technique import (
    MitreTechniqueListResponse,
    MitreTechniqueResponse,
)


class MitreService:
    """Business logic for MITRE ATT&CK technique operations."""

    def __init__(self, db: Session) -> None:
        self.repo = MitreRepository(db)

    def get_techniques(
        self, tactic: str | None = None
    ) -> MitreTechniqueListResponse:
        """Return all MITRE techniques, optionally filtered by tactic."""
        techniques = self.repo.get_all(tactic=tactic)
        total = self.repo.count(tactic=tactic)
        return MitreTechniqueListResponse(
            items=[
                MitreTechniqueResponse.model_validate(t) for t in techniques
            ],
            total=total,
        )

    def get_technique_by_technique_id(
        self, technique_id: str
    ) -> MitreTechniqueResponse | None:
        """Return a single technique by its MITRE ID (e.g. T1059)."""
        technique = self.repo.get_by_technique_id(technique_id)
        if technique is None:
            return None
        return MitreTechniqueResponse.model_validate(technique)
