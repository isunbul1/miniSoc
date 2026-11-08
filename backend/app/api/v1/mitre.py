"""API routes for MITRE ATT&CK techniques."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.mitre_technique import (
    MitreTechniqueListResponse,
    MitreTechniqueResponse,
)
from app.services.mitre_service import MitreService

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("", response_model=MitreTechniqueListResponse)
def list_techniques(
    tactic: str | None = Query(None, description="Filter by tactic"),
    db: Session = Depends(get_db),
):
    """Return all MITRE ATT&CK techniques, optionally filtered by tactic."""
    service = MitreService(db)
    return service.get_techniques(tactic=tactic)


@router.get("/{technique_id}", response_model=MitreTechniqueResponse)
def get_technique(technique_id: str, db: Session = Depends(get_db)):
    """Return a single MITRE technique by its technique ID (e.g. T1059)."""
    service = MitreService(db)
    technique = service.get_technique_by_technique_id(technique_id)
    if technique is None:
        raise HTTPException(status_code=404, detail="MITRE technique not found")
    return technique
