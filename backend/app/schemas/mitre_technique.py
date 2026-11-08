"""Pydantic schemas for MitreTechnique response validation."""

from pydantic import BaseModel, ConfigDict


class MitreTechniqueResponse(BaseModel):
    """Schema for returning a MITRE technique entry."""

    id: int
    technique_id: str
    technique_name: str
    tactic: str
    description: str | None

    model_config = ConfigDict(from_attributes=True)


class MitreTechniqueListResponse(BaseModel):
    """List of MITRE techniques."""

    items: list[MitreTechniqueResponse]
    total: int
