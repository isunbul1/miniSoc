"""MitreTechnique ORM model.

Stores MITRE ATT&CK technique reference data for threat classification.
"""

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class MitreTechnique(Base):
    """A MITRE ATT&CK technique entry."""

    __tablename__ = "mitre_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    technique_id: Mapped[str] = mapped_column(
        String(20), unique=True, nullable=False, index=True
    )
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationship: one technique -> many alerts
    alerts: Mapped[list["SecurityAlert"]] = relationship(
        "SecurityAlert", back_populates="mitre_technique"
    )

    def __repr__(self) -> str:
        return f"<MitreTechnique(id={self.id}, technique_id={self.technique_id})>"
