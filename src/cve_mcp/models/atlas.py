"""ATLAS (AI/ML threat framework) database models."""

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from cve_mcp.models.base import Base


class ATLASTechnique(Base):
    """MITRE ATLAS AI/ML attack techniques with semantic search."""

    __tablename__ = "atlas_techniques"

    # Primary identifier
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # AML.T0001
    # Note: stix_id is nullable because ATLAS moved from STIX to YAML format in late 2024
    stix_id: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)

    # Semantic search (1536 dimensions for text-embedding-3-small)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Full-text search
    description_vector: Mapped[str | None] = mapped_column(TSVECTOR)

    # Core fields
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # ATLAS-specific: ML lifecycle stages
    tactics: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # reconnaissance, ml-attack, impact

    # Target systems
    ml_lifecycle_stage: Mapped[str | None] = mapped_column(
        String(100)
    )  # data-collection, training, deployment
    ai_system_type: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # computer-vision, nlp, etc.

    # Detection and mitigation
    detection: Mapped[str | None] = mapped_column(Text)
    mitigation: Mapped[str | None] = mapped_column(Text)

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    # STIX extensions
    stix_extensions: Mapped[dict | None] = mapped_column(JSONB)

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    @property
    def badge_url(self) -> str:
        """Generate ATLAS badge URL."""
        # ATLAS uses different URL format: https://atlas.mitre.org/techniques/AML.T0001
        return f"https://atlas.mitre.org/techniques/{self.technique_id}"

    __table_args__ = (
        # Vector similarity index (IVFFlat with cosine distance)
        Index(
            "idx_atlas_tech_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 50},  # Fewer techniques than ATT&CK, use lists=50
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # Full-text search index
        Index(
            "idx_atlas_tech_description_fts",
            description_vector,
            postgresql_using="gin",
        ),
        # Tactic array index
        Index("idx_atlas_tech_tactics", tactics, postgresql_using="gin"),
        # Lifecycle stage index
        Index("idx_atlas_tech_lifecycle", ml_lifecycle_stage),
        # AI system type index
        Index("idx_atlas_tech_ai_type", ai_system_type, postgresql_using="gin"),
        # Name trigram index for fuzzy search
        Index(
            "idx_atlas_tech_name_trgm",
            name,
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
    )


class ATLASTactic(Base):
    """MITRE ATLAS tactics (ML kill chain phases)."""

    __tablename__ = "atlas_tactics"

    tactic_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # AML.TA0001
    # Note: stix_id is nullable because ATLAS moved from STIX to YAML format in late 2024
    stix_id: Mapped[str | None] = mapped_column(String(100), nullable=True, unique=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    shortname: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())


class ATLASCaseStudy(Base):
    """MITRE ATLAS real-world case studies."""

    __tablename__ = "atlas_case_studies"

    case_study_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # AML.CS0001
    # Note: stix_id is nullable because ATLAS moved from STIX to YAML format in late 2024
    stix_id: Mapped[str | None] = mapped_column(String(100), nullable=True, unique=True)

    # Semantic search
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Core fields
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    incident_date: Mapped[datetime | None] = mapped_column(DateTime)

    # Related techniques
    techniques_used: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # [AML.T0001, AML.T0002]

    # Incident details
    target_system: Mapped[str | None] = mapped_column(String(200))
    impact: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    # Note: created/modified are nullable because some case studies don't have dates in YAML
    created: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # STIX extensions
    stix_extensions: Mapped[dict | None] = mapped_column(JSONB)

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    __table_args__ = (
        Index(
            "idx_atlas_case_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 20},  # Small dataset
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        Index("idx_atlas_case_techniques", techniques_used, postgresql_using="gin"),
        Index("idx_atlas_case_date", incident_date),
    )
