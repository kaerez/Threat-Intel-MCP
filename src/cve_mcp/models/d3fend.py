"""MITRE D3FEND (Detection, Denial, and Disruption Framework) database models.

D3FEND provides a comprehensive catalog of defensive techniques that map
to offensive ATT&CK techniques, enabling defense-to-offense correlation.
"""

import enum
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base


class D3FENDRelationshipType(enum.Enum):
    """Relationship types between D3FEND techniques and ATT&CK techniques."""

    COUNTERS = "counters"
    ENABLES = "enables"
    RELATED_TO = "related-to"
    PRODUCES = "produces"
    USES = "uses"


class D3FENDArtifactRelationshipType(enum.Enum):
    """Relationship types between D3FEND techniques and artifacts."""

    PRODUCES = "produces"
    USES = "uses"
    ANALYZES = "analyzes"


class D3FENDTactic(Base):
    """D3FEND defensive tactics (kill chain phases).

    D3FEND defines 7 tactics: Model, Harden, Detect, Isolate, Deceive, Evict, Restore.
    ~7 records.
    """

    __tablename__ = "d3fend_tactics"

    tactic_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # D3-MODEL
    name: Mapped[str] = mapped_column(String(200), nullable=False)  # Model
    description: Mapped[str | None] = mapped_column(Text)
    display_order: Mapped[int] = mapped_column(Integer, nullable=False)  # For matrix rendering

    # Timestamps
    created: Mapped[datetime | None] = mapped_column(DateTime)
    modified: Mapped[datetime | None] = mapped_column(DateTime)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationships
    techniques: Mapped[list["D3FENDTechnique"]] = relationship(
        "D3FENDTechnique", back_populates="tactic"
    )


class D3FENDTechnique(Base):
    """D3FEND defensive techniques with semantic search.

    D3FEND provides ~200 defensive techniques that can counter ATT&CK techniques.
    """

    __tablename__ = "d3fend_techniques"

    # Primary identification
    technique_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # D3-AL

    # Semantic search (1536 dimensions for text-embedding-3-small)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Core fields
    name: Mapped[str] = mapped_column(String(300), nullable=False)  # Application Hardening
    description: Mapped[str] = mapped_column(Text, nullable=False)  # Full definition

    # Tactic relationship
    tactic_id: Mapped[str | None] = mapped_column(
        String(50),
        ForeignKey("d3fend_tactics.tactic_id", ondelete="SET NULL"),
    )

    # Hierarchy (self-referential for sub-techniques)
    parent_id: Mapped[str | None] = mapped_column(
        String(50),
        ForeignKey("d3fend_techniques.technique_id", ondelete="SET NULL"),
    )

    # Extended information from ontology
    synonyms: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # Alternative names
    references: Mapped[dict | None] = mapped_column(JSONB)  # [{title, url, authors}]
    kb_article_url: Mapped[str | None] = mapped_column(String(500))

    # Timestamps
    created: Mapped[datetime | None] = mapped_column(DateTime)
    modified: Mapped[datetime | None] = mapped_column(DateTime)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Metadata
    d3fend_version: Mapped[str | None] = mapped_column(String(50))  # Dataset version
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    tactic: Mapped["D3FENDTactic | None"] = relationship(
        "D3FENDTactic", back_populates="techniques"
    )
    parent: Mapped["D3FENDTechnique | None"] = relationship(
        "D3FENDTechnique",
        remote_side=[technique_id],
        back_populates="children",
        foreign_keys=[parent_id],
    )
    children: Mapped[list["D3FENDTechnique"]] = relationship(
        "D3FENDTechnique",
        back_populates="parent",
        foreign_keys=[parent_id],
    )
    attack_mappings: Mapped[list["D3FENDTechniqueAttackMapping"]] = relationship(
        "D3FENDTechniqueAttackMapping", back_populates="d3fend_technique"
    )
    artifact_relationships: Mapped[list["D3FENDTechniqueArtifact"]] = relationship(
        "D3FENDTechniqueArtifact", back_populates="technique"
    )

    @property
    def badge_url(self) -> str:
        """Generate D3FEND badge URL."""
        return f"https://d3fend.mitre.org/technique/{self.technique_id}/"

    __table_args__ = (
        # HNSW index for small dataset (~200 techniques) - no training required
        Index(
            "idx_d3fend_embedding",
            embedding,
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # B-tree indexes for fast lookups
        Index("idx_d3fend_tactic", tactic_id),
        Index("idx_d3fend_parent", parent_id),
        # GIN trigram index for fuzzy name search
        Index(
            "idx_d3fend_name_trgm",
            name,
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
    )


class D3FENDArtifact(Base):
    """D3FEND digital artifacts (what techniques produce or analyze).

    Artifacts represent digital entities like files, network traffic,
    processes, etc. that defensive techniques interact with.
    ~100 records.
    """

    __tablename__ = "d3fend_artifacts"

    artifact_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # d3f:File
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    artifact_type: Mapped[str | None] = mapped_column(
        String(50)
    )  # DigitalArtifact, NetworkTraffic, etc.

    # Relationships
    technique_relationships: Mapped[list["D3FENDTechniqueArtifact"]] = relationship(
        "D3FENDTechniqueArtifact", back_populates="artifact"
    )


class D3FENDTechniqueAttackMapping(Base):
    """Mapping between D3FEND techniques and ATT&CK techniques.

    This is the core correlation table enabling defense-to-offense mapping.
    """

    __tablename__ = "d3fend_technique_attack_mappings"

    mapping_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    d3fend_technique_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"),
        nullable=False,
    )

    # FK to the existing attack_techniques table
    attack_technique_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"),
        nullable=False,
    )

    relationship_type: Mapped[D3FENDRelationshipType] = mapped_column(
        Enum(D3FENDRelationshipType, name="d3fend_relationship_type"),
        nullable=False,
    )

    # Relationships
    d3fend_technique: Mapped["D3FENDTechnique"] = relationship(
        "D3FENDTechnique", back_populates="attack_mappings"
    )

    __table_args__ = (
        # Unique constraint: same d3fend technique + attack technique + relationship
        UniqueConstraint(
            "d3fend_technique_id",
            "attack_technique_id",
            "relationship_type",
            name="uq_d3fend_attack_mapping",
        ),
        # B-tree index for reverse lookups (find defenses for an attack technique)
        Index("idx_d3fend_attack_mapping", attack_technique_id),
    )


class D3FENDTechniqueArtifact(Base):
    """Join table between D3FEND techniques and artifacts.

    Tracks what artifacts a technique produces, uses, or analyzes.
    """

    __tablename__ = "d3fend_technique_artifacts"

    # Composite primary key
    technique_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"),
        primary_key=True,
    )
    artifact_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("d3fend_artifacts.artifact_id", ondelete="CASCADE"),
        primary_key=True,
    )
    relationship_type: Mapped[D3FENDArtifactRelationshipType] = mapped_column(
        Enum(D3FENDArtifactRelationshipType, name="d3fend_artifact_relationship_type"),
        primary_key=True,
    )

    # Relationships
    technique: Mapped["D3FENDTechnique"] = relationship(
        "D3FENDTechnique", back_populates="artifact_relationships"
    )
    artifact: Mapped["D3FENDArtifact"] = relationship(
        "D3FENDArtifact", back_populates="technique_relationships"
    )
