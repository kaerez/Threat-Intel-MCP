"""MITRE CAPEC (Common Attack Pattern Enumeration and Classification) database models."""

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from cve_mcp.models.base import Base


class CAPECPattern(Base):
    """MITRE CAPEC attack patterns with semantic search.

    CAPEC provides a comprehensive dictionary of known attack patterns used
    by adversaries to exploit weaknesses in cyber-enabled capabilities.
    """

    __tablename__ = "capec_patterns"

    # Primary identification
    pattern_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CAPEC-66
    capec_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)  # 66
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    # Semantic search (1536 dimensions for text-embedding-3-small)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Full-text search
    description_vector: Mapped[str | None] = mapped_column(TSVECTOR)

    # Core fields
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # CAPEC-specific: Abstraction levels (Meta, Standard, Detailed)
    abstraction: Mapped[str | None] = mapped_column(String(50))  # Meta, Standard, Detailed

    # CAPEC-specific: Status
    status: Mapped[str | None] = mapped_column(String(50))  # Draft, Stable, Deprecated

    # Hierarchical relationships (stored as arrays of pattern_ids)
    parent_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # ["CAPEC-1", "CAPEC-2"]
    child_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    can_precede: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    can_follow: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    peer_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Cross-framework mappings
    related_attack_patterns: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # ATT&CK technique IDs
    related_weaknesses: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # CWE IDs

    # Attack characteristics
    attack_likelihood: Mapped[str | None] = mapped_column(String(20))  # High, Medium, Low
    typical_severity: Mapped[str | None] = mapped_column(String(20))  # High, Medium, Low

    # Attack prerequisites and requirements
    prerequisites: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # What must exist for attack
    skills_required: Mapped[dict | None] = mapped_column(
        JSONB
    )  # Attacker skill level needed (level -> description)
    resources_required: Mapped[str | None] = mapped_column(Text)  # Resources needed for attack

    # Attack execution
    execution_flow: Mapped[dict | None] = mapped_column(
        JSONB
    )  # Step-by-step attack flow (structured)
    consequences: Mapped[dict | None] = mapped_column(
        JSONB
    )  # Impact/consequences (structured)

    # Detection and mitigation (references to CAPECMitigation)
    mitigations: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # Mitigation IDs

    # Examples and references
    examples: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    references: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)

    # STIX extensions
    stix_extensions: Mapped[dict | None] = mapped_column(JSONB)

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    @property
    def badge_url(self) -> str:
        """Generate CAPEC badge URL."""
        return f"https://capec.mitre.org/data/definitions/{self.capec_id}.html"

    __table_args__ = (
        # Vector similarity index (IVFFlat with cosine distance)
        # ~550 patterns, use lists=100 similar to ATT&CK
        Index(
            "idx_capec_pattern_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 100},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # Full-text search index
        Index(
            "idx_capec_pattern_description_fts",
            description_vector,
            postgresql_using="gin",
        ),
        # Name trigram index for fuzzy search
        Index(
            "idx_capec_pattern_name_trgm",
            name,
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
        # Abstraction level index
        Index("idx_capec_pattern_abstraction", abstraction),
        # Attack likelihood and severity indexes
        Index("idx_capec_pattern_likelihood", attack_likelihood),
        Index("idx_capec_pattern_severity", typical_severity),
        # Hierarchical relationship indexes
        Index("idx_capec_pattern_parent_of", parent_of, postgresql_using="gin"),
        Index("idx_capec_pattern_child_of", child_of, postgresql_using="gin"),
        # Cross-framework mapping indexes
        Index(
            "idx_capec_pattern_attack_patterns",
            related_attack_patterns,
            postgresql_using="gin",
        ),
        Index(
            "idx_capec_pattern_weaknesses",
            related_weaknesses,
            postgresql_using="gin",
        ),
    )


class CAPECCategory(Base):
    """CAPEC attack pattern categories (grouping mechanism).

    Categories organize attack patterns into logical groups for easier
    navigation and understanding.
    """

    __tablename__ = "capec_categories"

    category_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CAPEC-CAT-100
    capec_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)  # 100
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    # Member patterns
    member_patterns: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # ["CAPEC-1", "CAPEC-2"]

    # Hierarchy
    parent_category: Mapped[str | None] = mapped_column(String(20))
    child_categories: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    __table_args__ = (
        Index(
            "idx_capec_category_members",
            member_patterns,
            postgresql_using="gin",
        ),
    )


class CAPECMitigation(Base):
    """CAPEC mitigations (courses of action) with semantic search.

    Mitigations describe security measures that can be taken to prevent
    or reduce the effectiveness of attack patterns.
    """

    __tablename__ = "capec_mitigations"

    mitigation_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # CAPEC-MIT-1
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    # Semantic search (1536 dimensions for text-embedding-3-small)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Core fields
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Effectiveness
    effectiveness: Mapped[str | None] = mapped_column(String(20))  # High, Medium, Low

    # Related patterns this mitigation addresses
    mitigates_patterns: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # ["CAPEC-1", "CAPEC-2"]

    # Implementation guidance
    implementation_phases: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # Design, Build, Operation

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # STIX extensions
    stix_extensions: Mapped[dict | None] = mapped_column(JSONB)

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    __table_args__ = (
        # Vector similarity index (IVFFlat with cosine distance)
        # ~300 mitigations, use lists=50
        Index(
            "idx_capec_mitigation_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 50},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # Related patterns index
        Index(
            "idx_capec_mitigation_patterns",
            mitigates_patterns,
            postgresql_using="gin",
        ),
        # Name trigram index for fuzzy search
        Index(
            "idx_capec_mitigation_name_trgm",
            name,
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
    )
