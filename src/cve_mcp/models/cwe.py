"""MITRE CWE (Common Weakness Enumeration) database models."""

from datetime import datetime
from typing import TYPE_CHECKING

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base

if TYPE_CHECKING:
    pass


class CWEView(Base):
    """CWE view definitions (organizational perspectives).

    Views like CWE-1003 (Simplified Mapping), CWE-699 (Software Development),
    CWE-1000 (Research Concepts) provide different organizational structures.
    ~10 records.
    """

    __tablename__ = "cwe_views"

    view_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CWE-1003
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    view_type: Mapped[str | None] = mapped_column(String(50))  # Graph, Explicit, Implicit
    status: Mapped[str | None] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text)

    # Timestamps
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationships
    categories: Mapped[list["CWECategory"]] = relationship(
        "CWECategory", back_populates="view"
    )


class CWECategory(Base):
    """CWE category definitions within views.

    Categories group related weaknesses (e.g., CWE-310 Cryptographic Issues).
    ~300 records.
    """

    __tablename__ = "cwe_categories"

    category_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CWE-310
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    view_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cwe_views.view_id", ondelete="CASCADE"), nullable=False
    )

    # Timestamps
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationships
    view: Mapped["CWEView"] = relationship("CWEView", back_populates="categories")

    __table_args__ = (Index("idx_cwe_category_view", view_id),)


class CWEWeakness(Base):
    """MITRE CWE weakness definitions with semantic search.

    CWE provides a comprehensive catalog of software and hardware
    weakness types with actionable intelligence for developers.
    ~900 records.
    """

    __tablename__ = "cwe_weaknesses"

    # Primary identification
    cwe_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CWE-79
    weakness_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)  # 79

    # Semantic search (1536 dimensions for text-embedding-3-small)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Core fields
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)  # Some CWEs have no description
    extended_description: Mapped[str | None] = mapped_column(Text)

    # Abstraction hierarchy: Pillar > Class > Base > Variant > Compound
    abstraction: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str | None] = mapped_column(
        String(20)
    )  # Draft, Incomplete, Stable, Deprecated

    # Actionable intelligence (JSONB for structured data)
    common_consequences: Mapped[dict | None] = mapped_column(
        JSONB
    )  # [{scope, impact, likelihood}]
    potential_mitigations: Mapped[dict | None] = mapped_column(
        JSONB
    )  # [{phase, strategy, description}]
    detection_methods: Mapped[dict | None] = mapped_column(
        JSONB
    )  # [{method, effectiveness, description}]
    likelihood_of_exploit: Mapped[str | None] = mapped_column(
        String(20)
    )  # High, Medium, Low

    # Hierarchical relationships
    parent_of: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # ["CWE-20", "CWE-74"]
    child_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    peer_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    can_precede: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    can_follow: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Cross-framework mappings
    related_attack_patterns: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text)
    )  # CAPEC IDs

    # Timestamps
    created: Mapped[datetime | None] = mapped_column(DateTime)
    modified: Mapped[datetime | None] = mapped_column(DateTime)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Metadata
    cwe_version: Mapped[str | None] = mapped_column(
        String(20)
    )  # Dataset version e.g., "4.14"
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def badge_url(self) -> str:
        """URL to official CWE page."""
        return f"https://cwe.mitre.org/data/definitions/{self.weakness_id}.html"

    __table_args__ = (
        # Vector similarity search (IVFFlat for ~900 weaknesses)
        Index(
            "idx_cwe_weakness_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 100},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # Hierarchical relationship queries (GIN indexes)
        Index("idx_cwe_parent_of", parent_of, postgresql_using="gin"),
        Index("idx_cwe_child_of", child_of, postgresql_using="gin"),
        Index("idx_cwe_peer_of", peer_of, postgresql_using="gin"),
        # Cross-framework queries
        Index("idx_cwe_related_capec", related_attack_patterns, postgresql_using="gin"),
        # Fast integer lookups for CVE joins (B-tree)
        Index("idx_cwe_weakness_id", weakness_id),
        # Abstraction filtering (B-tree)
        Index("idx_cwe_abstraction", abstraction),
    )


class CWEWeaknessCategory(Base):
    """Many-to-many join table: weakness <-> category with view tracking.

    Same weakness can appear in different categories across different views.
    """

    __tablename__ = "cwe_weakness_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    weakness_id: Mapped[str] = mapped_column(
        String(20),
        ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
        nullable=False,
    )
    category_id: Mapped[str] = mapped_column(
        String(20),
        ForeignKey("cwe_categories.category_id", ondelete="CASCADE"),
        nullable=False,
    )
    view_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cwe_views.view_id", ondelete="CASCADE"), nullable=False
    )

    __table_args__ = (
        Index("idx_cwe_wc_weakness", weakness_id),
        Index("idx_cwe_wc_category", category_id),
        Index("idx_cwe_wc_view", view_id),
        Index("idx_cwe_wc_unique", weakness_id, category_id, view_id, unique=True),
    )


class CWEExternalMapping(Base):
    """External standard mappings (OWASP Top 10, SANS Top 25, etc.)."""

    __tablename__ = "cwe_external_mappings"

    mapping_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    weakness_id: Mapped[str] = mapped_column(
        String(20),
        ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
        nullable=False,
    )
    external_source: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # "OWASP Top Ten 2021"
    external_id: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # "A03:2021"
    mapping_type: Mapped[str | None] = mapped_column(String(50))  # Primary, Secondary
    rationale: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("idx_cwe_ext_weakness", weakness_id),
        # Composite index for external_source + external_id lookups
        Index("idx_cwe_ext_source_id", external_source, external_id),
    )
