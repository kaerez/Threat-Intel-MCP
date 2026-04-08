"""MITRE ATT&CK database models with semantic search."""

from datetime import datetime
from typing import TYPE_CHECKING

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base

if TYPE_CHECKING:
    from cve_mcp.models.attack import (
        AttackGroup,
        AttackMitigation,
        AttackSoftware,
        AttackTactic,
    )


class AttackTechnique(Base):
    """MITRE ATT&CK techniques and sub-techniques with semantic search."""

    __tablename__ = "attack_techniques"

    # Primary identification
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # T1566.001
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    # Hierarchy
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_technique_id: Mapped[str | None] = mapped_column(
        String(20), ForeignKey("attack_techniques.technique_id")
    )

    # Core details
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    description_vector: Mapped[str | None] = mapped_column(TSVECTOR)

    # Semantic search embedding (1536 dimensions for text-embedding-3-small)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))

    # Classification
    tactics: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # ["initial-access", "execution"]
    platforms: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # ["windows", "linux"]
    data_sources: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Detection & mitigation
    detection: Mapped[str | None] = mapped_column(Text)
    permissions_required: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    effective_permissions: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    # STIX extensions (full technique object as JSONB for flexibility)
    stix_extensions: Mapped[dict | None] = mapped_column(JSONB)

    # Badge URL (computed)
    @property
    def badge_url(self) -> str:
        """Return badge link URL."""
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    embedding_model: Mapped[str | None] = mapped_column(String(50))  # "text-embedding-3-small"
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Relationships
    parent: Mapped["AttackTechnique | None"] = relationship(
        "AttackTechnique", remote_side=[technique_id], back_populates="subtechniques"
    )
    subtechniques: Mapped[list["AttackTechnique"]] = relationship(
        "AttackTechnique", back_populates="parent"
    )

    __table_args__ = (
        Index("idx_attack_tech_name", name, postgresql_using="gin", postgresql_ops={"name": "gin_trgm_ops"}),
        Index("idx_attack_tech_desc_fts", description_vector, postgresql_using="gin"),
        Index("idx_attack_tech_tactics", tactics, postgresql_using="gin"),
        Index("idx_attack_tech_platforms", platforms, postgresql_using="gin"),
        Index("idx_attack_tech_parent", parent_technique_id),
        Index("idx_attack_tech_active", technique_id, postgresql_where=((~deprecated) & (~revoked))),
        # Vector similarity index (IVFFlat for fast approximate nearest neighbor)
        Index(
            "idx_attack_tech_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 100},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


class AttackGroup(Base):
    """MITRE ATT&CK threat actor groups with semantic search."""

    __tablename__ = "attack_groups"

    group_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # G0001
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    aliases: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    description_vector: Mapped[str | None] = mapped_column(TSVECTOR)

    # Semantic search embedding
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))

    # Targeting
    associated_groups: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    techniques_used: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # [T1566.001, T1059.001]
    software_used: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # [S0001, S0002]

    # Attribution indicators (for incident response)
    attribution_confidence: Mapped[str | None] = mapped_column(String(20))  # high, medium, low

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    stix_extensions: Mapped[dict | None] = mapped_column(JSONB)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    __table_args__ = (
        Index("idx_attack_group_name", name, postgresql_using="gin", postgresql_ops={"name": "gin_trgm_ops"}),
        Index("idx_attack_group_aliases", aliases, postgresql_using="gin"),
        Index("idx_attack_group_techniques", techniques_used, postgresql_using="gin"),
        Index(
            "idx_attack_group_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 50},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


class AttackTactic(Base):
    """MITRE ATT&CK tactics (kill chain phases)."""

    __tablename__ = "attack_tactics"

    tactic_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # TA0001
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    shortname: Mapped[str] = mapped_column(String(50), nullable=False)  # initial-access
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())


class AttackSoftware(Base):
    """MITRE ATT&CK software (tools and malware)."""

    __tablename__ = "attack_software"

    software_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # S0001
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    aliases: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    software_type: Mapped[str] = mapped_column(String(20), nullable=False)  # tool, malware
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Capabilities
    platforms: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    techniques_used: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    stix_extensions: Mapped[dict | None] = mapped_column(JSONB)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    __table_args__ = (
        Index("idx_attack_software_name", name),
        Index("idx_attack_software_type", software_type),
        Index("idx_attack_software_techniques", techniques_used, postgresql_using="gin"),
    )


class AttackMitigation(Base):
    """MITRE ATT&CK mitigations (defensive courses of action)."""

    __tablename__ = "attack_mitigations"

    mitigation_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # M0001
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships to techniques
    mitigates_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Metadata
    version: Mapped[str | None] = mapped_column(String(20))
    created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    __table_args__ = (Index("idx_attack_mitigation_techniques", mitigates_techniques, postgresql_using="gin"),)
