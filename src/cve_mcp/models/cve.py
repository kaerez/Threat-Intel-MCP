"""CVE-related database models."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base

if TYPE_CHECKING:
    from cve_mcp.models.exploit import ExploitReference
    from cve_mcp.models.intelligence import CISAKEV, EPSSScore


class CVE(Base):
    """Main CVE records from NVD API 2.0."""

    __tablename__ = "cves"

    # Primary identification
    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)

    # Temporal tracking
    published_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_modified_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Descriptive data
    description: Mapped[str] = mapped_column(Text, nullable=False)
    description_vector: Mapped[str | None] = mapped_column(TSVECTOR)

    # CVSS v2 scoring (legacy)
    cvss_v2_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_v2_vector: Mapped[str | None] = mapped_column(String(50))
    cvss_v2_severity: Mapped[str | None] = mapped_column(String(10))

    # CVSS v3.x scoring (primary)
    cvss_v3_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(100))
    cvss_v3_severity: Mapped[str | None] = mapped_column(String(10))
    cvss_v3_base_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_v3_exploitability_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_v3_impact_score: Mapped[float | None] = mapped_column(Numeric(3, 1))

    # CVSS v4.0 scoring (future-proofing)
    cvss_v4_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_v4_vector: Mapped[str | None] = mapped_column(String(300))
    cvss_v4_severity: Mapped[str | None] = mapped_column(String(10))

    # CWE associations
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    primary_cwe_id: Mapped[str | None] = mapped_column(String(20))

    # Problem type classification
    problem_type: Mapped[str | None] = mapped_column(Text)

    # Source tracking
    assigner: Mapped[str | None] = mapped_column(String(100))
    data_source: Mapped[str] = mapped_column(String(50), default="NVD")
    data_version: Mapped[str | None] = mapped_column(String(20))

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Computed flags (for faster queries)
    has_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    has_kev_entry: Mapped[bool] = mapped_column(Boolean, default=False)
    has_epss_score: Mapped[bool] = mapped_column(Boolean, default=False)
    has_public_poc: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    references: Mapped[list["CVEReference"]] = relationship(
        "CVEReference", back_populates="cve", cascade="all, delete-orphan"
    )
    cpe_mappings: Mapped[list["CVECPEMapping"]] = relationship(
        "CVECPEMapping", back_populates="cve", cascade="all, delete-orphan"
    )
    exploits: Mapped[list["ExploitReference"]] = relationship(
        "ExploitReference", back_populates="cve", cascade="all, delete-orphan"
    )
    kev_entry: Mapped["CISAKEV | None"] = relationship(
        "CISAKEV", back_populates="cve", uselist=False, cascade="all, delete-orphan"
    )
    epss_score: Mapped["EPSSScore | None"] = relationship(
        "EPSSScore", back_populates="cve", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("published_date <= last_modified_date", name="published_check"),
        Index("idx_cves_published", published_date.desc()),
        Index("idx_cves_modified", last_modified_date.desc()),
        Index("idx_cves_cvss_v3_score", cvss_v3_score.desc().nulls_last()),
        Index(
            "idx_cves_severity",
            cvss_v3_severity,
            postgresql_where=(cvss_v3_severity.in_(["HIGH", "CRITICAL"])),
        ),
        Index("idx_cves_has_kev", cve_id, postgresql_where=(has_kev_entry.is_(True))),
        Index("idx_cves_has_exploit", cve_id, postgresql_where=(has_exploit.is_(True))),
        Index(
            "idx_cves_description_fts",
            description_vector,
            postgresql_using="gin",
        ),
        Index(
            "idx_cves_high_priority",
            published_date.desc(),
            postgresql_where=((cvss_v3_score >= 7.0) | (has_kev_entry.is_(True))),
        ),
    )


class CVEReference(Base):
    """External references, advisories, and patches for CVEs."""

    __tablename__ = "cve_references"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False
    )

    # Reference details
    url: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(String(100))
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Metadata
    added_date: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationship
    cve: Mapped["CVE"] = relationship("CVE", back_populates="references")

    __table_args__ = (
        UniqueConstraint("cve_id", "url", name="cve_references_unique"),
        Index("idx_cve_refs_cve_id", cve_id),
        Index("idx_cve_refs_tags", tags, postgresql_using="gin"),
        Index("idx_cve_refs_source", source),
    )


class CVECPEMapping(Base):
    """CPE (Common Platform Enumeration) mappings - which products/versions are affected."""

    __tablename__ = "cve_cpe_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False
    )

    # CPE 2.3 format
    cpe_uri: Mapped[str] = mapped_column(String(500), nullable=False)

    # Parsed CPE components
    cpe_part: Mapped[str | None] = mapped_column(String(1))  # 'a', 'o', 'h'
    cpe_vendor: Mapped[str | None] = mapped_column(String(100))
    cpe_product: Mapped[str | None] = mapped_column(String(100))
    cpe_version: Mapped[str | None] = mapped_column(String(100))
    cpe_update: Mapped[str | None] = mapped_column(String(100))

    # Version range
    version_start_type: Mapped[str | None] = mapped_column(String(20))
    version_start: Mapped[str | None] = mapped_column(String(100))
    version_end_type: Mapped[str | None] = mapped_column(String(20))
    version_end: Mapped[str | None] = mapped_column(String(100))

    # Vulnerability status
    vulnerable: Mapped[bool] = mapped_column(Boolean, default=True)

    # Metadata
    configuration_id: Mapped[str | None] = mapped_column(String(100))
    added_date: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationship
    cve: Mapped["CVE"] = relationship("CVE", back_populates="cpe_mappings")

    __table_args__ = (
        UniqueConstraint(
            "cve_id", "cpe_uri", "version_start", "version_end", name="cpe_mappings_unique"
        ),
        Index("idx_cpe_cve_id", cve_id),
        Index("idx_cpe_uri", cpe_uri),
        Index("idx_cpe_vendor", cpe_vendor),
        Index("idx_cpe_product", cpe_product),
        Index("idx_cpe_vendor_product", cpe_vendor, cpe_product),
        Index("idx_cpe_version_range", cpe_vendor, cpe_product, version_start, version_end),
    )


class CWEData(Base):
    """CWE (Common Weakness Enumeration) definitions."""

    __tablename__ = "cwe_data"

    cwe_id: Mapped[str] = mapped_column(String(20), primary_key=True)

    # CWE details
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    extended_description: Mapped[str | None] = mapped_column(Text)

    # Classification
    weakness_type: Mapped[str | None] = mapped_column(String(50))
    abstraction: Mapped[str | None] = mapped_column(String(20))

    # Relationships
    parent_cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    child_cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # MITRE ATT&CK mapping
    related_attack_patterns: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    __table_args__ = (
        Index("idx_cwe_name", name, postgresql_using="gin", postgresql_ops={"name": "gin_trgm_ops"}),
        Index("idx_cwe_type", weakness_type),
    )
