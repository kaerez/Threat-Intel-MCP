"""Intelligence-related database models (KEV, EPSS)."""

from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base

if TYPE_CHECKING:
    from cve_mcp.models.cve import CVE


class CISAKEV(Base):
    """CISA Known Exploited Vulnerabilities catalog."""

    __tablename__ = "cisa_kev"

    cve_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cves.cve_id", ondelete="CASCADE"), primary_key=True
    )

    # KEV catalog data
    vulnerability_name: Mapped[str | None] = mapped_column(Text)
    short_description: Mapped[str | None] = mapped_column(Text)
    required_action: Mapped[str] = mapped_column(Text, nullable=False)
    due_date: Mapped[date | None] = mapped_column(Date)

    # Threat context
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)

    # Temporal data
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationship
    cve: Mapped["CVE"] = relationship("CVE", back_populates="kev_entry")

    __table_args__ = (
        Index("idx_kev_date_added", date_added.desc()),
        Index("idx_kev_ransomware", cve_id, postgresql_where=(known_ransomware_use.is_(True))),
        Index("idx_kev_due_date", due_date, postgresql_where=(due_date.is_not(None))),
    )


class EPSSScore(Base):
    """FIRST EPSS (Exploit Prediction Scoring System) scores."""

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cves.cve_id", ondelete="CASCADE"), primary_key=True
    )

    # EPSS scoring
    epss_score: Mapped[float] = mapped_column(Numeric(6, 5), nullable=False)
    epss_percentile: Mapped[float] = mapped_column(Numeric(6, 5), nullable=False)

    # Temporal data
    date_scored: Mapped[date] = mapped_column(Date, nullable=False)

    # Sync metadata
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationship
    cve: Mapped["CVE"] = relationship("CVE", back_populates="epss_score")

    __table_args__ = (
        CheckConstraint("epss_score >= 0 AND epss_score <= 1", name="epss_score_range"),
        CheckConstraint("epss_percentile >= 0 AND epss_percentile <= 1", name="epss_percentile_range"),
        Index("idx_epss_score", epss_score.desc()),
        Index("idx_epss_percentile", epss_percentile.desc()),
        Index("idx_epss_high_risk", cve_id, postgresql_where=(epss_score >= 0.75)),
    )
