"""Metadata database models (sync tracking, audit logs)."""

from datetime import datetime, time

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    Time,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from cve_mcp.models.base import Base


class SyncMetadata(Base):
    """Tracks data sync status and freshness for all external sources."""

    __tablename__ = "sync_metadata"

    source: Mapped[str] = mapped_column(String(50), primary_key=True)

    # Sync status
    last_sync_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_sync_status: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # 'success', 'failed', 'partial', 'running', 'pending'
    next_sync_time: Mapped[datetime | None] = mapped_column(DateTime)

    # Sync statistics
    records_synced: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    records_inserted: Mapped[int] = mapped_column(Integer, default=0)
    records_deleted: Mapped[int] = mapped_column(Integer, default=0)
    sync_duration_seconds: Mapped[int | None] = mapped_column(Integer)

    # Error handling
    error_message: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)

    # Data version
    data_version: Mapped[str | None] = mapped_column(String(50))
    data_checksum: Mapped[str | None] = mapped_column(String(64))

    # Sync window
    sync_window_start: Mapped[time] = mapped_column(Time, default=time(2, 0))
    sync_window_end: Mapped[time] = mapped_column(Time, default=time(4, 0))


class QueryAuditLog(Base):
    """7-year audit trail of all CVE queries for compliance."""

    __tablename__ = "query_audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # Query metadata
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    client_id: Mapped[str | None] = mapped_column(String(100))
    user_id: Mapped[str | None] = mapped_column(String(100))

    # Query details
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    query_params: Mapped[dict | None] = mapped_column(JSONB)

    # Results
    result_count: Mapped[int | None] = mapped_column(Integer)
    match_found: Mapped[bool | None] = mapped_column(Boolean)
    has_kev_result: Mapped[bool | None] = mapped_column(Boolean)

    # Performance
    query_time_ms: Mapped[int | None] = mapped_column(Integer)
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False)

    # Context
    workflow_run_id: Mapped[str | None] = mapped_column(String(100))
    request_id: Mapped[str | None] = mapped_column(String(100))

    __table_args__ = (
        Index("idx_audit_timestamp", timestamp.desc()),
        Index("idx_audit_client", client_id),
        Index("idx_audit_tool", tool_name),
    )
