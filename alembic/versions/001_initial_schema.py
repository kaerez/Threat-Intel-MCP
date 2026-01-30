"""Initial schema - CVE MCP database tables.

Revision ID: 001
Revises:
Create Date: 2026-01-30

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable required extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gin")

    # Create cves table
    op.create_table(
        "cves",
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("published_date", sa.DateTime(), nullable=False),
        sa.Column("last_modified_date", sa.DateTime(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("description_vector", postgresql.TSVECTOR()),
        sa.Column("cvss_v2_score", sa.Numeric(3, 1)),
        sa.Column("cvss_v2_vector", sa.String(50)),
        sa.Column("cvss_v2_severity", sa.String(10)),
        sa.Column("cvss_v3_score", sa.Numeric(3, 1)),
        sa.Column("cvss_v3_vector", sa.String(100)),
        sa.Column("cvss_v3_severity", sa.String(10)),
        sa.Column("cvss_v3_base_score", sa.Numeric(3, 1)),
        sa.Column("cvss_v3_exploitability_score", sa.Numeric(3, 1)),
        sa.Column("cvss_v3_impact_score", sa.Numeric(3, 1)),
        sa.Column("cvss_v4_score", sa.Numeric(3, 1)),
        sa.Column("cvss_v4_vector", sa.String(150)),
        sa.Column("cvss_v4_severity", sa.String(10)),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.Text())),
        sa.Column("primary_cwe_id", sa.String(20)),
        sa.Column("problem_type", sa.Text()),
        sa.Column("assigner", sa.String(100)),
        sa.Column("data_source", sa.String(50), server_default="NVD"),
        sa.Column("data_version", sa.String(20)),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("first_seen", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("has_exploit", sa.Boolean(), server_default="false"),
        sa.Column("has_kev_entry", sa.Boolean(), server_default="false"),
        sa.Column("has_epss_score", sa.Boolean(), server_default="false"),
        sa.Column("has_public_poc", sa.Boolean(), server_default="false"),
        sa.CheckConstraint(
            "published_date <= last_modified_date", name="ck_cves_published_check"
        ),
    )

    # Create indexes for cves
    op.create_index("idx_cves_published", "cves", [sa.text("published_date DESC")])
    op.create_index("idx_cves_modified", "cves", [sa.text("last_modified_date DESC")])
    op.create_index(
        "idx_cves_cvss_v3_score", "cves", [sa.text("cvss_v3_score DESC NULLS LAST")]
    )
    op.create_index(
        "idx_cves_severity",
        "cves",
        ["cvss_v3_severity"],
        postgresql_where=sa.text("cvss_v3_severity IN ('HIGH', 'CRITICAL')"),
    )
    op.create_index(
        "idx_cves_has_kev",
        "cves",
        ["cve_id"],
        postgresql_where=sa.text("has_kev_entry = true"),
    )
    op.create_index(
        "idx_cves_has_exploit",
        "cves",
        ["cve_id"],
        postgresql_where=sa.text("has_exploit = true"),
    )
    op.create_index(
        "idx_cves_description_fts",
        "cves",
        ["description_vector"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_cves_high_priority",
        "cves",
        [sa.text("published_date DESC")],
        postgresql_where=sa.text("cvss_v3_score >= 7.0 OR has_kev_entry = true"),
    )

    # Create trigger for tsvector update
    op.execute("""
        CREATE OR REPLACE FUNCTION update_description_vector()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.description_vector := to_tsvector('english', COALESCE(NEW.description, ''));
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER cves_description_vector_update
        BEFORE INSERT OR UPDATE ON cves
        FOR EACH ROW
        EXECUTE FUNCTION update_description_vector();
    """)

    # Create cve_references table
    op.create_table(
        "cve_references",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "cve_id",
            sa.String(20),
            sa.ForeignKey("cves.cve_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("source", sa.String(100)),
        sa.Column("tags", postgresql.ARRAY(sa.Text())),
        sa.Column("added_date", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("cve_id", "url", name="uq_cve_references_cve_id_url"),
    )
    op.create_index("idx_cve_refs_cve_id", "cve_references", ["cve_id"])
    op.create_index("idx_cve_refs_tags", "cve_references", ["tags"], postgresql_using="gin")
    op.create_index("idx_cve_refs_source", "cve_references", ["source"])

    # Create cve_cpe_mappings table
    op.create_table(
        "cve_cpe_mappings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "cve_id",
            sa.String(20),
            sa.ForeignKey("cves.cve_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cpe_uri", sa.String(500), nullable=False),
        sa.Column("cpe_part", sa.String(1)),
        sa.Column("cpe_vendor", sa.String(100)),
        sa.Column("cpe_product", sa.String(100)),
        sa.Column("cpe_version", sa.String(100)),
        sa.Column("cpe_update", sa.String(100)),
        sa.Column("version_start_type", sa.String(20)),
        sa.Column("version_start", sa.String(100)),
        sa.Column("version_end_type", sa.String(20)),
        sa.Column("version_end", sa.String(100)),
        sa.Column("vulnerable", sa.Boolean(), server_default="true"),
        sa.Column("configuration_id", sa.String(100)),
        sa.Column("added_date", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "cve_id",
            "cpe_uri",
            "version_start",
            "version_end",
            name="uq_cve_cpe_mappings_unique",
        ),
    )
    op.create_index("idx_cpe_cve_id", "cve_cpe_mappings", ["cve_id"])
    op.create_index("idx_cpe_uri", "cve_cpe_mappings", ["cpe_uri"])
    op.create_index("idx_cpe_vendor", "cve_cpe_mappings", ["cpe_vendor"])
    op.create_index("idx_cpe_product", "cve_cpe_mappings", ["cpe_product"])
    op.create_index(
        "idx_cpe_vendor_product", "cve_cpe_mappings", ["cpe_vendor", "cpe_product"]
    )
    op.create_index(
        "idx_cpe_version_range",
        "cve_cpe_mappings",
        ["cpe_vendor", "cpe_product", "version_start", "version_end"],
    )

    # Create cisa_kev table
    op.create_table(
        "cisa_kev",
        sa.Column(
            "cve_id",
            sa.String(20),
            sa.ForeignKey("cves.cve_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("vulnerability_name", sa.Text()),
        sa.Column("short_description", sa.Text()),
        sa.Column("required_action", sa.Text(), nullable=False),
        sa.Column("due_date", sa.Date()),
        sa.Column("known_ransomware_use", sa.Boolean(), server_default="false"),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("notes", sa.Text()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("idx_kev_date_added", "cisa_kev", [sa.text("date_added DESC")])
    op.create_index(
        "idx_kev_ransomware",
        "cisa_kev",
        ["cve_id"],
        postgresql_where=sa.text("known_ransomware_use = true"),
    )
    op.create_index(
        "idx_kev_due_date",
        "cisa_kev",
        ["due_date"],
        postgresql_where=sa.text("due_date IS NOT NULL"),
    )

    # Create epss_scores table
    op.create_table(
        "epss_scores",
        sa.Column(
            "cve_id",
            sa.String(20),
            sa.ForeignKey("cves.cve_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("epss_score", sa.Numeric(6, 5), nullable=False),
        sa.Column("epss_percentile", sa.Numeric(6, 5), nullable=False),
        sa.Column("date_scored", sa.Date(), nullable=False),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
        sa.CheckConstraint(
            "epss_score >= 0 AND epss_score <= 1", name="ck_epss_scores_score_range"
        ),
        sa.CheckConstraint(
            "epss_percentile >= 0 AND epss_percentile <= 1",
            name="ck_epss_scores_percentile_range",
        ),
    )
    op.create_index("idx_epss_score", "epss_scores", [sa.text("epss_score DESC")])
    op.create_index(
        "idx_epss_percentile", "epss_scores", [sa.text("epss_percentile DESC")]
    )
    op.create_index(
        "idx_epss_high_risk",
        "epss_scores",
        ["cve_id"],
        postgresql_where=sa.text("epss_score >= 0.75"),
    )

    # Create exploit_references table
    op.create_table(
        "exploit_references",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "cve_id",
            sa.String(20),
            sa.ForeignKey("cves.cve_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("exploit_url", sa.Text(), nullable=False),
        sa.Column("exploit_type", sa.String(50), nullable=False),
        sa.Column("exploit_title", sa.Text()),
        sa.Column("exploit_description", sa.Text()),
        sa.Column("exploit_maturity", sa.String(20)),
        sa.Column("verified", sa.Boolean(), server_default="false"),
        sa.Column("requires_authentication", sa.Boolean()),
        sa.Column("requires_user_interaction", sa.Boolean()),
        sa.Column("exploit_complexity", sa.String(10)),
        sa.Column("exploitdb_id", sa.Integer()),
        sa.Column("metasploit_module", sa.String(200)),
        sa.Column("github_repo", sa.String(200)),
        sa.Column("exploit_published_date", sa.Date()),
        sa.Column("date_added", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "cve_id", "exploit_url", name="uq_exploit_references_cve_id_url"
        ),
    )
    op.create_index("idx_exploit_cve_id", "exploit_references", ["cve_id"])
    op.create_index("idx_exploit_type", "exploit_references", ["exploit_type"])
    op.create_index("idx_exploit_maturity", "exploit_references", ["exploit_maturity"])
    op.create_index(
        "idx_exploit_verified",
        "exploit_references",
        ["cve_id"],
        postgresql_where=sa.text("verified = true"),
    )
    op.create_index(
        "idx_exploit_metasploit",
        "exploit_references",
        ["cve_id"],
        postgresql_where=sa.text("exploit_type = 'metasploit'"),
    )

    # Create cwe_data table
    op.create_table(
        "cwe_data",
        sa.Column("cwe_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("extended_description", sa.Text()),
        sa.Column("weakness_type", sa.String(50)),
        sa.Column("abstraction", sa.String(20)),
        sa.Column("parent_cwe_ids", postgresql.ARRAY(sa.Text())),
        sa.Column("child_cwe_ids", postgresql.ARRAY(sa.Text())),
        sa.Column("related_attack_patterns", postgresql.ARRAY(sa.Text())),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("idx_cwe_type", "cwe_data", ["weakness_type"])

    # Create sync_metadata table
    op.create_table(
        "sync_metadata",
        sa.Column("source", sa.String(50), primary_key=True),
        sa.Column("last_sync_time", sa.DateTime(), nullable=False),
        sa.Column("last_sync_status", sa.String(20), nullable=False),
        sa.Column("next_sync_time", sa.DateTime()),
        sa.Column("records_synced", sa.Integer(), server_default="0"),
        sa.Column("records_updated", sa.Integer(), server_default="0"),
        sa.Column("records_inserted", sa.Integer(), server_default="0"),
        sa.Column("records_deleted", sa.Integer(), server_default="0"),
        sa.Column("sync_duration_seconds", sa.Integer()),
        sa.Column("error_message", sa.Text()),
        sa.Column("retry_count", sa.Integer(), server_default="0"),
        sa.Column("data_version", sa.String(50)),
        sa.Column("data_checksum", sa.String(64)),
        sa.Column("sync_window_start", sa.Time(), server_default="02:00:00"),
        sa.Column("sync_window_end", sa.Time(), server_default="04:00:00"),
    )

    # Seed initial sync metadata
    op.execute("""
        INSERT INTO sync_metadata (source, last_sync_time, last_sync_status) VALUES
        ('nvd_recent', '1970-01-01', 'pending'),
        ('nvd_full', '1970-01-01', 'pending'),
        ('cisa_kev', '1970-01-01', 'pending'),
        ('epss_scores', '1970-01-01', 'pending'),
        ('exploitdb', '1970-01-01', 'pending'),
        ('cwe_data', '1970-01-01', 'pending')
        ON CONFLICT (source) DO NOTHING;
    """)

    # Create query_audit_log table
    op.create_table(
        "query_audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("client_id", sa.String(100)),
        sa.Column("user_id", sa.String(100)),
        sa.Column("tool_name", sa.String(50), nullable=False),
        sa.Column("query_params", postgresql.JSONB()),
        sa.Column("result_count", sa.Integer()),
        sa.Column("match_found", sa.Boolean()),
        sa.Column("has_kev_result", sa.Boolean()),
        sa.Column("query_time_ms", sa.Integer()),
        sa.Column("cache_hit", sa.Boolean(), server_default="false"),
        sa.Column("workflow_run_id", sa.String(100)),
        sa.Column("request_id", sa.String(100)),
    )
    op.create_index(
        "idx_audit_timestamp", "query_audit_log", [sa.text("timestamp DESC")]
    )
    op.create_index("idx_audit_client", "query_audit_log", ["client_id"])
    op.create_index("idx_audit_tool", "query_audit_log", ["tool_name"])

    # Create materialized view for high-priority CVEs
    op.execute("""
        CREATE MATERIALIZED VIEW mv_high_priority_cves AS
        SELECT
            c.cve_id,
            c.published_date,
            c.cvss_v3_score,
            c.cvss_v3_severity,
            c.description,
            c.has_kev_entry,
            c.has_exploit,
            k.date_added AS kev_date_added,
            k.known_ransomware_use,
            e.epss_score,
            e.epss_percentile,
            COUNT(DISTINCT ex.id) AS exploit_count
        FROM cves c
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        LEFT JOIN epss_scores e ON c.cve_id = e.cve_id
        LEFT JOIN exploit_references ex ON c.cve_id = ex.cve_id
        WHERE
            c.cvss_v3_score >= 7.0
            OR c.has_kev_entry = true
            OR e.epss_score >= 0.5
        GROUP BY c.cve_id, k.date_added, k.known_ransomware_use, e.epss_score, e.epss_percentile;
    """)
    op.execute(
        "CREATE UNIQUE INDEX idx_mv_high_priority_cve_id ON mv_high_priority_cves(cve_id)"
    )
    op.execute(
        "CREATE INDEX idx_mv_high_priority_score ON mv_high_priority_cves(cvss_v3_score DESC)"
    )
    op.execute(
        "CREATE INDEX idx_mv_high_priority_kev ON mv_high_priority_cves(cve_id) WHERE has_kev_entry = true"
    )


def downgrade() -> None:
    # Drop materialized view
    op.execute("DROP MATERIALIZED VIEW IF EXISTS mv_high_priority_cves")

    # Drop tables in reverse order (respecting foreign keys)
    op.drop_table("query_audit_log")
    op.drop_table("sync_metadata")
    op.drop_table("cwe_data")
    op.drop_table("exploit_references")
    op.drop_table("epss_scores")
    op.drop_table("cisa_kev")
    op.drop_table("cve_cpe_mappings")
    op.drop_table("cve_references")

    # Drop trigger and function
    op.execute("DROP TRIGGER IF EXISTS cves_description_vector_update ON cves")
    op.execute("DROP FUNCTION IF EXISTS update_description_vector()")

    op.drop_table("cves")

    # Drop extensions
    op.execute("DROP EXTENSION IF EXISTS btree_gin")
    op.execute("DROP EXTENSION IF EXISTS pg_trgm")
