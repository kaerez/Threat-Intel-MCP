"""Configuration settings for Threat Intelligence MCP server."""

from functools import lru_cache

from pydantic_settings import BaseSettings

# Project branding (for display in logs/UI)
# Module name remains "cve_mcp" for backward compatibility
PROJECT_NAME = "Threat Intel MCP"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    database_url: str = "postgresql+asyncpg://cve_user:changeme@localhost:5432/cve_mcp"
    database_url_sync: str = "postgresql://cve_user:changeme@localhost:5432/cve_mcp"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # NVD API
    nvd_api_key: str | None = None
    nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # OpenAI for embeddings (optional - disables semantic search if not set)
    OPENAI_API_KEY: str | None = None

    # CISA KEV
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    # EPSS
    epss_url: str = "https://epss.cyentia.com/epss_scores-current.csv.gz"

    # ExploitDB
    exploitdb_csv_url: str = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )

    # MCP Server
    mcp_port: int = 8307
    mcp_host: str = "0.0.0.0"
    mcp_transport: str = "http"  # 'http' or 'stdio'
    log_level: str = "INFO"
    cors_origins: str = "http://localhost,http://localhost:*,http://127.0.0.1,http://127.0.0.1:*"

    # Sync Configuration
    sync_window_start: str = "02:00"
    sync_window_end: str = "04:00"
    data_freshness_warning_hours: int = 48
    data_freshness_critical_hours: int = 168  # 7 days

    # Performance
    query_cache_ttl_seconds: int = 3600  # 1 hour
    cve_details_cache_ttl_seconds: int = 86400  # 24 hours
    max_query_results: int = 500
    default_query_results: int = 50
    batch_max_cves: int = 100

    # Audit
    audit_log_retention_days: int = 2555  # 7 years

    # Cloud Provider Credentials (for Cloud Security module production data)
    # AWS Security Hub
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_region: str = "us-east-1"
    aws_security_hub_enabled: bool = False

    # Azure Policy
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    azure_tenant_id: str | None = None
    azure_subscription_id: str | None = None
    azure_policy_source: str = "github"  # "github" or "api"
    azure_policy_repo_url: str = "https://github.com/Azure/azure-policy"
    azure_policy_branch: str = "master"

    # GCP Organization Policy
    google_application_credentials: str | None = None  # Path to service account JSON
    gcp_organization_id: str | None = None
    gcp_org_policy_enabled: bool = False

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
