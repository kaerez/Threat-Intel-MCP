"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MetadataResponse(BaseModel):
    """Metadata included in all responses."""

    query_time_ms: int
    cache_hit: bool = False
    data_freshness: str = "current"
    last_sync_time: str | None = None
    data_age_hours: int | None = None


class SearchCVERequest(BaseModel):
    """Request schema for search_cve tool."""

    keyword: str | None = Field(None, description="Full-text search in description")
    cvss_min: float | None = Field(None, ge=0, le=10, description="Minimum CVSS v3 score")
    cvss_max: float | None = Field(None, ge=0, le=10, description="Maximum CVSS v3 score")
    severity: list[str] | None = Field(
        None, description="Severity levels: CRITICAL, HIGH, MEDIUM, LOW, NONE"
    )
    has_kev: bool | None = Field(None, description="Only CVEs in CISA KEV catalog")
    has_exploit: bool | None = Field(None, description="Only CVEs with public exploits")
    epss_min: float | None = Field(None, ge=0, le=1, description="Minimum EPSS score")
    published_after: datetime | None = Field(None, description="Published after date")
    published_before: datetime | None = Field(None, description="Published before date")
    cwe_ids: list[str] | None = Field(None, description="Filter by CWE IDs")
    limit: int = Field(50, ge=1, le=500, description="Max results")
    offset: int = Field(0, ge=0, description="Pagination offset")


class SearchCVEResponse(BaseModel):
    """Response schema for search_cve tool."""

    data: dict[str, Any]
    metadata: MetadataResponse


class GetCVEDetailsRequest(BaseModel):
    """Request schema for get_cve_details tool."""

    cve_id: str = Field(..., description="CVE identifier", pattern=r"^CVE-\d{4}-\d{4,}$")
    include_references: bool = Field(True, description="Include external links")
    include_cpe: bool = Field(True, description="Include CPE mappings")
    include_exploits: bool = Field(True, description="Include exploit references")


class GetCVEDetailsResponse(BaseModel):
    """Response schema for get_cve_details tool."""

    data: dict[str, Any] | None
    metadata: MetadataResponse


class CheckKEVStatusRequest(BaseModel):
    """Request schema for check_kev_status tool."""

    cve_id: str = Field(..., description="CVE identifier", pattern=r"^CVE-\d{4}-\d{4,}$")


class CheckKEVStatusResponse(BaseModel):
    """Response schema for check_kev_status tool."""

    data: dict[str, Any]
    metadata: MetadataResponse


class GetEPSSScoreRequest(BaseModel):
    """Request schema for get_epss_score tool."""

    cve_id: str = Field(..., description="CVE identifier", pattern=r"^CVE-\d{4}-\d{4,}$")


class GetEPSSScoreResponse(BaseModel):
    """Response schema for get_epss_score tool."""

    data: dict[str, Any]
    metadata: MetadataResponse


class SearchByProductRequest(BaseModel):
    """Request schema for search_by_product tool."""

    product_name: str = Field(..., description="Product name to search")
    vendor: str | None = Field(None, description="Vendor name filter")
    version: str | None = Field(None, description="Version filter")
    version_operator: str | None = Field(
        None, description="Version comparison: eq, lt, lte, gt, gte"
    )
    limit: int = Field(50, ge=1, le=500, description="Max results")


class SearchByProductResponse(BaseModel):
    """Response schema for search_by_product tool."""

    data: dict[str, Any]
    metadata: MetadataResponse


class GetExploitsRequest(BaseModel):
    """Request schema for get_exploits tool."""

    cve_id: str = Field(..., description="CVE identifier", pattern=r"^CVE-\d{4}-\d{4,}$")
    verified_only: bool = Field(False, description="Only return verified exploits")


class GetExploitsResponse(BaseModel):
    """Response schema for get_exploits tool."""

    data: dict[str, Any]
    metadata: MetadataResponse


class GetCWEDetailsRequest(BaseModel):
    """Request schema for get_cwe_details tool."""

    cwe_id: str = Field(..., description="CWE identifier", pattern=r"^CWE-\d+$")


class GetCWEDetailsResponse(BaseModel):
    """Response schema for get_cwe_details tool."""

    data: dict[str, Any] | None
    metadata: MetadataResponse


class BatchSearchRequest(BaseModel):
    """Request schema for batch_search tool."""

    cve_ids: list[str] = Field(..., max_length=100, description="List of CVE IDs (max 100)")
    include_kev: bool = Field(True, description="Include KEV status")
    include_epss: bool = Field(True, description="Include EPSS scores")


class BatchSearchResponse(BaseModel):
    """Response schema for batch_search tool."""

    data: dict[str, Any]
    metadata: MetadataResponse


class HealthResponse(BaseModel):
    """Response schema for health check endpoint."""

    status: str
    data_freshness: dict[str, Any]
    database: dict[str, Any]
    cache: dict[str, Any]


class MCPToolDefinition(BaseModel):
    """MCP tool definition."""

    name: str
    description: str
    inputSchema: dict[str, Any]


class MCPToolsListResponse(BaseModel):
    """Response for listing MCP tools."""

    tools: list[MCPToolDefinition]


class MCPToolCallRequest(BaseModel):
    """Request for calling an MCP tool."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class MCPToolCallResponse(BaseModel):
    """Response from an MCP tool call."""

    content: list[dict[str, Any]]
    isError: bool = False
