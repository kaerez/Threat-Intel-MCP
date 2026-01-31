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
    inputSchema: dict[str, Any]  # noqa: N815 - MCP protocol uses camelCase


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
    isError: bool = False  # noqa: N815 - MCP protocol uses camelCase


# ATT&CK Request Schemas


class SearchTechniquesRequest(BaseModel):
    """Request schema for search_techniques tool."""

    query: str | None = Field(None, description="Full-text search in name/description")
    tactics: list[str] | None = Field(None, description="Filter by tactics")
    platforms: list[str] | None = Field(None, description="Filter by platforms")
    include_subtechniques: bool = Field(True, description="Include subtechniques in results")
    active_only: bool = Field(True, description="Exclude deprecated/revoked techniques")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarTechniquesRequest(BaseModel):
    """Request schema for find_similar_techniques tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of attack scenario",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    tactics: list[str] | None = Field(None, description="Filter by tactics")
    platforms: list[str] | None = Field(None, description="Filter by platforms")
    active_only: bool = Field(True, description="Exclude deprecated/revoked techniques")
    limit: int = Field(10, ge=1, le=100, description="Max results")


class GetTechniqueDetailsRequest(BaseModel):
    """Request schema for get_technique_details tool."""

    technique_id: str = Field(..., description="Technique ID (e.g., T1566 or T1566.001)")


class GetTechniqueBadgesRequest(BaseModel):
    """Request schema for get_technique_badges tool."""

    technique_ids: list[str] = Field(..., description="List of technique IDs")


class SearchThreatActorsRequest(BaseModel):
    """Request schema for search_threat_actors tool."""

    query: str | None = Field(None, description="Full-text search in name/aliases/description")
    techniques: list[str] | None = Field(None, description="Filter by techniques used")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarThreatActorsRequest(BaseModel):
    """Request schema for find_similar_threat_actors tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of threat actor or activity",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    limit: int = Field(10, ge=1, le=100, description="Max results")


class GetGroupProfileRequest(BaseModel):
    """Request schema for get_group_profile tool."""

    group_id: str = Field(..., description="Group ID (e.g., G0001)")


# ATLAS Request Schemas


class SearchATLASTechniquesRequest(BaseModel):
    """Request schema for search_atlas_techniques tool."""

    query: str | None = Field(None, description="Full-text search in name/description")
    tactics: list[str] | None = Field(None, description="Filter by tactics")
    ml_lifecycle_stage: str | None = Field(
        None, description="Filter by ML lifecycle stage (e.g., training, deployment)"
    )
    ai_system_type: list[str] | None = Field(
        None, description="Filter by AI system type (e.g., computer-vision, nlp)"
    )
    active_only: bool = Field(True, description="Exclude deprecated/revoked techniques")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarATLASTechniquesRequest(BaseModel):
    """Request schema for find_similar_atlas_techniques tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of AI/ML attack scenario",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    tactics: list[str] | None = Field(None, description="Filter by tactics")
    ml_lifecycle_stage: str | None = Field(None, description="Filter by ML lifecycle stage")
    ai_system_type: list[str] | None = Field(None, description="Filter by AI system type")
    active_only: bool = Field(True, description="Exclude deprecated/revoked techniques")
    limit: int = Field(10, ge=1, le=100, description="Max results")


class GetATLASTechniqueDetailsRequest(BaseModel):
    """Request schema for get_atlas_technique_details tool."""

    technique_id: str = Field(
        ..., description="ATLAS technique ID (e.g., AML.T0001)", pattern=r"^AML\.T\d{4}$"
    )


class SearchATLASCaseStudiesRequest(BaseModel):
    """Request schema for search_atlas_case_studies tool."""

    query: str | None = Field(None, description="Full-text search in name/summary")
    techniques: list[str] | None = Field(None, description="Filter by techniques used")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarATLASCaseStudiesRequest(BaseModel):
    """Request schema for find_similar_atlas_case_studies tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of AI/ML incident or scenario",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    limit: int = Field(10, ge=1, le=100, description="Max results")


# CAPEC Request Schemas


class SearchCAPECPatternsRequest(BaseModel):
    """Request schema for search_capec_patterns tool."""

    query: str | None = Field(None, description="Full-text search in name/description")
    abstraction: list[str] | None = Field(
        None, description="Filter by abstraction levels (Meta, Standard, Detailed)"
    )
    likelihood: str | None = Field(
        None, description="Filter by attack likelihood (High, Medium, Low)"
    )
    severity: str | None = Field(None, description="Filter by typical severity (High, Medium, Low)")
    related_cwe: list[str] | None = Field(
        None, description="Filter by related CWE IDs (e.g., ['CWE-79', 'CWE-89'])"
    )
    active_only: bool = Field(True, description="Exclude deprecated patterns")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarCAPECPatternsRequest(BaseModel):
    """Request schema for find_similar_capec_patterns tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of attack scenario",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    abstraction: list[str] | None = Field(None, description="Filter by abstraction levels")
    likelihood: str | None = Field(None, description="Filter by attack likelihood")
    severity: str | None = Field(None, description="Filter by typical severity")
    active_only: bool = Field(True, description="Exclude deprecated patterns")
    limit: int = Field(10, ge=1, le=100, description="Max results")


class GetCAPECPatternDetailsRequest(BaseModel):
    """Request schema for get_capec_pattern_details tool."""

    pattern_id: str = Field(
        ..., description="CAPEC pattern ID (e.g., CAPEC-66)", pattern=r"^CAPEC-\d+$"
    )


class SearchCAPECMitigationsRequest(BaseModel):
    """Request schema for search_capec_mitigations tool."""

    query: str | None = Field(None, description="Full-text search in name/description")
    effectiveness: str | None = Field(
        None, description="Filter by effectiveness (High, Medium, Low)"
    )
    patterns: list[str] | None = Field(
        None, description="Filter by patterns mitigated (e.g., ['CAPEC-66'])"
    )
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarCAPECMitigationsRequest(BaseModel):
    """Request schema for find_similar_capec_mitigations tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of mitigation need or security control",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    effectiveness: str | None = Field(None, description="Filter by effectiveness")
    limit: int = Field(10, ge=1, le=100, description="Max results")


# CWE Request Schemas


class SearchCWEWeaknessesRequest(BaseModel):
    """Request schema for search_cwe_weaknesses tool."""

    query: str | None = Field(None, description="Full-text search in name/description")
    abstraction: list[str] | None = Field(
        None, description="Filter by abstraction levels (Pillar, Class, Base, Variant, Compound)"
    )
    include_children: bool = Field(False, description="Include child weaknesses of matches")
    active_only: bool = Field(True, description="Exclude deprecated weaknesses")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarCWEWeaknessesRequest(BaseModel):
    """Request schema for find_similar_cwe_weaknesses tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of weakness or vulnerability",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    abstraction: list[str] | None = Field(None, description="Filter by abstraction levels")
    active_only: bool = Field(True, description="Exclude deprecated weaknesses")
    limit: int = Field(10, ge=1, le=100, description="Max results")


class GetCWEWeaknessDetailsRequest(BaseModel):
    """Request schema for get_cwe_weakness_details tool."""

    weakness_id: str = Field(
        ..., description="CWE weakness ID (e.g., CWE-79 or 79)", pattern=r"^(CWE-)?\d+$"
    )


class SearchByExternalMappingRequest(BaseModel):
    """Request schema for search_by_external_mapping tool."""

    source: str = Field(
        ..., description="External source name (e.g., 'OWASP Top Ten 2021', 'SANS Top 25')"
    )
    external_id: str | None = Field(None, description="External ID filter (e.g., 'A03:2021')")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class GetCWEHierarchyRequest(BaseModel):
    """Request schema for get_cwe_hierarchy tool."""

    weakness_id: str = Field(
        ..., description="CWE weakness ID (e.g., CWE-79 or 79)", pattern=r"^(CWE-)?\d+$"
    )
    direction: str = Field(
        "both", description="Hierarchy direction: 'parents', 'children', or 'both'"
    )
    depth: int = Field(3, ge=1, le=10, description="Maximum depth to traverse")


class FindWeaknessesForCAPECRequest(BaseModel):
    """Request schema for find_weaknesses_for_capec tool."""

    pattern_id: str = Field(
        ..., description="CAPEC pattern ID (e.g., CAPEC-66)", pattern=r"^(CAPEC-)?\d+$"
    )
