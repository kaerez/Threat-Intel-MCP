"""MCP tool definitions and handlers."""

import time
from datetime import datetime
from typing import Any

from cve_mcp.api.schemas import (
    BatchSearchRequest,
    CheckKEVStatusRequest,
    FindSimilarATLASCaseStudiesRequest,
    FindSimilarATLASTechniquesRequest,
    FindSimilarTechniquesRequest,
    FindSimilarThreatActorsRequest,
    GetATLASTechniqueDetailsRequest,
    GetCVEDetailsRequest,
    GetCWEDetailsRequest,
    GetEPSSScoreRequest,
    GetExploitsRequest,
    GetGroupProfileRequest,
    GetTechniqueBadgesRequest,
    GetTechniqueDetailsRequest,
    MCPToolDefinition,
    SearchATLASCaseStudiesRequest,
    SearchATLASTechniquesRequest,
    SearchByProductRequest,
    SearchCVERequest,
    SearchTechniquesRequest,
    SearchThreatActorsRequest,
)
from cve_mcp.config import get_settings
from cve_mcp.services import atlas_queries, attack_queries
from cve_mcp.services.cache import cache_service
from cve_mcp.services.database import db_service

# MCP Tool Definitions
MCP_TOOLS: list[MCPToolDefinition] = [
    MCPToolDefinition(
        name="search_cve",
        description="Search CVEs by keyword, severity, score range, and filters. Returns matching CVE records with CVSS scores, KEV status, and EPSS data.",
        inputSchema={
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Full-text search in CVE description",
                },
                "cvss_min": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 10,
                    "description": "Minimum CVSS v3 score (0-10)",
                },
                "cvss_max": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 10,
                    "description": "Maximum CVSS v3 score (0-10)",
                },
                "severity": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]},
                    "description": "Severity levels to include",
                },
                "has_kev": {
                    "type": "boolean",
                    "description": "Only CVEs in CISA KEV catalog",
                },
                "has_exploit": {
                    "type": "boolean",
                    "description": "Only CVEs with public exploits",
                },
                "epss_min": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": "Minimum EPSS score (0-1)",
                },
                "published_after": {
                    "type": "string",
                    "format": "date",
                    "description": "Published after date (YYYY-MM-DD)",
                },
                "published_before": {
                    "type": "string",
                    "format": "date",
                    "description": "Published before date (YYYY-MM-DD)",
                },
                "cwe_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by CWE IDs (e.g., ['CWE-79', 'CWE-89'])",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results to return",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Pagination offset",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_cve_details",
        description="Get complete details for a specific CVE including CVSS scores, references, CPE mappings, KEV status, EPSS score, and exploit references.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier (e.g., CVE-2024-1234)",
                },
                "include_references": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include external links",
                },
                "include_cpe": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include CPE mappings",
                },
                "include_exploits": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include exploit references",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="check_kev_status",
        description="Check if a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog. Returns KEV details including required remediation actions and due dates.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_epss_score",
        description="Get the EPSS (Exploit Prediction Scoring System) score for a CVE. Returns the probability of exploitation in the next 30 days and percentile ranking.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_by_product",
        description="Find CVEs affecting a specific product and version. Useful for vulnerability assessment of software components.",
        inputSchema={
            "type": "object",
            "required": ["product_name"],
            "properties": {
                "product_name": {
                    "type": "string",
                    "description": "Product name to search (e.g., 'apache', 'nginx')",
                },
                "vendor": {
                    "type": "string",
                    "description": "Vendor name filter (e.g., 'apache', 'microsoft')",
                },
                "version": {
                    "type": "string",
                    "description": "Specific version to check (e.g., '2.4.49')",
                },
                "version_operator": {
                    "type": "string",
                    "enum": ["eq", "lt", "lte", "gt", "gte"],
                    "description": "Version comparison operator",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_exploits",
        description="Get public exploit code references for a CVE from Metasploit, ExploitDB, GitHub PoCs, and other sources.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier",
                },
                "verified_only": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only return verified exploits",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_cwe_details",
        description="Get details about a CWE (Common Weakness Enumeration) including name, description, and related attack patterns.",
        inputSchema={
            "type": "object",
            "required": ["cwe_id"],
            "properties": {
                "cwe_id": {
                    "type": "string",
                    "pattern": "^CWE-\\d+$",
                    "description": "CWE identifier (e.g., CWE-79)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="batch_search",
        description="Get details for multiple CVEs in one query (max 100). Efficient for bulk vulnerability assessment.",
        inputSchema={
            "type": "object",
            "required": ["cve_ids"],
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,}$"},
                    "maxItems": 100,
                    "description": "List of CVE IDs to look up",
                },
                "include_kev": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include KEV status",
                },
                "include_epss": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include EPSS scores",
                },
            },
        },
    ),
    # ATT&CK Tools
    MCPToolDefinition(
        name="search_techniques",
        description="Search MITRE ATT&CK techniques using traditional keyword and filter-based search. Filter by tactics, platforms, and search technique names/descriptions.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in technique name/description",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics (e.g., ['initial-access', 'execution'])",
                },
                "platforms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by platforms (e.g., ['windows', 'linux'])",
                },
                "include_subtechniques": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include subtechniques in results",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_techniques",
        description="Find MITRE ATT&CK techniques using AI-powered semantic similarity search. Perfect for incident response - describe an attack scenario in natural language and get matching techniques with similarity scores. Uses AI embeddings for intelligent matching beyond keyword search. Example: 'Attacker sent phishing email with malicious PDF that executed PowerShell commands'",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of attack scenario or technique",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics",
                },
                "platforms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by platforms",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_technique_details",
        description="Get complete details for a specific MITRE ATT&CK technique including tactics, platforms, detection methods, data sources, and mitigation strategies.",
        inputSchema={
            "type": "object",
            "required": ["technique_id"],
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "Technique ID (e.g., T1566 or T1566.001)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_technique_badges",
        description="Get ATT&CK Navigator badge URLs for multiple techniques. Returns a mapping of technique IDs to their badge URLs for documentation and reporting.",
        inputSchema={
            "type": "object",
            "required": ["technique_ids"],
            "properties": {
                "technique_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of technique IDs (e.g., ['T1566', 'T1566.001'])",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_threat_actors",
        description="Search MITRE ATT&CK threat actor groups using traditional keyword search. Filter by group names, aliases, and techniques used.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in group name/aliases/description",
                },
                "techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by techniques used (e.g., ['T1566.001'])",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_threat_actors",
        description="Find MITRE ATT&CK threat actor groups using AI-powered semantic similarity search. Perfect for threat attribution - describe observed threat actor behavior and get matching groups with similarity scores. Uses AI embeddings for intelligent matching. Example: 'Advanced persistent threat targeting financial institutions with custom malware'",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of threat actor or observed activity",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_group_profile",
        description="Get complete profile for a specific MITRE ATT&CK threat actor group including aliases, techniques used, software, and attribution details.",
        inputSchema={
            "type": "object",
            "required": ["group_id"],
            "properties": {
                "group_id": {
                    "type": "string",
                    "description": "Group ID (e.g., G0001)",
                },
            },
        },
    ),
    # ATLAS Tools
    MCPToolDefinition(
        name="search_atlas_techniques",
        description="Search MITRE ATLAS AI/ML attack techniques using traditional keyword and filter-based search. Filter by tactics, ML lifecycle stage, and AI system type. ATLAS focuses on adversarial ML attacks against AI/ML systems.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in technique name/description",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics (e.g., ['reconnaissance', 'ml-attack', 'impact'])",
                },
                "ml_lifecycle_stage": {
                    "type": "string",
                    "description": "Filter by ML lifecycle stage (e.g., 'data-collection', 'training', 'deployment')",
                },
                "ai_system_type": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by AI system type (e.g., ['computer-vision', 'nlp', 'recommendation'])",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_atlas_techniques",
        description="Find MITRE ATLAS AI/ML attack techniques using AI-powered semantic similarity search. Describe an adversarial ML attack scenario in natural language and get matching techniques with similarity scores. Uses AI embeddings for intelligent matching. Example: 'Attacker poisoned training data to create backdoor in image classifier'",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of AI/ML attack scenario",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics",
                },
                "ml_lifecycle_stage": {
                    "type": "string",
                    "description": "Filter by ML lifecycle stage",
                },
                "ai_system_type": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by AI system type",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_atlas_technique_details",
        description="Get complete details for a specific MITRE ATLAS AI/ML attack technique including tactics, ML lifecycle stage, AI system types, detection methods, and mitigations.",
        inputSchema={
            "type": "object",
            "required": ["technique_id"],
            "properties": {
                "technique_id": {
                    "type": "string",
                    "pattern": "^AML\\.T\\d{4}$",
                    "description": "ATLAS technique ID (e.g., AML.T0001)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_atlas_case_studies",
        description="Search MITRE ATLAS real-world case studies of AI/ML attacks. Filter by techniques used and search case study names and summaries.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in case study name/summary",
                },
                "techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by ATLAS techniques used (e.g., ['AML.T0001'])",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_atlas_case_studies",
        description="Find similar MITRE ATLAS case studies using AI-powered semantic similarity search. Describe an AI/ML incident or attack scenario and get matching real-world case studies with similarity scores. Example: 'Autonomous vehicle fooled by adversarial road signs'",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of AI/ML incident or scenario",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
]


def get_mcp_tools() -> list[MCPToolDefinition]:
    """Get list of MCP tool definitions."""
    return MCP_TOOLS


async def _get_metadata(query_time_ms: int, cache_hit: bool = False) -> dict[str, Any]:
    """Build metadata for response."""
    settings = get_settings()

    # Get last sync time
    async with db_service.session() as session:
        sync_metadata = await db_service.get_sync_metadata(session)

    nvd_sync = sync_metadata.get("nvd_recent", {})
    last_sync = nvd_sync.get("last_sync")

    data_age_hours = None
    data_freshness = "current"
    if last_sync:
        try:
            last_sync_dt = datetime.fromisoformat(last_sync)
            data_age_hours = int((datetime.now() - last_sync_dt).total_seconds() / 3600)
            if data_age_hours > settings.data_freshness_critical_hours:
                data_freshness = "critical"
            elif data_age_hours > settings.data_freshness_warning_hours:
                data_freshness = "stale"
        except Exception:
            pass

    return {
        "query_time_ms": query_time_ms,
        "cache_hit": cache_hit,
        "data_freshness": data_freshness,
        "last_sync_time": last_sync,
        "data_age_hours": data_age_hours,
    }


async def handle_search_cve(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_cve tool call."""
    start_time = time.time()

    # Check cache
    cached = await cache_service.get_search(params)
    if cached:
        query_time_ms = int((time.time() - start_time) * 1000)
        return {
            "data": cached,
            "metadata": await _get_metadata(query_time_ms, cache_hit=True),
        }

    # Parse request
    request = SearchCVERequest(**params)

    # Execute query
    async with db_service.session() as session:
        cves, total_count = await db_service.search_cves(
            session,
            keyword=request.keyword,
            cvss_min=request.cvss_min,
            cvss_max=request.cvss_max,
            severity=request.severity,
            has_kev=request.has_kev,
            has_exploit=request.has_exploit,
            epss_min=request.epss_min,
            published_after=request.published_after,
            published_before=request.published_before,
            cwe_ids=request.cwe_ids,
            limit=request.limit,
            offset=request.offset,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    data = {
        "cves": cves,
        "total_results": total_count,
        "returned_results": len(cves),
    }

    # Cache results
    await cache_service.set_search(params, data)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_cve_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cve_details tool call."""
    start_time = time.time()
    request = GetCVEDetailsRequest(**params)

    # Check cache
    cached = await cache_service.get_cve(request.cve_id)
    if cached:
        query_time_ms = int((time.time() - start_time) * 1000)
        return {
            "data": cached,
            "metadata": await _get_metadata(query_time_ms, cache_hit=True),
        }

    # Execute query
    async with db_service.session() as session:
        data = await db_service.get_cve_details(
            session,
            cve_id=request.cve_id,
            include_references=request.include_references,
            include_cpe=request.include_cpe,
            include_exploits=request.include_exploits,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    if data:
        await cache_service.set_cve(request.cve_id, data)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_check_kev_status(params: dict[str, Any]) -> dict[str, Any]:
    """Handle check_kev_status tool call."""
    start_time = time.time()
    request = CheckKEVStatusRequest(**params)

    async with db_service.session() as session:
        data = await db_service.check_kev_status(session, request.cve_id)

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_epss_score(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_epss_score tool call."""
    start_time = time.time()
    request = GetEPSSScoreRequest(**params)

    async with db_service.session() as session:
        data = await db_service.get_epss_score(session, request.cve_id)

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_by_product(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_by_product tool call."""
    start_time = time.time()
    request = SearchByProductRequest(**params)

    async with db_service.session() as session:
        cves, total_count = await db_service.search_by_product(
            session,
            product_name=request.product_name,
            vendor=request.vendor,
            version=request.version,
            version_operator=request.version_operator,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "cves": cves,
            "total_results": total_count,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_exploits(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_exploits tool call."""
    start_time = time.time()
    request = GetExploitsRequest(**params)

    async with db_service.session() as session:
        data = await db_service.get_exploits(
            session,
            cve_id=request.cve_id,
            verified_only=request.verified_only,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_cwe_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cwe_details tool call."""
    start_time = time.time()
    request = GetCWEDetailsRequest(**params)

    async with db_service.session() as session:
        data = await db_service.get_cwe_details(session, request.cwe_id)

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_batch_search(params: dict[str, Any]) -> dict[str, Any]:
    """Handle batch_search tool call."""
    start_time = time.time()
    request = BatchSearchRequest(**params)

    async with db_service.session() as session:
        data = await db_service.batch_search(
            session,
            cve_ids=request.cve_ids,
            include_kev=request.include_kev,
            include_epss=request.include_epss,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


# ATT&CK Tool Handlers


async def handle_search_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_techniques tool call."""
    start_time = time.time()
    request = SearchTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques, total_count = await attack_queries.search_techniques(
            session,
            query=request.query,
            tactics=request.tactics,
            platforms=request.platforms,
            include_subtechniques=request.include_subtechniques,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "total_results": total_count,
            "returned_results": len(techniques),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_techniques tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques = await attack_queries.find_similar_techniques(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            tactics=request.tactics,
            platforms=request.platforms,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "returned_results": len(techniques),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_technique_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_technique_details tool call."""
    start_time = time.time()
    request = GetTechniqueDetailsRequest(**params)

    async with db_service.session() as session:
        data = await attack_queries.get_technique_details(
            session,
            technique_id=request.technique_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_technique_badges(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_technique_badges tool call."""
    start_time = time.time()
    request = GetTechniqueBadgesRequest(**params)

    async with db_service.session() as session:
        badges = await attack_queries.get_technique_badges(
            session,
            technique_ids=request.technique_ids,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "badges": badges,
            "count": len(badges),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_threat_actors(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_threat_actors tool call."""
    start_time = time.time()
    request = SearchThreatActorsRequest(**params)

    async with db_service.session() as session:
        groups, total_count = await attack_queries.search_threat_actors(
            session,
            query=request.query,
            techniques=request.techniques,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "groups": groups,
            "total_results": total_count,
            "returned_results": len(groups),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_threat_actors(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_threat_actors tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarThreatActorsRequest(**params)

    async with db_service.session() as session:
        groups = await attack_queries.find_similar_threat_actors(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "groups": groups,
            "returned_results": len(groups),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_group_profile(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_group_profile tool call."""
    start_time = time.time()
    request = GetGroupProfileRequest(**params)

    async with db_service.session() as session:
        data = await attack_queries.get_group_profile(
            session,
            group_id=request.group_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


# ATLAS Tool Handlers


async def handle_search_atlas_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_atlas_techniques tool call."""
    start_time = time.time()
    request = SearchATLASTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques, total_count = await atlas_queries.search_techniques(
            session,
            query=request.query,
            tactics=request.tactics,
            ml_lifecycle_stage=request.ml_lifecycle_stage,
            ai_system_type=request.ai_system_type,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "total_results": total_count,
            "returned_results": len(techniques),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_atlas_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_atlas_techniques tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarATLASTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques = await atlas_queries.find_similar_techniques(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            tactics=request.tactics,
            ml_lifecycle_stage=request.ml_lifecycle_stage,
            ai_system_type=request.ai_system_type,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "returned_results": len(techniques),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_atlas_technique_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_atlas_technique_details tool call."""
    start_time = time.time()
    request = GetATLASTechniqueDetailsRequest(**params)

    async with db_service.session() as session:
        data = await atlas_queries.get_technique_details(
            session,
            technique_id=request.technique_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_atlas_case_studies(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_atlas_case_studies tool call."""
    start_time = time.time()
    request = SearchATLASCaseStudiesRequest(**params)

    async with db_service.session() as session:
        case_studies, total_count = await atlas_queries.search_case_studies(
            session,
            query=request.query,
            techniques=request.techniques,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "case_studies": case_studies,
            "total_results": total_count,
            "returned_results": len(case_studies),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_atlas_case_studies(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_atlas_case_studies tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarATLASCaseStudiesRequest(**params)

    async with db_service.session() as session:
        case_studies = await atlas_queries.find_similar_case_studies(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "case_studies": case_studies,
            "returned_results": len(case_studies),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


# Tool handler mapping
TOOL_HANDLERS = {
    "search_cve": handle_search_cve,
    "get_cve_details": handle_get_cve_details,
    "check_kev_status": handle_check_kev_status,
    "get_epss_score": handle_get_epss_score,
    "search_by_product": handle_search_by_product,
    "get_exploits": handle_get_exploits,
    "get_cwe_details": handle_get_cwe_details,
    "batch_search": handle_batch_search,
    # ATT&CK handlers
    "search_techniques": handle_search_techniques,
    "find_similar_techniques": handle_find_similar_techniques,
    "get_technique_details": handle_get_technique_details,
    "get_technique_badges": handle_get_technique_badges,
    "search_threat_actors": handle_search_threat_actors,
    "find_similar_threat_actors": handle_find_similar_threat_actors,
    "get_group_profile": handle_get_group_profile,
    # ATLAS handlers
    "search_atlas_techniques": handle_search_atlas_techniques,
    "find_similar_atlas_techniques": handle_find_similar_atlas_techniques,
    "get_atlas_technique_details": handle_get_atlas_technique_details,
    "search_atlas_case_studies": handle_search_atlas_case_studies,
    "find_similar_atlas_case_studies": handle_find_similar_atlas_case_studies,
}


async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call an MCP tool by name."""
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        raise ValueError(f"Unknown tool: {name}")
    return await handler(arguments)
