"""MCP tool definitions and handlers."""

import time
from datetime import datetime
from typing import Any

from cve_mcp.api.schemas import (
    BatchSearchRequest,
    CheckKEVStatusRequest,
    GetCVEDetailsRequest,
    GetCWEDetailsRequest,
    GetEPSSScoreRequest,
    GetExploitsRequest,
    MCPToolDefinition,
    SearchByProductRequest,
    SearchCVERequest,
)
from cve_mcp.config import get_settings
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
}


async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call an MCP tool by name."""
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        raise ValueError(f"Unknown tool: {name}")
    return await handler(arguments)
