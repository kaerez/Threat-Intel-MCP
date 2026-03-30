"""FastAPI application for CVE MCP server.

This is the HTTP wrapper layer that exposes the MCP server via REST endpoints
for Ansvar platform integration. It calls into the MCP server internally,
ensuring that both stdio (MCP protocol) and HTTP modes use identical business logic.
"""

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mcp.types import TextContent
from pydantic import ValidationError

from cve_mcp.api.middleware import RequestLoggingMiddleware
from cve_mcp.api.schemas import (
    HealthResponse,
    MCPToolCallRequest,
    MCPToolCallResponse,
    MCPToolsListResponse,
)
from cve_mcp.api.tools import TOOL_HANDLERS, get_mcp_tools
from cve_mcp.config import get_settings
from cve_mcp.services.cache import cache_service
from cve_mcp.services.database import db_service

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    # Startup
    logger.info("Starting CVE MCP server (HTTP mode)")

    # Create MCP server instance (lazy import to avoid circular dependency)
    from cve_mcp.mcp.server import create_mcp_server
    app.state.mcp_server = create_mcp_server()
    logger.info("MCP server instance created")

    await cache_service.connect()
    logger.info("Connected to Redis")
    yield
    # Shutdown
    logger.info("Shutting down CVE MCP server")
    await cache_service.disconnect()


def create_app() -> FastAPI:
    """Create and configure FastAPI application.

    This creates the HTTP wrapper around the MCP server. The wrapper:
    - Exposes MCP tools via REST endpoints for Ansvar platform
    - Calls into MCP server internally (same business logic as stdio mode)
    - Provides CORS and request logging middleware
    - Maintains 100% backward compatibility with existing clients
    """
    settings = get_settings()

    app = FastAPI(
        title="Threat Intelligence MCP Server",
        description="Offline-first MCP server for CVE/CISA KEV/EPSS/ExploitDB vulnerability data and MITRE ATT&CK/ATLAS/CAPEC/CWE/D3FEND threat intelligence frameworks with AI-powered semantic search",
        version="1.3.0",
        lifespan=lifespan,
    )

    # CORS middleware - defaults to localhost for security
    # Set CORS_ORIGINS env var to customize (comma-separated list)
    cors_origins = settings.cors_origins.split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging middleware
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/health", response_model=HealthResponse)
    async def health_check() -> HealthResponse:
        """Health check endpoint with data freshness info."""
        # Get database stats
        async with db_service.session() as session:
            db_stats = await db_service.get_database_stats(session)
            sync_metadata = await db_service.get_sync_metadata(session)

        # Get cache stats
        cache_healthy = await cache_service.health_check()
        cache_stats = {"redis_connected": cache_healthy}
        if cache_healthy:
            try:
                cache_stats = await cache_service.get_stats()
            except Exception:
                pass

        # Calculate data freshness
        data_freshness = {}
        for source, meta in sync_metadata.items():
            status = "current"
            age_hours = None
            if meta.get("last_sync"):
                try:
                    from datetime import datetime
                    last_sync = datetime.fromisoformat(meta["last_sync"])
                    age_hours = int((datetime.now() - last_sync).total_seconds() / 3600)
                    if age_hours > settings.data_freshness_critical_hours:
                        status = "critical"
                    elif age_hours > settings.data_freshness_warning_hours:
                        status = "stale"
                except Exception:
                    pass

            data_freshness[source] = {
                "last_sync": meta.get("last_sync"),
                "age_hours": age_hours,
                "status": status,
            }

        return HealthResponse(
            status="healthy" if cache_healthy else "degraded",
            data_freshness=data_freshness,
            database=db_stats,
            cache=cache_stats,
        )

    # MCP Protocol Endpoints

    @app.get("/mcp/tools", response_model=MCPToolsListResponse)
    async def list_tools() -> MCPToolsListResponse:
        """List available MCP tools."""
        return MCPToolsListResponse(tools=get_mcp_tools())

    @app.post("/mcp/tools/call", response_model=MCPToolCallResponse)
    async def call_mcp_tool(
        request: MCPToolCallRequest, req: Request
    ) -> MCPToolCallResponse:
        """Call an MCP tool via HTTP wrapper.

        This endpoint calls into the MCP server's call_tool handler,
        ensuring identical behavior between stdio and HTTP modes.
        """
        try:
            # Get MCP server wrapper from app state
            mcp_server = req.app.state.mcp_server

            # Call the MCP server's call_tool handler directly
            # This returns list[TextContent] in MCP protocol format
            result_contents = await mcp_server.call_tool(
                request.name, request.arguments
            )

            # Convert MCP TextContent response to HTTP response format
            # MCP returns list[TextContent], we need list[dict] for HTTP
            content = [{"type": item.type, "text": item.text} for item in result_contents]

            # Check if the result indicates an error
            # MCP server returns error messages as text starting with "Error calling tool"
            is_error = any(
                isinstance(item, TextContent) and item.text.startswith("Error calling tool")
                for item in result_contents
            )

            return MCPToolCallResponse(content=content, isError=is_error)

        except ValidationError as e:
            # Pydantic validation errors - give agents clear field-level feedback
            errors = e.errors()
            messages = []
            for err in errors:
                loc = " -> ".join(str(l) for l in err["loc"])
                messages.append(f"{loc}: {err['msg']}")
            return MCPToolCallResponse(
                content=[{"type": "text", "text": f"Validation error: {'; '.join(messages)}"}],
                isError=True,
            )
        except ValueError as e:
            return MCPToolCallResponse(
                content=[{"type": "text", "text": str(e)}],
                isError=True,
            )
        except Exception as e:
            logger.exception("Error calling tool", tool=request.name, error=str(e))
            return MCPToolCallResponse(
                content=[{"type": "text", "text": f"Internal error: {str(e)}"}],
                isError=True,
            )

    # Direct REST API Endpoints (alternative to MCP protocol)

    @app.post("/api/search")
    async def api_search_cve(request: Request) -> JSONResponse:
        """REST API endpoint for CVE search."""
        params = await request.json()
        result = await TOOL_HANDLERS["search_cve"](params)
        return JSONResponse(content=result)

    @app.get("/api/cve/{cve_id}")
    async def api_get_cve(
        cve_id: str,
        include_references: bool = True,
        include_cpe: bool = True,
        include_exploits: bool = True,
    ) -> JSONResponse:
        """REST API endpoint for CVE details."""
        result = await TOOL_HANDLERS["get_cve_details"]({
            "cve_id": cve_id,
            "include_references": include_references,
            "include_cpe": include_cpe,
            "include_exploits": include_exploits,
        })
        if result["data"] is None:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        return JSONResponse(content=result)

    @app.get("/api/kev/{cve_id}")
    async def api_check_kev(cve_id: str) -> JSONResponse:
        """REST API endpoint for KEV status check."""
        result = await TOOL_HANDLERS["check_kev_status"]({"cve_id": cve_id})
        return JSONResponse(content=result)

    @app.get("/api/epss/{cve_id}")
    async def api_get_epss(cve_id: str) -> JSONResponse:
        """REST API endpoint for EPSS score."""
        result = await TOOL_HANDLERS["get_epss_score"]({"cve_id": cve_id})
        return JSONResponse(content=result)

    @app.post("/api/product")
    async def api_search_product(request: Request) -> JSONResponse:
        """REST API endpoint for product search."""
        params = await request.json()
        result = await TOOL_HANDLERS["search_by_product"](params)
        return JSONResponse(content=result)

    @app.get("/api/exploits/{cve_id}")
    async def api_get_exploits(cve_id: str, verified_only: bool = False) -> JSONResponse:
        """REST API endpoint for exploit references."""
        result = await TOOL_HANDLERS["get_exploits"]({
            "cve_id": cve_id,
            "verified_only": verified_only,
        })
        return JSONResponse(content=result)

    @app.get("/api/cwe/{cwe_id}")
    async def api_get_cwe(cwe_id: str) -> JSONResponse:
        """REST API endpoint for CWE details (comprehensive data)."""
        result = await TOOL_HANDLERS["get_cwe_details"]({"cwe_id": cwe_id})
        if result["data"] is None:
            raise HTTPException(status_code=404, detail=f"CWE {cwe_id} not found")
        return JSONResponse(content=json.loads(json.dumps(result, default=str)))

    @app.post("/api/batch")
    async def api_batch_search(request: Request) -> JSONResponse:
        """REST API endpoint for batch CVE lookup."""
        params = await request.json()
        result = await TOOL_HANDLERS["batch_search"](params)
        return JSONResponse(content=result)

    # ── Standard MCP Streamable HTTP Endpoint ──────────────────────
    # Handles JSON-RPC 2.0 over POST /mcp for platform proxy + watchdog.
    # The platform sends standard MCP protocol to base_url + /mcp.
    # This translates JSON-RPC requests to internal tool handlers.

    @app.post("/mcp")
    async def mcp_streamable_http(request: Request) -> JSONResponse:
        """Standard MCP Streamable HTTP endpoint (JSON-RPC 2.0).

        Translates MCP protocol requests to internal tool handlers so that
        the Ansvar platform proxy and watchdog can communicate using the
        standard MCP Streamable HTTP transport.
        """
        body = await request.json()
        jsonrpc = body.get("jsonrpc", "2.0")
        req_id = body.get("id")
        method = body.get("method", "")
        params = body.get("params", {})

        # Notifications (no id) — acknowledge silently
        if req_id is None:
            return JSONResponse(content={}, status_code=202)

        if method == "initialize":
            return JSONResponse(content={
                "jsonrpc": jsonrpc,
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "threat-intel-mcp", "version": "1.4.0"},
                },
            })

        if method == "tools/list":
            tools_list = get_mcp_tools()
            return JSONResponse(content={
                "jsonrpc": jsonrpc,
                "id": req_id,
                "result": {
                    "tools": [t.model_dump() for t in tools_list],
                },
            })

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                mcp_server = request.app.state.mcp_server
                result_contents = await mcp_server.call_tool(name, arguments)
                content = [
                    {"type": item.type, "text": item.text}
                    for item in result_contents
                ]
                is_error = any(
                    isinstance(item, TextContent)
                    and item.text.startswith("Error calling tool")
                    for item in result_contents
                )
                return JSONResponse(content={
                    "jsonrpc": jsonrpc,
                    "id": req_id,
                    "result": {"content": content, "isError": is_error},
                })
            except Exception as e:
                logger.exception("MCP tools/call error", tool=name, error=str(e))
                return JSONResponse(content={
                    "jsonrpc": jsonrpc,
                    "id": req_id,
                    "error": {"code": -32603, "message": str(e)},
                })

        return JSONResponse(content={
            "jsonrpc": jsonrpc,
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        })

    return app


# Create default app instance
app = create_app()
