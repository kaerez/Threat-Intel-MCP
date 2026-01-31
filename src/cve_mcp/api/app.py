"""FastAPI application for CVE MCP server."""

import json
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cve_mcp.api.schemas import (
    HealthResponse,
    MCPToolCallRequest,
    MCPToolCallResponse,
    MCPToolsListResponse,
)
from cve_mcp.api.tools import TOOL_HANDLERS, call_tool, get_mcp_tools
from cve_mcp.config import get_settings
from cve_mcp.services.cache import cache_service
from cve_mcp.services.database import db_service

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting CVE MCP server")
    await cache_service.connect()
    logger.info("Connected to Redis")
    yield
    # Shutdown
    logger.info("Shutting down CVE MCP server")
    await cache_service.disconnect()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="CVE + Exploit Intelligence MCP Server",
        description="Offline-first MCP server for CVE vulnerability data, CISA KEV, EPSS scores, and exploit tracking",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
    async def call_mcp_tool(request: MCPToolCallRequest) -> MCPToolCallResponse:
        """Call an MCP tool."""
        try:
            result = await call_tool(request.name, request.arguments)
            return MCPToolCallResponse(
                content=[{"type": "text", "text": json.dumps(result, indent=2, default=str)}],
                isError=False,
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
        """REST API endpoint for CWE details."""
        result = await TOOL_HANDLERS["get_cwe_details"]({"cwe_id": cwe_id})
        if result["data"] is None:
            raise HTTPException(status_code=404, detail=f"CWE {cwe_id} not found")
        return JSONResponse(content=result)

    @app.post("/api/batch")
    async def api_batch_search(request: Request) -> JSONResponse:
        """REST API endpoint for batch CVE lookup."""
        params = await request.json()
        result = await TOOL_HANDLERS["batch_search"](params)
        return JSONResponse(content=result)

    return app


# Create default app instance
app = create_app()
