"""Transport implementations for MCP protocol."""

import json

import structlog
import uvicorn
from mcp.server import Server
from mcp.server.stdio import stdio_server

from cve_mcp.services.cache import cache_service

logger = structlog.get_logger(__name__)


async def run_stdio_transport(server: Server) -> None:
    """Run MCP server using stdio transport (for Claude Desktop, Cursor, etc.)."""
    logger.info("Starting MCP server with stdio transport")

    # Connect cache for stdio mode too — tools expect it
    await cache_service.connect()

    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    finally:
        await cache_service.disconnect()


async def run_streamable_http_transport(server: Server, host: str, port: int) -> None:
    """Run MCP server using Streamable HTTP transport (SDK 1.26.0)."""
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    logger.info(
        "Starting MCP server with Streamable HTTP transport",
        host=host, port=port, endpoint="/mcp",
    )

    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=True,
    )

    async def app(scope, receive, send):
        """Raw ASGI app with /mcp and /health routing."""
        if scope["type"] == "lifespan":
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                # Initialize application services
                await cache_service.connect()
                logger.info("Application services initialized")

                # Start session manager task group
                scope["state"] = scope.get("state", {})
                scope["state"]["_sm_cm"] = session_manager.run()
                await scope["state"]["_sm_cm"].__aenter__()
                await send({"type": "lifespan.startup.complete"})
            msg = await receive()
            if msg["type"] == "lifespan.shutdown":
                await scope["state"]["_sm_cm"].__aexit__(None, None, None)
                await cache_service.disconnect()
                logger.info("Application services shut down")
                await send({"type": "lifespan.shutdown.complete"})
            return

        if scope["type"] != "http":
            return

        path = scope.get("path", "")

        if path == "/health":
            cache_ok = await cache_service.health_check()
            status = "ok" if cache_ok else "degraded"
            body = json.dumps({
                "status": status,
                "server": "threat-intel-mcp",
                "cache": "connected" if cache_ok else "unavailable",
            }).encode()
            await send({"type": "http.response.start", "status": 200, "headers": [
                [b"content-type", b"application/json"],
            ]})
            await send({"type": "http.response.body", "body": body})
            return

        if path in ("/mcp", "/mcp/"):
            await session_manager.handle_request(scope, receive, send)
            return

        body = json.dumps({"error": "not found"}).encode()
        await send({"type": "http.response.start", "status": 404, "headers": [
            [b"content-type", b"application/json"],
        ]})
        await send({"type": "http.response.body", "body": body})

    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    uvicorn_server = uvicorn.Server(config)
    await uvicorn_server.serve()
