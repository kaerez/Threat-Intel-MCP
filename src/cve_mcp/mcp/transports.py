"""Transport implementations for MCP protocol."""

import asyncio
import json

import structlog
import uvicorn
from mcp.server import Server
from mcp.server.stdio import stdio_server

logger = structlog.get_logger(__name__)


async def run_stdio_transport(server: Server) -> None:
    """Run MCP server using stdio transport (for Claude Desktop, Cursor, etc.)."""
    logger.info("Starting MCP server with stdio transport")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


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
        """Raw ASGI app: routes /mcp and /health."""
        if scope["type"] == "lifespan":
            # Accept lifespan events (uvicorn sends these)
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return

        if scope["type"] != "http":
            return

        path = scope.get("path", "")

        if path == "/health":
            body = json.dumps({"status": "ok", "server": "threat-intel-mcp"}).encode()
            await send({"type": "http.response.start", "status": 200, "headers": [
                [b"content-type", b"application/json"],
            ]})
            await send({"type": "http.response.body", "body": body})
            return

        if path in ("/mcp", "/mcp/"):
            # Normalize path to /mcp for the session manager
            scope["path"] = "/mcp"
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
