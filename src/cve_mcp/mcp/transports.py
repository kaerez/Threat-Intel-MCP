"""Transport implementations for MCP protocol."""

import asyncio

import structlog
from mcp.server import Server
from mcp.server.stdio import stdio_server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

logger = structlog.get_logger(__name__)


async def run_stdio_transport(server: Server) -> None:
    """
    Run MCP server using stdio transport (for Claude Desktop, Cursor, etc.).

    This transport reads JSON-RPC 2.0 messages from stdin and writes responses
    to stdout. stderr is used for logging.

    Args:
        server: MCP server instance
    """
    logger.info("Starting MCP server with stdio transport")
    logger.info(
        "Server ready for JSON-RPC 2.0 communication",
        protocol="MCP",
        transport="stdio",
    )

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


async def run_streamable_http_transport(server: Server, host: str, port: int) -> None:
    """
    Run MCP server using Streamable HTTP transport.

    This is the MCP-standard HTTP transport for universal client compatibility
    (ChatGPT, open-source MCP clients, web integrations). It uses the official
    MCP SDK's StreamableHTTPSessionManager for automatic session handling.

    The transport exposes:
    - POST /mcp   -- JSON-RPC requests (tool calls, tool listing)
    - GET  /mcp   -- SSE stream for server-initiated messages
    - DELETE /mcp -- Session termination
    - GET /health -- Health check for Docker/Azure probes

    Args:
        server: MCP server instance
        host: Host to bind to
        port: Port to bind to
    """
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    logger.info(
        "Starting MCP server with Streamable HTTP transport",
        host=host,
        port=port,
        endpoint="/mcp",
    )

    # StreamableHTTPSessionManager wraps the MCP server and manages
    # per-client sessions automatically (session creation, routing,
    # cleanup). json_response=True returns JSON instead of SSE for
    # simple request/response tool calls.
    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=True,
    )

    async def health_check(request: Request) -> JSONResponse:
        """Health check endpoint for Docker/Azure container probes."""
        return JSONResponse({"status": "ok", "server": "threat-intel-mcp"})

    app = Starlette(
        routes=[
            Route("/health", health_check, methods=["GET"]),
            Mount("/mcp", app=session_manager.handle_request),
        ],
    )

    import uvicorn

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
    )
    uvicorn_server = uvicorn.Server(config)

    await uvicorn_server.serve()
