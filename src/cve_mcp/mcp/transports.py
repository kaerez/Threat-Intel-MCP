"""Transport implementations for MCP protocol."""

import asyncio
import json

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
    MCP SDK's StreamableHTTPServerTransport.

    The transport exposes:
    - POST /mcp   — JSON-RPC requests (tool calls, tool listing)
    - GET  /mcp   — SSE stream for server-initiated messages
    - DELETE /mcp — Session termination
    - GET /health — Health check for Docker/Azure probes

    Args:
        server: MCP server instance
        host: Host to bind to
        port: Port to bind to
    """
    from mcp.server.streamable_http import StreamableHTTPServerTransport

    logger.info(
        "Starting MCP server with Streamable HTTP transport",
        host=host,
        port=port,
        endpoint="/mcp",
    )

    # Create the Streamable HTTP transport.
    # mcp_endpoint="/" because the Starlette Mount at "/mcp" already
    # provides the path prefix. Using "/" here avoids a /mcp/mcp path.
    transport = StreamableHTTPServerTransport(
        mcp_endpoint="/",
        is_json_response_enabled=True,
    )

    async def health_check(request: Request) -> JSONResponse:
        """Health check endpoint for Docker/Azure container probes."""
        return JSONResponse({"status": "ok", "server": "threat-intel-mcp"})

    app = Starlette(
        routes=[
            Route("/health", health_check, methods=["GET"]),
            Mount("/mcp", app=transport.asgi_app),
        ],
    )

    # Start serving in background, then connect server to transport
    import uvicorn

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
    )
    uvicorn_server = uvicorn.Server(config)

    # Run uvicorn and MCP server connection concurrently
    async def serve_mcp() -> None:
        """Connect MCP server to the transport after HTTP is ready."""
        # Small delay to let uvicorn start
        await asyncio.sleep(0.5)
        logger.info("Connecting MCP server to Streamable HTTP transport")
        await server.run(
            transport.read_stream,
            transport.write_stream,
            server.create_initialization_options(),
        )

    await asyncio.gather(
        uvicorn_server.serve(),
        serve_mcp(),
    )
