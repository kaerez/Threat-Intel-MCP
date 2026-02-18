"""Transport implementations for MCP protocol."""

import asyncio

import structlog
from mcp.server import Server
from mcp.server.stdio import stdio_server
from starlette.applications import Starlette
from starlette.routing import Mount

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

    The transport exposes a single /mcp endpoint that handles:
    - POST /mcp - JSON-RPC requests (tool calls, tool listing)
    - GET /mcp - SSE stream for server-initiated messages
    - DELETE /mcp - Session termination

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

    # Create the Streamable HTTP transport
    transport = StreamableHTTPServerTransport(
        mcp_endpoint="/mcp",
        is_json_response_enabled=True,
    )

    # Mount the transport's ASGI app under /mcp
    app = Starlette(
        routes=[
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
