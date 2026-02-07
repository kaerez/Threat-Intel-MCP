"""Transport implementations for MCP protocol."""

import asyncio
import sys
from typing import Any

import structlog
from mcp.server import Server
from mcp.server.stdio import stdio_server

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


async def run_http_sse_transport(server: Server, host: str, port: int) -> None:
    """
    Run MCP server using HTTP with Server-Sent Events transport.

    This transport is provided by the MCP SDK for HTTP-based clients.
    Note: The Ansvar platform uses a custom HTTP wrapper instead of this.

    Args:
        server: MCP server instance
        host: Host to bind to
        port: Port to bind to
    """
    logger.info(
        "HTTP/SSE transport not yet implemented - use stdio or custom HTTP wrapper",
        host=host,
        port=port,
    )
    raise NotImplementedError(
        "HTTP/SSE transport not yet implemented. "
        "Use --mode stdio for MCP clients or --mode http for Ansvar platform."
    )
