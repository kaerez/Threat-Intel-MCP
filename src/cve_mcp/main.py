"""Main entry point for Threat Intel MCP server."""

import argparse
import asyncio
import sys

import structlog
import uvicorn

from cve_mcp.config import PROJECT_NAME, get_settings
from cve_mcp.mcp.server import create_mcp_server
from cve_mcp.mcp.transports import run_stdio_transport

logger = structlog.get_logger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{PROJECT_NAME} - CVE, ATT&CK, Cloud Security, and threat intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # MCP protocol over stdio (for Claude Desktop, Cursor, etc.)
  %(prog)s --mode stdio

  # HTTP REST API (for Ansvar platform)
  %(prog)s --mode http

  # Streamable HTTP transport (for ChatGPT, open-source MCP clients)
  %(prog)s --mode mcp-http

  # Both modes simultaneously (for development/testing)
  %(prog)s --mode both
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["stdio", "http", "mcp-http", "both"],
        default=None,
        help="Server mode: stdio (MCP clients), http (Ansvar platform), mcp-http (Streamable HTTP for universal MCP clients), or both (dev/test)",
    )

    parser.add_argument(
        "--host",
        default=None,
        help="Host to bind HTTP server (only used with --mode http or both)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port for HTTP server (only used with --mode http or both)",
    )

    return parser.parse_args()


async def run_stdio_mode() -> None:
    """Run server in stdio mode for MCP clients."""
    logger.info("Starting server in stdio mode", protocol="MCP", transport="stdio")

    # Create MCP server
    server = create_mcp_server()

    # Run with stdio transport
    await run_stdio_transport(server)


def run_http_mode(host: str, port: int) -> None:
    """
    Run server in HTTP mode for Ansvar platform.

    Args:
        host: Host to bind to
        port: Port to bind to
    """
    logger.info(
        "Starting server in HTTP mode",
        host=host,
        port=port,
        note="Using custom FastAPI wrapper (not MCP SDK HTTP transport)",
    )

    # Use uvicorn to run the FastAPI app (existing HTTP wrapper)
    uvicorn.run(
        "cve_mcp.api.app:app",
        host=host,
        port=port,
        reload=get_settings().log_level == "DEBUG",
        log_level=get_settings().log_level.lower(),
    )


async def run_both_modes(host: str, port: int) -> None:
    """
    Run server in both stdio and HTTP modes simultaneously.

    This is useful for development and testing where you want to:
    - Use Claude Desktop via stdio
    - Use HTTP endpoints for integration tests
    - Debug both transports at the same time

    Args:
        host: Host to bind HTTP server to
        port: Port to bind HTTP server to
    """
    logger.info(
        "Starting server in dual mode",
        modes=["stdio", "http"],
        http_host=host,
        http_port=port,
    )

    # Create tasks for both modes
    async def run_http() -> None:
        """Run HTTP server in async context."""
        config = uvicorn.Config(
            "cve_mcp.api.app:app",
            host=host,
            port=port,
            log_level=get_settings().log_level.lower(),
        )
        server = uvicorn.Server(config)
        await server.serve()

    # Run both modes concurrently
    await asyncio.gather(
        run_stdio_mode(),
        run_http(),
    )


def main() -> None:
    """Main entry point."""
    args = parse_args()
    settings = get_settings()

    # Determine mode from CLI args or settings
    mode = args.mode or settings.mcp_mode
    host = args.host or settings.mcp_host
    port = args.port or settings.mcp_port

    logger.info(
        "Starting Threat Intel MCP server",
        project=PROJECT_NAME,
        mode=mode,
        version="1.4.0",
    )

    try:
        if mode == "stdio":
            # Run stdio mode (MCP protocol)
            asyncio.run(run_stdio_mode())
        elif mode == "http":
            # Run HTTP mode (Ansvar platform)
            run_http_mode(host, port)
        elif mode == "mcp-http":
            # Run Streamable HTTP mode (universal MCP clients)
            from cve_mcp.mcp.transports import run_streamable_http_transport
            server = create_mcp_server()
            asyncio.run(run_streamable_http_transport(server.server, host, port))
        elif mode == "both":
            # Run both modes simultaneously
            asyncio.run(run_both_modes(host, port))
        else:
            logger.error(f"Invalid mode: {mode}. Must be 'stdio', 'http', 'mcp-http', or 'both'")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error("Server error", error=str(e), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
