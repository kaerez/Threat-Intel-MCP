"""Main entry point for CVE MCP server."""

import uvicorn

from cve_mcp.config import get_settings


def main() -> None:
    """Run the CVE MCP server."""
    settings = get_settings()

    uvicorn.run(
        "cve_mcp.api.app:app",
        host=settings.mcp_host,
        port=settings.mcp_port,
        reload=settings.log_level == "DEBUG",
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
