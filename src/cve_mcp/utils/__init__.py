"""Utility modules for CVE MCP server."""

from cve_mcp.utils.nvd_parser import parse_nvd_cve


def escape_like(value: str) -> str:
    """Escape LIKE/ILIKE wildcard characters in user input.

    Prevents % and _ from being interpreted as wildcards in SQL LIKE patterns.
    Uses \\ as the escape character (PostgreSQL default).

    Args:
        value: User-supplied search string

    Returns:
        String with %, _, and \\ escaped for safe use in LIKE clauses
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


__all__ = ["parse_nvd_cve", "escape_like"]
