"""Citation metadata helpers for MCP tool results.

The platform entity linker reads the ``_citation`` block from tool results
to match agent prose references to actual tool executions deterministically.
See ``services/citation/ledger.py`` in the agent service for the consumer.

Expected structure::

    {
        "canonical_ref": "CVE-2024-1234",
        "display_text": "CVE-2024-1234",
        "aliases": [],
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "tool_name": "get_cve_details",
        "params": {"cve_id": "CVE-2024-1234"}
    }

The ledger builder extracts ``canonical_ref``, ``display_text``, and
``aliases`` for entity linking. ``source_url``, ``tool_name``, and
``params`` are carried for display and debugging.
"""

from __future__ import annotations


def build_citation(
    canonical_ref: str,
    display_text: str,
    tool_name: str,
    params: dict,
    source_url: str | None = None,
    aliases: list[str] | None = None,
) -> dict:
    """Build a ``_citation`` metadata block for an MCP tool result.

    Args:
        canonical_ref: The authoritative identifier for the entity,
            e.g. ``"CVE-2024-1234"``, ``"T1566"``, ``"CWE-79"``.
        display_text: Human-readable label shown in the citation panel,
            e.g. ``"MITRE ATT&CK T1566"``.
        tool_name: The MCP tool name that produced this result,
            e.g. ``"get_cve_details"``.
        params: The parameters passed to the tool call, used for
            traceability.
        source_url: Optional canonical URL for the entity at its
            authoritative source (NVD, MITRE ATT&CK, CWE, etc.).
        aliases: Optional additional identifiers the entity is known by,
            used to widen entity-linker matching.

    Returns:
        A dict suitable for embedding as ``_citation`` in a tool result.
    """
    citation: dict = {
        "canonical_ref": canonical_ref,
        "display_text": display_text,
        "aliases": aliases or [],
        "tool_name": tool_name,
        "params": params,
    }
    if source_url is not None:
        citation["source_url"] = source_url
    return citation
