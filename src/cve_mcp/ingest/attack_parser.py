"""MITRE ATT&CK STIX 2.1 parser.

Parses STIX bundles from MITRE ATT&CK CTI repository into database models.
"""

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def _parse_datetime(dt_str: str) -> datetime:
    """Parse STIX datetime string to datetime object.

    Args:
        dt_str: ISO 8601 datetime string (e.g., "2020-03-11T14:26:15.113Z")

    Returns:
        datetime object
    """
    # Handle both with and without milliseconds
    if "." in dt_str:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ")


def _extract_external_id(external_refs: list[dict[str, Any]], source: str = "mitre-attack") -> str | None:
    """Extract external ID from STIX external_references.

    Args:
        external_refs: List of external reference objects
        source: Source name to filter by (default: "mitre-attack")

    Returns:
        External ID (e.g., "T1566.001") or None if not found
    """
    for ref in external_refs:
        if ref.get("source_name") == source and "external_id" in ref:
            return ref["external_id"]
    return None


def _extract_tactics(kill_chain_phases: list[dict[str, Any]] | None) -> list[str]:
    """Extract tactic names from kill_chain_phases.

    Args:
        kill_chain_phases: List of kill chain phase objects

    Returns:
        List of tactic names (e.g., ["initial-access", "execution"])
    """
    if not kill_chain_phases:
        return []

    tactics = []
    for phase in kill_chain_phases:
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase["phase_name"])

    return tactics


def _extract_parent_id(technique_id: str, is_subtechnique: bool) -> str | None:
    """Extract parent technique ID from subtechnique ID.

    Args:
        technique_id: Technique ID (e.g., "T1566.001")
        is_subtechnique: Whether this is a subtechnique

    Returns:
        Parent ID (e.g., "T1566") or None if not a subtechnique
    """
    if not is_subtechnique or "." not in technique_id:
        return None

    return technique_id.split(".")[0]


def parse_technique(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX attack-pattern object to technique data.

    Args:
        stix_obj: STIX attack-pattern object

    Returns:
        Dictionary with technique data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    technique_id = _extract_external_id(external_refs)

    if not technique_id:
        logger.warning(f"Technique missing external_id: {stix_obj.get('id')}")
        return None

    # Determine if subtechnique
    is_subtechnique = stix_obj.get("x_mitre_is_subtechnique", False)
    parent_id = _extract_parent_id(technique_id, is_subtechnique)

    # Extract tactics from kill_chain_phases
    tactics = _extract_tactics(stix_obj.get("kill_chain_phases"))

    # Build technique data dictionary
    technique_data = {
        "technique_id": technique_id,
        "stix_id": stix_obj["id"],
        "name": stix_obj["name"],
        "description": stix_obj["description"],
        "is_subtechnique": is_subtechnique,
        "parent_technique_id": parent_id,
        "tactics": tactics if tactics else None,
        "platforms": stix_obj.get("x_mitre_platforms"),
        "data_sources": stix_obj.get("x_mitre_data_sources"),
        "detection": stix_obj.get("x_mitre_detection"),
        "permissions_required": stix_obj.get("x_mitre_permissions_required"),
        "effective_permissions": stix_obj.get("x_mitre_effective_permissions"),
        "version": stix_obj.get("x_mitre_version"),
        "created": _parse_datetime(stix_obj["created"]),
        "modified": _parse_datetime(stix_obj["modified"]),
        "deprecated": stix_obj.get("x_mitre_deprecated", False),
        "revoked": stix_obj.get("revoked", False),
        "stix_extensions": stix_obj,  # Store full STIX object for flexibility
    }

    return technique_data


def parse_group(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX intrusion-set object to threat actor group data.

    Args:
        stix_obj: STIX intrusion-set object

    Returns:
        Dictionary with group data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    group_id = _extract_external_id(external_refs)

    if not group_id:
        logger.warning(f"Group missing external_id: {stix_obj.get('id')}")
        return None

    # Get aliases (may be empty)
    aliases = stix_obj.get("aliases", [])
    if not aliases:
        aliases = None

    # Build group data dictionary
    group_data = {
        "group_id": group_id,
        "stix_id": stix_obj["id"],
        "name": stix_obj["name"],
        "description": stix_obj["description"],
        "aliases": aliases,
        "version": stix_obj.get("x_mitre_version"),
        "created": _parse_datetime(stix_obj["created"]),
        "modified": _parse_datetime(stix_obj["modified"]),
        "revoked": stix_obj.get("revoked", False),
        "stix_extensions": stix_obj,
    }

    return group_data


def parse_tactic(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX x-mitre-tactic object to tactic data.

    Args:
        stix_obj: STIX x-mitre-tactic object

    Returns:
        Dictionary with tactic data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    tactic_id = _extract_external_id(external_refs)

    if not tactic_id:
        logger.warning(f"Tactic missing external_id: {stix_obj.get('id')}")
        return None

    # Build tactic data dictionary
    tactic_data = {
        "tactic_id": tactic_id,
        "stix_id": stix_obj["id"],
        "name": stix_obj["name"],
        "shortname": stix_obj["x_mitre_shortname"],
        "description": stix_obj["description"],
        "created": _parse_datetime(stix_obj["created"]),
        "modified": _parse_datetime(stix_obj["modified"]),
    }

    return tactic_data


def parse_software(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX malware/tool object to software data.

    Args:
        stix_obj: STIX malware or tool object

    Returns:
        Dictionary with software data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    software_id = _extract_external_id(external_refs)

    if not software_id:
        logger.warning(f"Software missing external_id: {stix_obj.get('id')}")
        return None

    # Determine software type from STIX type
    software_type = stix_obj["type"]  # "malware" or "tool"

    # Get aliases
    aliases = stix_obj.get("x_mitre_aliases", [])
    if not aliases:
        aliases = None

    # Build software data dictionary
    software_data = {
        "software_id": software_id,
        "stix_id": stix_obj["id"],
        "name": stix_obj["name"],
        "software_type": software_type,
        "description": stix_obj["description"],
        "aliases": aliases,
        "platforms": stix_obj.get("x_mitre_platforms"),
        "version": stix_obj.get("x_mitre_version"),
        "created": _parse_datetime(stix_obj["created"]),
        "modified": _parse_datetime(stix_obj["modified"]),
        "revoked": stix_obj.get("revoked", False),
        "stix_extensions": stix_obj,
    }

    return software_data


def parse_mitigation(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX course-of-action object to mitigation data.

    Args:
        stix_obj: STIX course-of-action object

    Returns:
        Dictionary with mitigation data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    mitigation_id = _extract_external_id(external_refs)

    if not mitigation_id:
        logger.warning(f"Mitigation missing external_id: {stix_obj.get('id')}")
        return None

    # Build mitigation data dictionary
    mitigation_data = {
        "mitigation_id": mitigation_id,
        "stix_id": stix_obj["id"],
        "name": stix_obj["name"],
        "description": stix_obj["description"],
        "version": stix_obj.get("x_mitre_version"),
        "created": _parse_datetime(stix_obj["created"]),
        "modified": _parse_datetime(stix_obj["modified"]),
    }

    return mitigation_data
