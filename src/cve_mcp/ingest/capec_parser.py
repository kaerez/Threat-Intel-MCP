"""MITRE CAPEC STIX 2.1 parser.

Parses STIX bundles from MITRE CAPEC repository into database models.
CAPEC is the Common Attack Pattern Enumeration and Classification framework.
"""

from datetime import datetime
from typing import Any


def _parse_datetime(dt_str: str) -> datetime:
    """Parse STIX datetime string to datetime object.

    Args:
        dt_str: ISO 8601 datetime string (e.g., "2022-01-01T00:00:00.000Z")

    Returns:
        datetime object
    """
    # Handle both with and without milliseconds
    if "." in dt_str:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ")


def _extract_external_id(external_refs: list[dict], source: str = "capec") -> str | None:
    """Extract external ID from STIX external_references.

    Args:
        external_refs: List of external reference objects
        source: Source name to filter by (default: "capec")

    Returns:
        External ID (e.g., "CAPEC-66" or "66") or None if not found
    """
    for ref in external_refs:
        if ref.get("source_name") == source and "external_id" in ref:
            return ref["external_id"]
    return None


def _extract_capec_id(pattern_id: str) -> int | None:
    """Extract numeric CAPEC ID from pattern_id string.

    Args:
        pattern_id: Pattern ID like "CAPEC-1" or "1"

    Returns:
        Integer CAPEC ID or None if invalid
    """
    if not pattern_id:
        return None

    # Remove "CAPEC-" prefix if present
    if pattern_id.startswith("CAPEC-"):
        pattern_id = pattern_id[6:]

    try:
        return int(pattern_id)
    except ValueError:
        return None


def parse_attack_pattern(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse CAPEC attack pattern from STIX attack-pattern.

    Args:
        stix_obj: STIX 2.1 attack-pattern object

    Returns:
        Dictionary with pattern data ready for CAPECPattern model,
        or None if invalid (missing CAPEC ID or invalid format)
    """
    external_refs = stix_obj.get("external_references", [])
    pattern_id = _extract_external_id(external_refs, "capec")

    if not pattern_id:
        # No CAPEC ID found
        return None

    # Extract numeric CAPEC ID
    capec_id = _extract_capec_id(pattern_id)
    if capec_id is None:
        return None

    # Ensure pattern_id has CAPEC- prefix
    if not pattern_id.startswith("CAPEC-"):
        pattern_id = f"CAPEC-{pattern_id}"

    # Extract CAPEC-specific fields with x_capec_ prefix
    abstraction = stix_obj.get("x_capec_abstraction")
    status = stix_obj.get("x_capec_status")
    extended_description = stix_obj.get("x_capec_extended_description")
    likelihood = stix_obj.get("x_capec_likelihood_of_attack")
    severity = stix_obj.get("x_capec_typical_severity")

    # Extract prerequisites (list of strings)
    prerequisites = stix_obj.get("x_capec_prerequisites", [])

    # Extract skills required (dict of skill: level)
    skills_required = stix_obj.get("x_capec_skills_required")

    # Extract parent/child relationships
    parent_of = stix_obj.get("x_capec_parent_of_refs", [])
    child_of = stix_obj.get("x_capec_child_of_refs", [])
    can_precede = stix_obj.get("x_capec_can_precede_refs", [])
    can_follow = stix_obj.get("x_capec_can_follow_refs", [])
    peer_of = stix_obj.get("x_capec_peer_of_refs", [])

    # Extract consequences
    consequences = stix_obj.get("x_capec_consequences")

    # Extract examples
    example_instances = stix_obj.get("x_capec_example_instances", [])

    # Extract execution flow
    execution_flow = stix_obj.get("x_capec_execution_flow")

    return {
        "pattern_id": pattern_id,
        "capec_id": capec_id,
        "stix_id": stix_obj.get("id"),
        "name": stix_obj.get("name"),
        "description": stix_obj.get("description", ""),
        "abstraction": abstraction,
        "status": status,
        "extended_description": extended_description,
        "likelihood_of_attack": likelihood,
        "typical_severity": severity,
        "prerequisites": prerequisites if prerequisites else None,
        "skills_required": skills_required,
        "parent_of": parent_of if parent_of else None,
        "child_of": child_of if child_of else None,
        "can_precede": can_precede if can_precede else None,
        "can_follow": can_follow if can_follow else None,
        "peer_of": peer_of if peer_of else None,
        "consequences": consequences,
        "mitigation_refs": [],  # Will be populated from relationships
        "example_instances": example_instances if example_instances else None,
        "execution_flow": execution_flow,
        "version": stix_obj.get("x_capec_version"),
        "created": _parse_datetime(stix_obj.get("created")),
        "modified": _parse_datetime(stix_obj.get("modified")),
        "deprecated": stix_obj.get("x_capec_status") == "Deprecated",
        "revoked": stix_obj.get("revoked", False),
        "stix_extensions": stix_obj,
    }


def parse_category(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse CAPEC category from STIX x-capec-category or grouping object.

    Args:
        stix_obj: STIX 2.1 category object (x-capec-category or grouping type)

    Returns:
        Dictionary with category data ready for CAPECCategory model,
        or None if invalid (missing CAPEC ID)
    """
    external_refs = stix_obj.get("external_references", [])
    category_id = _extract_external_id(external_refs, "capec")

    if not category_id:
        return None

    # Ensure category_id has CAPEC- prefix
    if not category_id.startswith("CAPEC-"):
        category_id = f"CAPEC-{category_id}"

    return {
        "category_id": category_id,
        "stix_id": stix_obj.get("id"),
        "name": stix_obj.get("name"),
        "summary": stix_obj.get("description", ""),
        "created": _parse_datetime(stix_obj.get("created")),
        "modified": _parse_datetime(stix_obj.get("modified")),
    }


def parse_mitigation(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse CAPEC mitigation from STIX course-of-action.

    Args:
        stix_obj: STIX 2.1 course-of-action object

    Returns:
        Dictionary with mitigation data ready for CAPECMitigation model,
        or None if invalid (missing STIX ID)
    """
    # Use STIX ID as mitigation_id (no CAPEC ID for mitigations)
    stix_id = stix_obj.get("id")

    if not stix_id:
        return None

    # Generate friendly mitigation ID from STIX ID
    # e.g., "course-of-action--abc123" -> "COA-abc123"
    mitigation_id = stix_id.replace("course-of-action--", "COA-")

    return {
        "mitigation_id": mitigation_id,
        "stix_id": stix_id,
        "name": stix_obj.get("name"),
        "description": stix_obj.get("description", ""),
        "version": stix_obj.get("x_capec_version"),
        "created": _parse_datetime(stix_obj.get("created")),
        "modified": _parse_datetime(stix_obj.get("modified")),
    }
