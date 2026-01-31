"""MITRE ATLAS STIX 2.1 parser.

Parses STIX bundles from MITRE ATLAS repository into database models.
ATLAS is the Adversarial Threat Landscape for AI Systems framework.
"""

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def _parse_datetime(dt_str: str) -> datetime:
    """Parse STIX datetime string to datetime object.

    Args:
        dt_str: ISO 8601 datetime string (e.g., "2022-03-01T14:00:00.000Z")

    Returns:
        datetime object
    """
    # Handle both with and without milliseconds
    if "." in dt_str:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ")


def _extract_external_id(external_refs: list[dict[str, Any]], source: str = "ATLAS") -> str | None:
    """Extract external ID from STIX external_references.

    Args:
        external_refs: List of external reference objects
        source: Source name to filter by (default: "ATLAS")

    Returns:
        External ID (e.g., "AML.T0010") or None if not found
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
        List of tactic names (e.g., ["reconnaissance", "ml-attack-staging"])
    """
    if not kill_chain_phases:
        return []

    tactics = []
    for phase in kill_chain_phases:
        # ATLAS uses "mitre-atlas" as kill chain name
        if phase.get("kill_chain_name") == "mitre-atlas":
            tactics.append(phase["phase_name"])

    return tactics


def _extract_references(external_refs: list[dict[str, Any]], source: str = "ATLAS") -> list[str]:
    """Extract reference URLs from external_references (excluding the primary source).

    Args:
        external_refs: List of external reference objects
        source: Primary source name to exclude (default: "ATLAS")

    Returns:
        List of reference URLs
    """
    references = []
    for ref in external_refs:
        if ref.get("source_name") != source and "url" in ref:
            references.append(ref["url"])
    return references


def parse_technique(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX attack-pattern object to ATLAS technique data.

    Args:
        stix_obj: STIX attack-pattern object

    Returns:
        Dictionary with technique data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    technique_id = _extract_external_id(external_refs)

    if not technique_id:
        logger.warning(f"ATLAS technique missing external_id: {stix_obj.get('id')}")
        return None

    # Extract tactics from kill_chain_phases
    tactics = _extract_tactics(stix_obj.get("kill_chain_phases"))

    # ATLAS uses x_mitre_platforms for AI system types (e.g., "computer-vision", "nlp")
    ai_system_type = stix_obj.get("x_mitre_platforms")

    # Build technique data dictionary
    technique_data = {
        "technique_id": technique_id,
        "stix_id": stix_obj["id"],
        "name": stix_obj["name"],
        "description": stix_obj["description"],
        "tactics": tactics if tactics else None,
        "ml_lifecycle_stage": stix_obj.get("x_mitre_ml_lifecycle_stage"),
        "ai_system_type": ai_system_type,
        "detection": stix_obj.get("x_mitre_detection"),
        "mitigation": stix_obj.get("x_mitre_mitigation"),
        "version": stix_obj.get("x_mitre_version"),
        "created": _parse_datetime(stix_obj["created"]),
        "modified": _parse_datetime(stix_obj["modified"]),
        "deprecated": stix_obj.get("x_mitre_deprecated", False),
        "revoked": stix_obj.get("revoked", False),
        "stix_extensions": stix_obj,  # Store full STIX object for flexibility
    }

    return technique_data


def parse_tactic(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX x-mitre-tactic object to ATLAS tactic data.

    Args:
        stix_obj: STIX x-mitre-tactic object

    Returns:
        Dictionary with tactic data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    tactic_id = _extract_external_id(external_refs)

    if not tactic_id:
        logger.warning(f"ATLAS tactic missing external_id: {stix_obj.get('id')}")
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


def parse_case_study(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse STIX case study object to ATLAS case study data.

    ATLAS case studies document real-world incidents involving AI/ML systems.

    Args:
        stix_obj: STIX x-mitre-case-study object

    Returns:
        Dictionary with case study data, or None if invalid
    """
    # Extract external ID (required)
    external_refs = stix_obj.get("external_references", [])
    case_study_id = _extract_external_id(external_refs)

    if not case_study_id:
        logger.warning(f"ATLAS case study missing external_id: {stix_obj.get('id')}")
        return None

    # Extract techniques used (list of technique IDs)
    techniques_used = stix_obj.get("x_mitre_techniques")

    # Extract references (URLs from external_references, excluding ATLAS source)
    references = _extract_references(external_refs)

    # Build case study data dictionary
    case_study_data = {
        "case_study_id": case_study_id,
        "stix_id": stix_obj["id"],
        "name": stix_obj["name"],
        "summary": stix_obj["description"],  # ATLAS uses description field for summary
        "incident_date": None,  # May be parsed from metadata if available
        "techniques_used": techniques_used,
        "target_system": stix_obj.get("x_mitre_target_system"),
        "impact": stix_obj.get("x_mitre_impact"),
        "references": references if references else None,
        "version": stix_obj.get("x_mitre_version"),
        "created": _parse_datetime(stix_obj["created"]),
        "modified": _parse_datetime(stix_obj["modified"]),
        "stix_extensions": stix_obj,
    }

    return case_study_data
