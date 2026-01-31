"""MITRE ATLAS YAML parser.

Parses ATLAS YAML data from MITRE ATLAS repository into database models.
ATLAS is the Adversarial Threat Landscape for AI Systems framework.

Note: ATLAS migrated from STIX 2.1 JSON to YAML format in late 2024.
"""

import logging
from datetime import date, datetime
from typing import Any

logger = logging.getLogger(__name__)


def _parse_date(date_value: date | datetime | str | None) -> datetime | None:
    """Parse date value to datetime object.

    Handles multiple input types from YAML parsing:
    - date objects (from PyYAML)
    - datetime objects
    - ISO 8601 strings (fallback)

    Args:
        date_value: Date in various formats

    Returns:
        datetime object or None if invalid
    """
    if date_value is None:
        return None

    if isinstance(date_value, datetime):
        return date_value

    if isinstance(date_value, date):
        return datetime.combine(date_value, datetime.min.time())

    if isinstance(date_value, str):
        # Handle ISO format strings as fallback
        try:
            if "T" in date_value:
                if "." in date_value:
                    return datetime.strptime(date_value, "%Y-%m-%dT%H:%M:%S.%fZ")
                else:
                    return datetime.strptime(date_value, "%Y-%m-%dT%H:%M:%SZ")
            else:
                return datetime.strptime(date_value, "%Y-%m-%d")
        except ValueError:
            logger.warning(f"Failed to parse date string: {date_value}")
            return None

    logger.warning(f"Unexpected date type: {type(date_value)}")
    return None


def parse_technique(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse ATLAS YAML technique object to technique data.

    New YAML format (2024+):
    {
        'id': 'AML.T0000',
        'name': 'Technique Name',
        'description': '...',
        'object-type': 'technique',
        'tactics': ['AML.TA0002'],
        'ATT&CK-reference': {'id': 'T1596', 'url': '...'},
        'created_date': date(2021, 5, 13),
        'modified_date': date(2025, 4, 9),
        'maturity': 'demonstrated'
    }

    Args:
        obj: ATLAS technique object from YAML

    Returns:
        Dictionary with technique data, or None if invalid
    """
    # Extract technique ID (required) - direct field in new format
    technique_id = obj.get("id")

    if not technique_id:
        logger.warning(f"ATLAS technique missing id: {obj.get('name', 'unknown')}")
        return None

    # Extract tactics - now a direct list of tactic IDs
    tactics = obj.get("tactics", [])

    # Extract ATT&CK reference if present
    attack_ref = obj.get("ATT&CK-reference")
    attack_technique_id = attack_ref.get("id") if attack_ref else None

    # Handle subtechniques (id format: AML.T0000.001)
    is_subtechnique = "." in technique_id.split("T")[-1] if "T" in technique_id else False
    parent_id = None
    if is_subtechnique:
        # Extract parent: AML.T0000.001 -> AML.T0000
        parts = technique_id.rsplit(".", 1)
        if len(parts) == 2:
            parent_id = parts[0]

    # Build technique data dictionary
    technique_data = {
        "technique_id": technique_id,
        "stix_id": None,  # No STIX ID in new format
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "tactics": tactics if tactics else None,
        "ml_lifecycle_stage": obj.get("ml-lifecycle-stage"),
        "ai_system_type": obj.get("platforms"),  # New field name
        "detection": obj.get("detection"),
        "mitigation": obj.get("mitigation"),
        "version": obj.get("version"),
        "created": _parse_date(obj.get("created_date")),
        "modified": _parse_date(obj.get("modified_date")),
        "deprecated": obj.get("deprecated", False),
        "revoked": obj.get("revoked", False),
        "stix_extensions": {
            "maturity": obj.get("maturity"),
            "attack_reference": attack_technique_id,
            "is_subtechnique": is_subtechnique,
            "parent_id": parent_id,
        },
    }

    return technique_data


def parse_tactic(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse ATLAS YAML tactic object to tactic data.

    New YAML format (2024+):
    {
        'id': 'AML.TA0002',
        'name': 'Resource Development',
        'description': '...',
        'object-type': 'tactic',
        'created_date': date(2021, 5, 13),
        'modified_date': date(2025, 4, 9)
    }

    Args:
        obj: ATLAS tactic object from YAML

    Returns:
        Dictionary with tactic data, or None if invalid
    """
    # Extract tactic ID (required) - direct field in new format
    tactic_id = obj.get("id")

    if not tactic_id:
        logger.warning(f"ATLAS tactic missing id: {obj.get('name', 'unknown')}")
        return None

    # Generate shortname from tactic name (lowercase, hyphenated)
    name = obj.get("name", "")
    shortname = name.lower().replace(" ", "-") if name else None

    # Build tactic data dictionary
    tactic_data = {
        "tactic_id": tactic_id,
        "stix_id": None,  # No STIX ID in new format
        "name": name,
        "shortname": shortname,
        "description": obj.get("description", ""),
        "created": _parse_date(obj.get("created_date")),
        "modified": _parse_date(obj.get("modified_date")),
    }

    return tactic_data


def parse_case_study(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Parse ATLAS YAML case study object to case study data.

    ATLAS case studies document real-world incidents involving AI/ML systems.

    New YAML format (2024+):
    {
        'id': 'AML.CS0000',
        'name': 'Case Study Name',
        'summary': '...',
        'object-type': 'case-study',
        'incident-date': date(2020, 1, 1),
        'incident-date-granularity': 'YEAR',
        'procedure': [...],
        'reporter': 'Organization Name',
        'target': 'Target System',
        'actor': 'Threat Actor',
        'case-study-type': 'incident',
        'references': [{'title': '...', 'url': '...'}],
        'created_date': date(2021, 5, 13),
        'modified_date': date(2025, 4, 9)
    }

    Args:
        obj: ATLAS case study object from YAML

    Returns:
        Dictionary with case study data, or None if invalid
    """
    # Extract case study ID (required) - direct field in new format
    case_study_id = obj.get("id")

    if not case_study_id:
        logger.warning(f"ATLAS case study missing id: {obj.get('name', 'unknown')}")
        return None

    # Extract techniques used from procedure steps
    techniques_used = []
    procedure = obj.get("procedure", [])
    for step in procedure:
        technique = step.get("technique")
        if technique:
            techniques_used.append(technique)

    # Extract reference URLs
    references = []
    for ref in obj.get("references", []):
        url = ref.get("url")
        if url:
            references.append(url)

    # Parse incident date
    incident_date = _parse_date(obj.get("incident-date"))

    # Build case study data dictionary
    case_study_data = {
        "case_study_id": case_study_id,
        "stix_id": None,  # No STIX ID in new format
        "name": obj.get("name", ""),
        "summary": obj.get("summary", ""),
        "incident_date": incident_date,
        "techniques_used": techniques_used if techniques_used else None,
        "target_system": obj.get("target"),
        "impact": obj.get("actor"),  # Map actor to impact for now
        "references": references if references else None,
        "version": obj.get("version"),
        "created": _parse_date(obj.get("created_date")),
        "modified": _parse_date(obj.get("modified_date")),
        "stix_extensions": {
            "reporter": obj.get("reporter"),
            "case_study_type": obj.get("case-study-type"),
            "incident_date_granularity": obj.get("incident-date-granularity"),
            "procedure": procedure,
        },
    }

    return case_study_data
