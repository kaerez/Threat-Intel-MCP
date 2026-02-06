"""MITRE CWE XML parser.

Parses XML data from MITRE CWE repository into database models.
CWE is the Common Weakness Enumeration - a list of software and
hardware weakness types.

Note: CWE XML uses a default namespace (http://cwe.mitre.org/cwe-7).
All child element lookups must include the namespace prefix.
The `ns` parameter (e.g., "{http://cwe.mitre.org/cwe-7}") must be
passed to parser functions for correct element resolution.
"""

from typing import Any

from lxml import etree


def _get_text(element: etree._Element | None) -> str | None:
    """Extract text content from an XML element.

    Args:
        element: XML element or None

    Returns:
        Text content or None if element is None or has no text
    """
    if element is None:
        return None
    text = element.text
    if text:
        return text.strip()
    return None


def _get_all_text(element: etree._Element | None) -> str | None:
    """Extract all text content including nested elements.

    Args:
        element: XML element or None

    Returns:
        Concatenated text content from element and all descendants,
        or None if element is None or has no text
    """
    if element is None:
        return None

    # Use itertext to get all text content from element and descendants
    texts = list(element.itertext())
    if not texts:
        return None

    # Join and clean up whitespace
    full_text = " ".join(t.strip() for t in texts if t.strip())
    return full_text if full_text else None


def _extract_cwe_id(element: etree._Element) -> tuple[str | None, int | None]:
    """Extract CWE ID from element.

    Args:
        element: XML element with ID attribute

    Returns:
        Tuple of (formatted CWE ID like "CWE-79", numeric ID like 79)
    """
    id_str = element.get("ID")
    if not id_str:
        return None, None

    try:
        weakness_id = int(id_str)
        cwe_id = f"CWE-{weakness_id}"
        return cwe_id, weakness_id
    except ValueError:
        return None, None


def _parse_consequence(consequence_elem: etree._Element, ns: str = "") -> dict[str, Any] | None:
    """Parse a Consequence element.

    Args:
        consequence_elem: Consequence XML element
        ns: XML namespace prefix (e.g., "{http://cwe.mitre.org/cwe-7}")

    Returns:
        Dictionary with scope, impact, likelihood, note fields
    """
    result: dict[str, Any] = {}

    # Scope can have multiple values
    scopes = [_get_text(s) for s in consequence_elem.findall(f"{ns}Scope")]
    scopes = [s for s in scopes if s]
    if scopes:
        result["scope"] = scopes if len(scopes) > 1 else scopes[0]

    # Impact can have multiple values
    impacts = [_get_text(i) for i in consequence_elem.findall(f"{ns}Impact")]
    impacts = [i for i in impacts if i]
    if impacts:
        result["impact"] = impacts if len(impacts) > 1 else impacts[0]

    # Likelihood is optional
    likelihood = _get_text(consequence_elem.find(f"{ns}Likelihood"))
    if likelihood:
        result["likelihood"] = likelihood

    # Note is optional
    note = _get_all_text(consequence_elem.find(f"{ns}Note"))
    if note:
        result["note"] = note

    return result if result else None


def _parse_mitigation(mitigation_elem: etree._Element, ns: str = "") -> dict[str, Any] | None:
    """Parse a Mitigation element.

    Args:
        mitigation_elem: Mitigation XML element
        ns: XML namespace prefix

    Returns:
        Dictionary with phase, strategy, effectiveness, description fields
    """
    result: dict[str, Any] = {}

    # Phase can have multiple values
    phases = [_get_text(p) for p in mitigation_elem.findall(f"{ns}Phase")]
    phases = [p for p in phases if p]
    if phases:
        result["phase"] = phases if len(phases) > 1 else phases[0]

    # Strategy is optional
    strategy = _get_text(mitigation_elem.find(f"{ns}Strategy"))
    if strategy:
        result["strategy"] = strategy

    # Effectiveness is optional
    effectiveness = _get_text(mitigation_elem.find(f"{ns}Effectiveness"))
    if effectiveness:
        result["effectiveness"] = effectiveness

    # Description is optional but common
    description = _get_all_text(mitigation_elem.find(f"{ns}Description"))
    if description:
        result["description"] = description

    return result if result else None


def _parse_detection_method(detection_elem: etree._Element, ns: str = "") -> dict[str, Any] | None:
    """Parse a Detection_Method element.

    Args:
        detection_elem: Detection_Method XML element
        ns: XML namespace prefix

    Returns:
        Dictionary with method, effectiveness, description fields
    """
    result: dict[str, Any] = {}

    # Method is the primary field
    method = _get_text(detection_elem.find(f"{ns}Method"))
    if method:
        result["method"] = method

    # Effectiveness is optional
    effectiveness = _get_text(detection_elem.find(f"{ns}Effectiveness"))
    if effectiveness:
        result["effectiveness"] = effectiveness

    # Description is optional
    description = _get_all_text(detection_elem.find(f"{ns}Description"))
    if description:
        result["description"] = description

    return result if result else None


def _parse_relationships(
    related_weaknesses_elem: etree._Element | None,
    ns: str = "",
) -> dict[str, list[str]]:
    """Parse Related_Weaknesses element to extract relationships.

    Args:
        related_weaknesses_elem: Related_Weaknesses XML element
        ns: XML namespace prefix

    Returns:
        Dictionary with relationship types as keys and lists of CWE IDs as values
    """
    relationships: dict[str, list[str]] = {
        "parent_of": [],
        "child_of": [],
        "peer_of": [],
        "can_precede": [],
        "can_follow": [],
    }

    if related_weaknesses_elem is None:
        return relationships

    # Map XML Nature values to our relationship keys
    nature_map = {
        "ParentOf": "parent_of",
        "ChildOf": "child_of",
        "PeerOf": "peer_of",
        "CanPrecede": "can_precede",
        "CanFollow": "can_follow",
        "StartsWith": "can_follow",  # Map StartsWith to can_follow
        "CanAlsoBe": "peer_of",  # Map CanAlsoBe to peer_of
        "Requires": "child_of",  # Map Requires to child_of (dependency)
    }

    for related in related_weaknesses_elem.findall(f"{ns}Related_Weakness"):
        nature = related.get("Nature")
        cwe_id = related.get("CWE_ID")

        if nature and cwe_id:
            rel_key = nature_map.get(nature)
            if rel_key:
                relationships[rel_key].append(f"CWE-{cwe_id}")

    return relationships


def _parse_taxonomy_mappings(
    taxonomy_mappings_elem: etree._Element | None,
    ns: str = "",
) -> list[dict[str, Any]]:
    """Parse Taxonomy_Mappings element.

    Args:
        taxonomy_mappings_elem: Taxonomy_Mappings XML element
        ns: XML namespace prefix

    Returns:
        List of taxonomy mapping dictionaries
    """
    mappings: list[dict[str, Any]] = []

    if taxonomy_mappings_elem is None:
        return mappings

    for mapping in taxonomy_mappings_elem.findall(f"{ns}Taxonomy_Mapping"):
        taxonomy_name = mapping.get("Taxonomy_Name")
        if not taxonomy_name:
            continue

        entry: dict[str, Any] = {"taxonomy_name": taxonomy_name}

        entry_id = _get_text(mapping.find(f"{ns}Entry_ID"))
        if entry_id:
            entry["entry_id"] = entry_id

        entry_name = _get_text(mapping.find(f"{ns}Entry_Name"))
        if entry_name:
            entry["entry_name"] = entry_name

        mapping_fit = _get_text(mapping.find(f"{ns}Mapping_Fit"))
        if mapping_fit:
            entry["mapping_fit"] = mapping_fit

        mappings.append(entry)

    return mappings


def parse_weakness(element: etree._Element, ns: str = "") -> dict[str, Any] | None:
    """Parse a Weakness XML element.

    Args:
        element: CWE Weakness XML element
        ns: XML namespace prefix (e.g., "{http://cwe.mitre.org/cwe-7}")

    Returns:
        Dictionary with weakness data ready for CWEWeakness model,
        or None if invalid (missing ID or invalid format)
    """
    # Extract CWE ID
    cwe_id, weakness_id = _extract_cwe_id(element)
    if not cwe_id or weakness_id is None:
        return None

    # Basic fields (from XML attributes - never namespaced)
    name = element.get("Name")
    abstraction = element.get("Abstraction")
    status = element.get("Status")

    # Description and extended description (child elements - need namespace)
    description = _get_all_text(element.find(f"{ns}Description"))
    extended_description = _get_all_text(element.find(f"{ns}Extended_Description"))

    # Likelihood of exploit
    likelihood_of_exploit = _get_text(element.find(f"{ns}Likelihood_Of_Exploit"))

    # Parse consequences
    consequences: list[dict[str, Any]] = []
    common_consequences = element.find(f"{ns}Common_Consequences")
    if common_consequences is not None:
        for consequence in common_consequences.findall(f"{ns}Consequence"):
            parsed = _parse_consequence(consequence, ns)
            if parsed:
                consequences.append(parsed)

    # Parse mitigations
    mitigations: list[dict[str, Any]] = []
    potential_mitigations = element.find(f"{ns}Potential_Mitigations")
    if potential_mitigations is not None:
        for mitigation in potential_mitigations.findall(f"{ns}Mitigation"):
            parsed = _parse_mitigation(mitigation, ns)
            if parsed:
                mitigations.append(parsed)

    # Parse detection methods
    detection_methods: list[dict[str, Any]] = []
    detection_methods_elem = element.find(f"{ns}Detection_Methods")
    if detection_methods_elem is not None:
        for detection in detection_methods_elem.findall(f"{ns}Detection_Method"):
            parsed = _parse_detection_method(detection, ns)
            if parsed:
                detection_methods.append(parsed)

    # Parse relationships
    related_weaknesses = element.find(f"{ns}Related_Weaknesses")
    relationships = _parse_relationships(related_weaknesses, ns)

    # Parse taxonomy mappings
    taxonomy_mappings_elem = element.find(f"{ns}Taxonomy_Mappings")
    taxonomy_mappings = _parse_taxonomy_mappings(taxonomy_mappings_elem, ns)

    return {
        "cwe_id": cwe_id,
        "weakness_id": weakness_id,
        "name": name,
        "description": description,
        "extended_description": extended_description,
        "abstraction": abstraction,
        "status": status,
        "likelihood_of_exploit": likelihood_of_exploit,
        "common_consequences": consequences if consequences else None,
        "potential_mitigations": mitigations if mitigations else None,
        "detection_methods": detection_methods if detection_methods else None,
        "parent_of": relationships["parent_of"] if relationships["parent_of"] else None,
        "child_of": relationships["child_of"] if relationships["child_of"] else None,
        "peer_of": relationships["peer_of"] if relationships["peer_of"] else None,
        "can_precede": (
            relationships["can_precede"] if relationships["can_precede"] else None
        ),
        "can_follow": (
            relationships["can_follow"] if relationships["can_follow"] else None
        ),
        "taxonomy_mappings": taxonomy_mappings if taxonomy_mappings else None,
        "deprecated": status == "Deprecated",
    }


def parse_category(element: etree._Element, ns: str = "") -> dict[str, Any] | None:
    """Parse a Category XML element.

    Args:
        element: CWE Category XML element
        ns: XML namespace prefix

    Returns:
        Dictionary with category data ready for CWECategory model,
        or None if invalid (missing ID)
    """
    # Extract category ID
    id_str = element.get("ID")
    if not id_str:
        return None

    try:
        category_id_num = int(id_str)
    except ValueError:
        return None

    category_id = f"CWE-{category_id_num}"
    name = element.get("Name")
    status = element.get("Status")

    # Summary is in the Summary element
    summary = _get_all_text(element.find(f"{ns}Summary"))

    # Get member weaknesses
    relationships = element.find(f"{ns}Relationships")
    members: list[str] = []
    if relationships is not None:
        for member in relationships.findall(f"{ns}Has_Member"):
            cwe_id = member.get("CWE_ID")
            if cwe_id:
                members.append(f"CWE-{cwe_id}")

    return {
        "category_id": category_id,
        "name": name,
        "summary": summary,
        "status": status,
        "members": members if members else None,
    }


def parse_view(element: etree._Element, ns: str = "") -> dict[str, Any] | None:
    """Parse a View XML element.

    Args:
        element: CWE View XML element
        ns: XML namespace prefix

    Returns:
        Dictionary with view data ready for CWEView model,
        or None if invalid (missing ID)
    """
    # Extract view ID
    id_str = element.get("ID")
    if not id_str:
        return None

    try:
        view_id_num = int(id_str)
    except ValueError:
        return None

    view_id = f"CWE-{view_id_num}"
    name = element.get("Name")
    view_type = element.get("Type")
    status = element.get("Status")

    # Objective describes the view's purpose
    objective = _get_all_text(element.find(f"{ns}Objective"))

    # Get member weaknesses from the view
    members_elem = element.find(f"{ns}Members")
    members: list[str] = []
    if members_elem is not None:
        for member in members_elem.findall(f"{ns}Has_Member"):
            cwe_id = member.get("CWE_ID")
            if cwe_id:
                members.append(f"CWE-{cwe_id}")

    return {
        "view_id": view_id,
        "name": name,
        "view_type": view_type,
        "status": status,
        "objective": objective,
        "members": members if members else None,
    }


def parse_external_mapping(
    weakness_id: str, mapping_data: dict[str, Any]
) -> dict[str, Any] | None:
    """Parse a taxonomy mapping for external framework references.

    This function processes taxonomy mappings to extract OWASP, SANS,
    and other external framework references.

    Args:
        weakness_id: CWE ID (e.g., "CWE-79")
        mapping_data: Dictionary containing taxonomy mapping data

    Returns:
        Dictionary with external mapping data, or None if invalid
    """
    if not weakness_id or not mapping_data:
        return None

    taxonomy_name = mapping_data.get("taxonomy_name")
    if not taxonomy_name:
        return None

    entry_id = mapping_data.get("entry_id")
    entry_name = mapping_data.get("entry_name")

    # Determine the framework type from taxonomy name
    framework_type = None
    if "OWASP" in taxonomy_name:
        framework_type = "owasp"
    elif "SANS" in taxonomy_name or "CWE Top 25" in taxonomy_name:
        framework_type = "sans"
    elif "CERT" in taxonomy_name:
        framework_type = "cert"
    elif "NIST" in taxonomy_name:
        framework_type = "nist"

    return {
        "weakness_id": weakness_id,
        "taxonomy_name": taxonomy_name,
        "entry_id": entry_id,
        "entry_name": entry_name,
        "framework_type": framework_type,
        "mapping_fit": mapping_data.get("mapping_fit"),
    }
