"""MITRE D3FEND MISP Galaxy JSON parser.

Parses MISP Galaxy JSON format containing D3FEND techniques into database models.
D3FEND is the Detection, Denial, and Disruption Framework Empowering Network Defense.
"""


def normalize_d3fend_id(external_id: str | None) -> str | None:
    """Normalize D3FEND ID to standard format (D3-XX).

    Args:
        external_id: D3FEND ID in various formats

    Returns:
        Normalized ID or original value for edge cases

    Examples:
        - "d3f:D3-AH" -> "D3-AH"
        - "d3-ah" -> "D3-AH"
        - None -> None
        - "" -> ""
    """
    if external_id is None:
        return None

    if external_id == "":
        return ""

    # Remove d3f: prefix if present
    normalized = external_id
    if normalized.lower().startswith("d3f:"):
        normalized = normalized[4:]

    # Uppercase the ID
    return normalized.upper()


def parse_tactic_from_kill_chain(kill_chain: list[str] | None) -> str | None:
    """Extract tactic ID from kill_chain array.

    Args:
        kill_chain: List of kill chain entries like ["d3fend:Harden"]

    Returns:
        Tactic ID in D3-XXX format or None if not found

    Examples:
        - ["d3fend:Harden"] -> "D3-HARDEN"
        - ["mitre-d3fend:Model"] -> "D3-MODEL"
        - [] -> None
        - None -> None
    """
    if not kill_chain:
        return None

    # Take the first entry
    first_entry = kill_chain[0]

    # Extract the tactic name after the colon
    if ":" in first_entry:
        tactic_name = first_entry.split(":")[-1]
    else:
        tactic_name = first_entry

    # Format as D3-TACTIC in uppercase
    return f"D3-{tactic_name.upper()}"


def extract_attack_mappings(related: list[dict] | None) -> list[dict]:
    """Extract ATT&CK technique mappings from related array.

    Look for tags like "attack-technique:T1059" in related entries.

    Args:
        related: List of related entries with dest-uuid, type, and tags

    Returns:
        List of {"attack_technique_id": "T1059", "relationship_type": "counters"}
        Skip entries without attack-technique tags.
    """
    if not related:
        return []

    mappings = []

    for entry in related:
        tags = entry.get("tags", [])
        relationship_type = entry.get("type")

        for tag in tags:
            # Look for attack-technique: prefix
            if tag.startswith("attack-technique:"):
                technique_id = tag.replace("attack-technique:", "")
                mappings.append(
                    {
                        "attack_technique_id": technique_id,
                        "relationship_type": relationship_type,
                    }
                )
                break  # Only take first attack-technique tag per entry

    return mappings


def parse_technique(entry: dict) -> dict:
    """Parse a single D3FEND technique from MISP Galaxy format.

    Args:
        entry: MISP Galaxy value entry containing technique data

    Returns:
        Dictionary with parsed technique data:
        - technique_id: normalized ID
        - name: from entry["value"]
        - description: from entry["description"]
        - tactic_id: extracted from kill_chain
        - synonyms: from meta.synonyms
        - references: non-d3fend refs as [{"url": ...}]
        - kb_article_url: d3fend.mitre.org ref
        - attack_mappings: extracted ATT&CK mappings
    """
    meta = entry.get("meta", {})

    # Normalize the external_id
    technique_id = normalize_d3fend_id(meta.get("external_id"))

    # Extract tactic from kill_chain
    tactic_id = parse_tactic_from_kill_chain(meta.get("kill_chain"))

    # Get synonyms
    synonyms = meta.get("synonyms")

    # Process references - separate d3fend.mitre.org URL from other refs
    refs = meta.get("refs", [])
    kb_article_url = None
    references = []

    for ref in refs:
        if "d3fend.mitre.org" in ref:
            kb_article_url = ref
        else:
            references.append({"url": ref})

    # Extract ATT&CK mappings
    attack_mappings = extract_attack_mappings(entry.get("related"))

    return {
        "technique_id": technique_id,
        "name": entry.get("value"),
        "description": entry.get("description"),
        "tactic_id": tactic_id,
        "synonyms": synonyms,
        "references": references,
        "kb_article_url": kb_article_url,
        "attack_mappings": attack_mappings,
    }
