"""MITRE D3FEND MISP Galaxy JSON parser.

Parses MISP Galaxy JSON format containing D3FEND techniques into database models.
D3FEND is the Detection, Denial, and Disruption Framework Empowering Network Defense.

Also parses the D3FEND ontology JSON to extract D3FEND→ATT&CK mappings through
shared digital artifacts.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Properties on D3FEND technique entries that represent artifact relationships
# (exclude metadata properties)
_D3FEND_METADATA_PROPS = frozenset({
    "d3f:d3fend-id", "d3f:definition", "d3f:synonym", "d3f:kb-article",
    "d3f:kb-reference", "d3f:todo", "d3f:attack-id",
})


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

    # Extract ATT&CK mappings (from MISP Galaxy tags - may be empty)
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


def _extract_refs(value: Any) -> list[str]:
    """Extract @id references from a JSON-LD value (dict or list of dicts)."""
    refs = []
    if isinstance(value, dict) and "@id" in value:
        refs.append(value["@id"])
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and "@id" in item:
                refs.append(item["@id"])
    return refs


def extract_ontology_attack_mappings(ontology_data: dict) -> list[dict[str, str]]:
    """Extract D3FEND→ATT&CK technique mappings from the D3FEND ontology JSON.

    The D3FEND ontology links defensive and offensive techniques through shared
    digital artifacts. This function resolves those indirect relationships into
    direct D3FEND→ATT&CK mappings.

    Algorithm:
    1. Index all entries by @id
    2. Find D3FEND techniques (entries with d3fend-id starting with "D3-")
       and their artifact relationships (e.g., d3f:analyzes → d3f:NetworkTraffic)
    3. Find ATT&CK techniques (entries with attack-id starting with "T")
       and their artifact relationships
    4. Build artifact→ATT&CK index
    5. Match: for each D3FEND→artifact link, find ATT&CK techniques linked
       to the same artifact (or its parent classes)

    Args:
        ontology_data: Parsed JSON from d3fend.mitre.org/ontologies/d3fend.json

    Returns:
        List of dicts with keys: d3fend_technique_id, attack_technique_id,
        relationship_type (the D3FEND property name like "analyzes", "blocks")
    """
    graph = ontology_data.get("@graph", [])
    if not graph:
        logger.warning("D3FEND ontology has no @graph entries")
        return []

    # Build lookup by @id
    by_id: dict[str, dict] = {}
    for entry in graph:
        if isinstance(entry, dict) and "@id" in entry:
            by_id[entry["@id"]] = entry

    # Step 1: Find D3FEND techniques and their artifact relationships
    d3fend_techs: dict[str, list[tuple[str, str]]] = {}  # d3fend_id -> [(rel_type, artifact_id)]
    for entry in graph:
        if not isinstance(entry, dict):
            continue
        d3id = entry.get("d3f:d3fend-id", "")
        if not d3id or not d3id.startswith("D3-"):
            continue

        artifact_rels: list[tuple[str, str]] = []
        for key, val in entry.items():
            if not key.startswith("d3f:") or key in _D3FEND_METADATA_PROPS:
                continue
            for ref in _extract_refs(val):
                if ref.startswith("d3f:") and not ref.startswith("d3f:D3-"):
                    artifact_rels.append((key.replace("d3f:", ""), ref))
        if artifact_rels:
            d3fend_techs[d3id] = artifact_rels

    # Step 2: Find ATT&CK techniques and their artifact relationships
    artifact_to_attack: dict[str, set[str]] = {}  # artifact_id -> {attack_id}
    for entry in graph:
        if not isinstance(entry, dict):
            continue
        attack_id = entry.get("d3f:attack-id", "")
        if not attack_id or not attack_id.startswith("T"):
            continue

        for key, val in entry.items():
            if not key.startswith("d3f:") or key in _D3FEND_METADATA_PROPS:
                continue
            for ref in _extract_refs(val):
                if ref.startswith("d3f:"):
                    if ref not in artifact_to_attack:
                        artifact_to_attack[ref] = set()
                    artifact_to_attack[ref].add(attack_id)

    # Step 3: Also index parent classes of artifacts to ATT&CK techniques
    # This catches cases where D3FEND links to a more specific artifact class
    # but ATT&CK links to a parent class (or vice versa)
    parent_cache: dict[str, set[str]] = {}  # artifact_id -> {parent_ids}

    def _get_parents(artifact_id: str) -> set[str]:
        if artifact_id in parent_cache:
            return parent_cache[artifact_id]
        parents: set[str] = set()
        entry = by_id.get(artifact_id, {})
        parent_refs = entry.get("rdfs:subClassOf", [])
        if isinstance(parent_refs, dict):
            parent_refs = [parent_refs]
        if isinstance(parent_refs, list):
            for p in parent_refs:
                if isinstance(p, dict) and "@id" in p:
                    pid = p["@id"]
                    if pid.startswith("d3f:"):
                        parents.add(pid)
        parent_cache[artifact_id] = parents
        return parents

    # Step 4: Match D3FEND→ATT&CK through shared artifacts
    unique_mappings: set[tuple[str, str, str]] = set()
    mappings: list[dict[str, str]] = []

    for d3id, artifact_rels in d3fend_techs.items():
        for rel_type, artifact_id in artifact_rels:
            # Check direct artifact match
            matched_attack_ids: set[str] = set()
            if artifact_id in artifact_to_attack:
                matched_attack_ids.update(artifact_to_attack[artifact_id])

            # Check parent class matches (one level up)
            for parent_id in _get_parents(artifact_id):
                if parent_id in artifact_to_attack:
                    matched_attack_ids.update(artifact_to_attack[parent_id])

            # Also check if ATT&CK links to a child of this artifact
            # (reverse parent lookup - check if any artifact that links to ATT&CK
            #  has this artifact as a parent)
            for child_id, child_entry in by_id.items():
                if child_id in artifact_to_attack:
                    child_parents = _get_parents(child_id)
                    if artifact_id in child_parents:
                        matched_attack_ids.update(artifact_to_attack[child_id])

            for attack_id in matched_attack_ids:
                key = (d3id, attack_id, rel_type)
                if key not in unique_mappings:
                    unique_mappings.add(key)
                    mappings.append({
                        "d3fend_technique_id": d3id,
                        "attack_technique_id": attack_id,
                        "relationship_type": rel_type,
                    })

    logger.info(
        f"Extracted {len(mappings)} D3FEND→ATT&CK mappings from ontology "
        f"({len(d3fend_techs)} D3FEND techniques, "
        f"{len(set(m['attack_technique_id'] for m in mappings))} ATT&CK techniques)"
    )

    return mappings
