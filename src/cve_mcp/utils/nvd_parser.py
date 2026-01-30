"""NVD API response parser."""

from datetime import datetime
from typing import Any


def parse_nvd_cve(vuln_item: dict[str, Any]) -> dict[str, Any]:
    """Parse a CVE item from NVD API 2.0 response.

    Args:
        vuln_item: Raw vulnerability item from NVD API

    Returns:
        Parsed CVE data suitable for database insertion
    """
    cve = vuln_item.get("cve", {})
    cve_id = cve.get("id", "")

    # Parse dates
    published_date = None
    if cve.get("published"):
        try:
            published_date = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
        except ValueError:
            published_date = datetime.now()

    last_modified_date = None
    if cve.get("lastModified"):
        try:
            last_modified_date = datetime.fromisoformat(cve["lastModified"].replace("Z", "+00:00"))
        except ValueError:
            last_modified_date = datetime.now()

    # Get description (prefer English)
    description = ""
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # Parse CVSS metrics
    metrics = cve.get("metrics", {})

    # CVSS v3.1 (preferred) or v3.0
    cvss_v3_score = None
    cvss_v3_vector = None
    cvss_v3_severity = None
    cvss_v3_base_score = None
    cvss_v3_exploitability_score = None
    cvss_v3_impact_score = None

    cvss_v31 = metrics.get("cvssMetricV31", [])
    if not cvss_v31:
        cvss_v31 = metrics.get("cvssMetricV30", [])

    if cvss_v31:
        primary = None
        for metric in cvss_v31:
            if metric.get("type") == "Primary":
                primary = metric
                break
        if not primary and cvss_v31:
            primary = cvss_v31[0]

        if primary:
            cvss_data = primary.get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
            cvss_v3_severity = cvss_data.get("baseSeverity")
            cvss_v3_base_score = cvss_data.get("baseScore")
            cvss_v3_exploitability_score = primary.get("exploitabilityScore")
            cvss_v3_impact_score = primary.get("impactScore")

    # CVSS v2 (legacy)
    cvss_v2_score = None
    cvss_v2_vector = None
    cvss_v2_severity = None

    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2:
        primary = None
        for metric in cvss_v2:
            if metric.get("type") == "Primary":
                primary = metric
                break
        if not primary and cvss_v2:
            primary = cvss_v2[0]

        if primary:
            cvss_data = primary.get("cvssData", {})
            cvss_v2_score = cvss_data.get("baseScore")
            cvss_v2_vector = cvss_data.get("vectorString")
            cvss_v2_severity = primary.get("baseSeverity")

    # CVSS v4.0 (if available)
    cvss_v4_score = None
    cvss_v4_vector = None
    cvss_v4_severity = None

    cvss_v4 = metrics.get("cvssMetricV40", [])
    if cvss_v4:
        primary = cvss_v4[0]
        cvss_data = primary.get("cvssData", {})
        cvss_v4_score = cvss_data.get("baseScore")
        cvss_v4_vector = cvss_data.get("vectorString")
        cvss_v4_severity = cvss_data.get("baseSeverity")

    # Parse CWE IDs
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                cwe_value = desc.get("value", "")
                if cwe_value.startswith("CWE-"):
                    cwe_ids.append(cwe_value)

    primary_cwe_id = cwe_ids[0] if cwe_ids else None

    # Parse references
    references = []
    for ref in cve.get("references", []):
        references.append({
            "url": ref.get("url", ""),
            "source": ref.get("source"),
            "tags": ref.get("tags", []),
        })

    # Parse CPE configurations
    cpe_mappings = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            _parse_cpe_node(node, cpe_mappings)

    # Build CVE data dict
    cve_data = {
        "cve_id": cve_id,
        "published_date": published_date,
        "last_modified_date": last_modified_date,
        "description": description,
        "cvss_v2_score": cvss_v2_score,
        "cvss_v2_vector": cvss_v2_vector,
        "cvss_v2_severity": cvss_v2_severity,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v3_vector": cvss_v3_vector,
        "cvss_v3_severity": cvss_v3_severity,
        "cvss_v3_base_score": cvss_v3_base_score,
        "cvss_v3_exploitability_score": cvss_v3_exploitability_score,
        "cvss_v3_impact_score": cvss_v3_impact_score,
        "cvss_v4_score": cvss_v4_score,
        "cvss_v4_vector": cvss_v4_vector,
        "cvss_v4_severity": cvss_v4_severity,
        "cwe_ids": cwe_ids if cwe_ids else None,
        "primary_cwe_id": primary_cwe_id,
        "assigner": cve.get("sourceIdentifier"),
        "data_source": "NVD",
        "data_version": "2.0",
        "data_last_updated": datetime.now(),
        "references": references,
        "cpe_mappings": cpe_mappings,
    }

    return cve_data


def _parse_cpe_node(node: dict[str, Any], cpe_mappings: list[dict]) -> None:
    """Parse a CPE configuration node recursively."""
    # Parse CPE matches in this node
    for cpe_match in node.get("cpeMatch", []):
        cpe_uri = cpe_match.get("criteria", "")

        # Parse CPE 2.3 URI components
        # Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        parts = cpe_uri.split(":")
        cpe_part = parts[2] if len(parts) > 2 else None
        cpe_vendor = parts[3] if len(parts) > 3 and parts[3] != "*" else None
        cpe_product = parts[4] if len(parts) > 4 and parts[4] != "*" else None
        cpe_version = parts[5] if len(parts) > 5 and parts[5] != "*" else None
        cpe_update = parts[6] if len(parts) > 6 and parts[6] != "*" else None

        cpe_mappings.append({
            "cpe_uri": cpe_uri,
            "cpe_part": cpe_part,
            "cpe_vendor": cpe_vendor,
            "cpe_product": cpe_product,
            "cpe_version": cpe_version,
            "cpe_update": cpe_update,
            "version_start_type": cpe_match.get("versionStartIncluding") and "including"
            or cpe_match.get("versionStartExcluding") and "excluding",
            "version_start": cpe_match.get("versionStartIncluding")
            or cpe_match.get("versionStartExcluding"),
            "version_end_type": cpe_match.get("versionEndIncluding") and "including"
            or cpe_match.get("versionEndExcluding") and "excluding",
            "version_end": cpe_match.get("versionEndIncluding")
            or cpe_match.get("versionEndExcluding"),
            "vulnerable": cpe_match.get("vulnerable", True),
        })

    # Recursively parse child nodes
    for child in node.get("children", []):
        _parse_cpe_node(child, cpe_mappings)
