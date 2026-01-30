"""Tests for NVD parser."""

import pytest

from cve_mcp.utils.nvd_parser import parse_nvd_cve


def test_parse_nvd_cve_basic():
    """Test parsing a basic CVE item."""
    vuln_item = {
        "cve": {
            "id": "CVE-2024-1234",
            "published": "2024-01-15T10:30:00.000",
            "lastModified": "2024-01-20T14:00:00.000",
            "descriptions": [
                {"lang": "en", "value": "A test vulnerability description."}
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseSeverity": "CRITICAL",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    }
                ]
            },
            "weaknesses": [
                {
                    "description": [{"lang": "en", "value": "CWE-79"}]
                }
            ],
            "references": [
                {
                    "url": "https://example.com/advisory",
                    "source": "vendor",
                    "tags": ["Patch", "Vendor Advisory"],
                }
            ],
            "configurations": [],
        }
    }

    result = parse_nvd_cve(vuln_item)

    assert result["cve_id"] == "CVE-2024-1234"
    assert result["description"] == "A test vulnerability description."
    assert result["cvss_v3_score"] == 9.8
    assert result["cvss_v3_severity"] == "CRITICAL"
    assert result["cwe_ids"] == ["CWE-79"]
    assert result["primary_cwe_id"] == "CWE-79"
    assert len(result["references"]) == 1
    assert result["references"][0]["url"] == "https://example.com/advisory"


def test_parse_nvd_cve_with_cpe():
    """Test parsing CVE with CPE configurations."""
    vuln_item = {
        "cve": {
            "id": "CVE-2024-5678",
            "published": "2024-02-01T00:00:00.000",
            "lastModified": "2024-02-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Test with CPE."}],
            "metrics": {},
            "weaknesses": [],
            "references": [],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                    "versionStartIncluding": "1.0",
                                    "versionEndExcluding": "2.0",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    }

    result = parse_nvd_cve(vuln_item)

    assert result["cve_id"] == "CVE-2024-5678"
    assert len(result["cpe_mappings"]) == 1
    cpe = result["cpe_mappings"][0]
    assert cpe["cpe_vendor"] == "vendor"
    assert cpe["cpe_product"] == "product"
    assert cpe["cpe_version"] == "1.0"
    assert cpe["version_start"] == "1.0"
    assert cpe["version_start_type"] == "including"
    assert cpe["version_end"] == "2.0"
    assert cpe["version_end_type"] == "excluding"


def test_parse_nvd_cve_no_description():
    """Test parsing CVE without description falls back gracefully."""
    vuln_item = {
        "cve": {
            "id": "CVE-2024-0001",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-01T00:00:00.000",
            "descriptions": [],
            "metrics": {},
            "weaknesses": [],
            "references": [],
            "configurations": [],
        }
    }

    result = parse_nvd_cve(vuln_item)

    assert result["cve_id"] == "CVE-2024-0001"
    assert result["description"] == ""
