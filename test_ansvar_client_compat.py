#!/usr/bin/env python3
"""Test Ansvar platform ThreatIntelClient compatibility with refactored MCP server.

This test verifies all 25 agent-facing tools work correctly.
"""

import asyncio
import json

import httpx


BASE_URL = "http://localhost:8307"


async def test_tool(name: str, arguments: dict, expected_keys: list[str] = None):
    """Test a single tool call."""
    expected_keys = expected_keys or ["data", "metadata"]

    print(f"\nTesting {name}...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{BASE_URL}/mcp/tools/call",
            json={"name": name, "arguments": arguments}
        )

        if response.status_code != 200:
            print(f"  ✗ HTTP {response.status_code}")
            return False

        data = response.json()
        if data.get("isError"):
            error_msg = data.get("content", [{}])[0].get("text", "Unknown error")
            print(f"  ✗ Tool error: {error_msg[:100]}")
            return False

        # Parse result
        content = data.get("content", [{}])[0].get("text", "{}")
        result = json.loads(content)

        # Verify expected keys
        for key in expected_keys:
            if key not in result:
                print(f"  ✗ Missing key: {key}")
                return False

        print(f"  ✓ {name} passed")
        return True


async def main():
    """Test all 25 agent-facing tools."""
    print("=" * 70)
    print("Ansvar Platform ThreatIntelClient Compatibility Test")
    print("Testing all 25 agent-facing tools")
    print("=" * 70)

    results = {}

    # CVE tools (8)
    results["search_cve"] = await test_tool(
        "search_cve",
        {"keyword": "SQL injection", "limit": 5}
    )

    results["get_cve_details"] = await test_tool(
        "get_cve_details",
        {"cve_id": "CVE-2021-44228", "include_references": False, "include_cpe": False}
    )

    results["check_kev_status"] = await test_tool(
        "check_kev_status",
        {"cve_id": "CVE-2021-44228"}
    )

    results["get_epss_score"] = await test_tool(
        "get_epss_score",
        {"cve_id": "CVE-2021-44228"}
    )

    results["search_by_product"] = await test_tool(
        "search_by_product",
        {"vendor": "microsoft", "product": "windows", "limit": 5}
    )

    results["get_exploits"] = await test_tool(
        "get_exploits",
        {"cve_id": "CVE-2021-44228", "verified_only": False}
    )

    results["get_cwe_details"] = await test_tool(
        "get_cwe_details",
        {"cwe_id": "CWE-79"}
    )

    results["batch_search"] = await test_tool(
        "batch_search",
        {"cve_ids": ["CVE-2021-44228", "CVE-2023-23397"]}
    )

    # ATT&CK tools (7)
    results["search_techniques"] = await test_tool(
        "search_techniques",
        {"query": "credential dumping", "limit": 5}
    )

    results["get_technique_details"] = await test_tool(
        "get_technique_details",
        {"technique_id": "T1003"}
    )

    results["get_technique_badges"] = await test_tool(
        "get_technique_badges",
        {"technique_id": "T1003"}
    )

    results["search_threat_actors"] = await test_tool(
        "search_threat_actors",
        {"query": "APT", "limit": 5}
    )

    results["get_group_profile"] = await test_tool(
        "get_group_profile",
        {"group_id": "G0007"}
    )

    # ATLAS tools (2)
    results["search_atlas_techniques"] = await test_tool(
        "search_atlas_techniques",
        {"query": "poisoning", "limit": 5}
    )

    results["get_atlas_technique_details"] = await test_tool(
        "get_atlas_technique_details",
        {"technique_id": "AML.T0020"}
    )

    # CAPEC tools (2)
    results["search_capec_patterns"] = await test_tool(
        "search_capec_patterns",
        {"query": "injection", "limit": 5}
    )

    results["get_capec_pattern_details"] = await test_tool(
        "get_capec_pattern_details",
        {"pattern_id": "CAPEC-66"}
    )

    results["search_capec_mitigations"] = await test_tool(
        "search_capec_mitigations",
        {"query": "input validation", "limit": 5}
    )

    # CWE tools (3)
    results["search_cwe_weaknesses"] = await test_tool(
        "search_cwe_weaknesses",
        {"query": "injection", "limit": 5}
    )

    results["get_cwe_weakness_details"] = await test_tool(
        "get_cwe_weakness_details",
        {"cwe_id": "CWE-79"}
    )

    results["get_cwe_hierarchy"] = await test_tool(
        "get_cwe_hierarchy",
        {"cwe_id": "CWE-79"}
    )

    # D3FEND tools (2)
    results["search_defenses"] = await test_tool(
        "search_defenses",
        {"query": "network segmentation", "limit": 5}
    )

    results["get_defense_details"] = await test_tool(
        "get_defense_details",
        {"technique_id": "D3-AL"}
    )

    results["get_attack_coverage"] = await test_tool(
        "get_attack_coverage",
        {"technique_ids": ["D3-AL", "D3-NTF"]}
    )

    # Cloud Security tools (1 - just test one to verify module works)
    results["search_cloud_services"] = await test_tool(
        "search_cloud_services",
        {"keyword": "compute", "limit": 5}
    )

    # System tool (1)
    results["get_data_freshness"] = await test_tool(
        "get_data_freshness",
        {}
    )

    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for name, result in sorted(results.items()):
        status = "✓" if result else "✗"
        print(f"{status} {name}")

    print("=" * 70)
    print(f"Passed: {passed}/{total} tools")

    if passed == total:
        print("✓ All Ansvar platform tools work correctly!")
    else:
        print(f"✗ {total - passed} tool(s) failed")

    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
