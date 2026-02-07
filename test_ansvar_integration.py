#!/usr/bin/env python3
"""Integration test mimicking actual Ansvar platform ThreatIntelClient usage."""

import asyncio
import json
import sys

import httpx


BASE_URL = "http://localhost:8307"


async def _call_tool(tool_name: str, arguments: dict) -> dict:
    """Mimic ThreatIntelClient._call_tool method."""
    clean_args = {k: v for k, v in arguments.items() if v is not None}

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        response = await client.post(
            f"{BASE_URL}/mcp/tools/call",
            json={"name": tool_name, "arguments": clean_args},
            headers={"Content-Type": "application/json"}
        )

        if response.status_code != 200:
            raise Exception(f"MCP returned status {response.status_code}")

        data = response.json()
        if data.get("isError"):
            error_text = data.get("content", [{}])[0].get("text", "Unknown error")
            raise ValueError(f"Tool error: {error_text}")

        # Parse JSON from text content
        content = data.get("content", [{}])[0].get("text", "{}")
        return json.loads(content)


async def test_search_cve():
    """Test search_cve exactly as Ansvar client calls it."""
    print("Testing search_cve (Ansvar client style)...")
    result = await _call_tool("search_cve", {
        "keyword": "remote code execution",
        "limit": 5,
        "has_kev": True
    })
    assert "data" in result
    assert "metadata" in result
    print(f"  ✓ Found {len(result['data'])} CVEs with KEV status")


async def test_get_cve_details():
    """Test get_cve_details exactly as Ansvar client calls it."""
    print("Testing get_cve_details (Ansvar client style)...")
    result = await _call_tool("get_cve_details", {
        "cve_id": "CVE-2021-44228",
        "include_references": True,
        "include_cpe": False,
        "include_exploits": True
    })
    assert result["data"]["cve_id"] == "CVE-2021-44228"
    print(f"  ✓ Retrieved CVE details: {result['data']['description'][:60]}...")


async def test_search_by_product():
    """Test search_by_product exactly as Ansvar client calls it."""
    print("Testing search_by_product (Ansvar client style)...")
    result = await _call_tool("search_by_product", {
        "product_name": "windows",
        "vendor": "microsoft",
        "limit": 5
    })
    assert "data" in result
    print(f"  ✓ Found {len(result['data'])} CVEs for Microsoft Windows")


async def test_search_techniques():
    """Test search_techniques exactly as Ansvar client calls it."""
    print("Testing search_techniques (Ansvar client style)...")
    result = await _call_tool("search_techniques", {
        "query": "credential dumping",
        "limit": 5
    })
    assert "data" in result
    print(f"  ✓ Found {len(result['data'])} ATT&CK techniques")


async def test_get_technique_details():
    """Test get_technique_details exactly as Ansvar client calls it."""
    print("Testing get_technique_details (Ansvar client style)...")
    result = await _call_tool("get_technique_details", {
        "technique_id": "T1003"
    })
    assert result["data"]["technique_id"] == "T1003"
    print(f"  ✓ Retrieved technique: {result['data']['name']}")


async def test_get_group_profile():
    """Test get_group_profile exactly as Ansvar client calls it."""
    print("Testing get_group_profile (Ansvar client style)...")
    result = await _call_tool("get_group_profile", {
        "group_id": "G0007"
    })
    assert result["data"]["group_id"] == "G0007"
    print(f"  ✓ Retrieved group: {result['data']['name']}")


async def test_search_cloud_services():
    """Test search_cloud_services exactly as Ansvar client calls it."""
    print("Testing search_cloud_services (Ansvar client style)...")
    result = await _call_tool("search_cloud_services", {
        "keyword": "compute",
        "limit": 5
    })
    assert "data" in result
    print(f"  ✓ Found {len(result['data'])} cloud services")


async def test_get_data_freshness():
    """Test get_data_freshness exactly as Ansvar client calls it."""
    print("Testing get_data_freshness (Ansvar client style)...")
    result = await _call_tool("get_data_freshness", {})
    assert "data" in result
    sources = list(result["data"].keys())
    print(f"  ✓ Data freshness for {len(sources)} sources")


async def main():
    """Run all Ansvar client integration tests."""
    print("=" * 70)
    print("Ansvar Platform Integration Test")
    print("Mimicking actual ThreatIntelClient._call_tool() usage")
    print("=" * 70)
    print()

    tests = [
        test_search_cve,
        test_get_cve_details,
        test_search_by_product,
        test_search_techniques,
        test_get_technique_details,
        test_get_group_profile,
        test_search_cloud_services,
        test_get_data_freshness,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            await test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  ✗ Test failed: {e}")

    print()
    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("✓ All Ansvar platform integration tests passed!")
        print("HTTP wrapper maintains 100% client compatibility")
    else:
        print(f"✗ {failed} test(s) failed")
        sys.exit(1)

    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
