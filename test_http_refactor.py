#!/usr/bin/env python3
"""Test script to verify HTTP wrapper refactoring maintains backward compatibility."""

import asyncio
import json

import httpx


BASE_URL = "http://localhost:8307"


async def test_health():
    """Test /health endpoint."""
    print("Testing /health endpoint...")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/health")
        print(f"  Status: {response.status_code}")
        data = response.json()
        print(f"  Status: {data.get('status')}")
        print(f"  Data sources: {len(data.get('data_freshness', {}))}")
        assert response.status_code == 200
        assert data.get("status") in ["healthy", "degraded"]
        print("  ✓ Health check passed")


async def test_list_tools():
    """Test /mcp/tools endpoint."""
    print("\nTesting /mcp/tools endpoint...")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/mcp/tools")
        print(f"  Status: {response.status_code}")
        data = response.json()
        tools = data.get("tools", [])
        print(f"  Tool count: {len(tools)}")
        assert response.status_code == 200
        assert len(tools) == 41, f"Expected 41 tools, got {len(tools)}"

        # Verify a few key tools exist
        tool_names = [t["name"] for t in tools]
        assert "search_cve" in tool_names
        assert "get_cve_details" in tool_names
        assert "search_techniques" in tool_names
        assert "get_defense_details" in tool_names
        print("  ✓ Tool listing passed (41 tools)")


async def test_call_tool_search_cve():
    """Test /mcp/tools/call with search_cve."""
    print("\nTesting /mcp/tools/call with search_cve...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{BASE_URL}/mcp/tools/call",
            json={
                "name": "search_cve",
                "arguments": {
                    "keyword": "remote code execution",
                    "limit": 5
                }
            }
        )
        print(f"  Status: {response.status_code}")
        data = response.json()
        print(f"  isError: {data.get('isError')}")

        assert response.status_code == 200
        assert not data.get("isError"), f"Tool call returned error: {data}"

        # Parse the result
        content = data.get("content", [{}])[0].get("text", "{}")
        result = json.loads(content)

        print(f"  Result type: {type(result)}")
        print(f"  Has 'data' key: {'data' in result}")
        print(f"  Has 'metadata' key: {'metadata' in result}")

        if result.get("data"):
            print(f"  CVE count: {len(result['data'])}")

        assert "data" in result
        assert "metadata" in result
        print("  ✓ search_cve tool call passed")


async def test_call_tool_get_cve_details():
    """Test /mcp/tools/call with get_cve_details."""
    print("\nTesting /mcp/tools/call with get_cve_details...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{BASE_URL}/mcp/tools/call",
            json={
                "name": "get_cve_details",
                "arguments": {
                    "cve_id": "CVE-2021-44228",  # Log4Shell
                    "include_references": True,
                    "include_cpe": False,
                    "include_exploits": True
                }
            }
        )
        print(f"  Status: {response.status_code}")
        data = response.json()
        print(f"  isError: {data.get('isError')}")

        assert response.status_code == 200
        assert not data.get("isError"), f"Tool call returned error: {data}"

        # Parse the result
        content = data.get("content", [{}])[0].get("text", "{}")
        result = json.loads(content)

        if result.get("data"):
            cve_data = result["data"]
            print(f"  CVE ID: {cve_data.get('cve_id')}")
            print(f"  Description: {cve_data.get('description', '')[:80]}...")
            print(f"  CVSS Score: {cve_data.get('cvss_base_score')}")

        assert "data" in result
        assert result["data"] is not None
        assert result["data"]["cve_id"] == "CVE-2021-44228"
        print("  ✓ get_cve_details tool call passed")


async def test_call_tool_validation_error():
    """Test /mcp/tools/call with invalid arguments."""
    print("\nTesting /mcp/tools/call with validation error...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{BASE_URL}/mcp/tools/call",
            json={
                "name": "search_cve",
                "arguments": {
                    "keyword": "test",
                    "limit": 99999  # Exceeds max (500)
                }
            }
        )
        print(f"  Status: {response.status_code}")
        data = response.json()
        print(f"  isError: {data.get('isError')}")

        assert response.status_code == 200
        assert data.get("isError") is True, "Expected validation error to be flagged"

        content = data.get("content", [{}])[0].get("text", "")
        print(f"  Error message: {content[:100]}...")

        assert "validation" in content.lower() or "limit" in content.lower()
        print("  ✓ Validation error handling passed")


async def test_call_tool_not_found():
    """Test /mcp/tools/call with unknown tool."""
    print("\nTesting /mcp/tools/call with unknown tool...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{BASE_URL}/mcp/tools/call",
            json={
                "name": "nonexistent_tool",
                "arguments": {}
            }
        )
        print(f"  Status: {response.status_code}")
        data = response.json()
        print(f"  isError: {data.get('isError')}")

        assert response.status_code == 200
        assert data.get("isError") is True, "Expected tool not found error"

        content = data.get("content", [{}])[0].get("text", "")
        print(f"  Error message: {content}")

        assert "not found" in content.lower() or "unknown" in content.lower()
        print("  ✓ Unknown tool error handling passed")


async def main():
    """Run all tests."""
    print("=" * 70)
    print("HTTP Wrapper Refactoring Tests")
    print("Testing backward compatibility with MCP server integration")
    print("=" * 70)

    try:
        await test_health()
        await test_list_tools()
        await test_call_tool_search_cve()
        await test_call_tool_get_cve_details()
        await test_call_tool_validation_error()
        await test_call_tool_not_found()

        print("\n" + "=" * 70)
        print("✓ All tests passed!")
        print("HTTP wrapper maintains 100% backward compatibility")
        print("=" * 70)

    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        raise
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
