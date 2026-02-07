#!/bin/bash
# Validation script for HTTP wrapper refactoring
# Verifies all endpoints work correctly with MCP server integration

set -e

BASE_URL="http://localhost:8307"

echo "======================================================================"
echo "HTTP Wrapper Refactoring Validation"
echo "======================================================================"
echo ""

# Check server is running
echo "1. Checking server health..."
if curl -sf "$BASE_URL/health" > /dev/null; then
    echo "   ✓ Server is healthy"
else
    echo "   ✗ Server is not responding"
    exit 1
fi

# Check tools list
echo ""
echo "2. Checking tools list..."
TOOL_COUNT=$(curl -s "$BASE_URL/mcp/tools" | python3 -c "import sys, json; print(len(json.load(sys.stdin)['tools']))")
if [ "$TOOL_COUNT" = "41" ]; then
    echo "   ✓ All 41 tools available"
else
    echo "   ✗ Expected 41 tools, got $TOOL_COUNT"
    exit 1
fi

# Test MCP tool call endpoint
echo ""
echo "3. Testing MCP tool call endpoint..."
RESULT=$(curl -s -X POST "$BASE_URL/mcp/tools/call" \
    -H "Content-Type: application/json" \
    -d '{"name":"search_cve","arguments":{"keyword":"test","limit":1}}')

IS_ERROR=$(echo "$RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('isError', True))")
if [ "$IS_ERROR" = "False" ]; then
    echo "   ✓ Tool call succeeded"
else
    echo "   ✗ Tool call failed"
    echo "$RESULT" | python3 -m json.tool
    exit 1
fi

# Test direct REST API
echo ""
echo "4. Testing direct REST API endpoint..."
if curl -sf "$BASE_URL/api/cve/CVE-2021-44228" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d['data']['cve_id'] == 'CVE-2021-44228'" 2>/dev/null; then
    echo "   ✓ Direct API endpoint works"
else
    echo "   ✗ Direct API endpoint failed"
    exit 1
fi

# Check middleware is active
echo ""
echo "5. Checking request logging middleware..."
if docker logs cve-mcp-server 2>&1 | grep -q "HTTP request.*method=GET.*path=/health"; then
    echo "   ✓ Request logging middleware active"
else
    echo "   ✗ Request logging middleware not found in logs"
    exit 1
fi

# Check MCP server is being used
echo ""
echo "6. Verifying MCP server integration..."
if docker logs cve-mcp-server 2>&1 | grep -q "MCP server created.*tools_count=41"; then
    echo "   ✓ MCP server created and registered 41 tools"
else
    echo "   ✗ MCP server not properly initialized"
    exit 1
fi

echo ""
echo "======================================================================"
echo "✓ All validation checks passed!"
echo "HTTP wrapper successfully refactored to use MCP server"
echo "======================================================================"
