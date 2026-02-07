#!/bin/bash
# Test all documentation examples to ensure they work
# This script validates all curl commands and task names from README.md and SETUP.md

set -e  # Exit on first error

echo "=== Testing Documentation Examples ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

test_passed() {
    echo -e "${GREEN}✓ $1${NC}"
    PASSED=$((PASSED + 1))
}

test_failed() {
    echo -e "${RED}✗ $1${NC}"
    FAILED=$((FAILED + 1))
}

# 1. Test health endpoint
echo "1. Testing health endpoint..."
if curl -s http://localhost:8307/health | grep -q '"status"'; then
    test_passed "Health endpoint works"
else
    test_failed "Health endpoint failed"
fi

# 2. Test /mcp/tools endpoint
echo "2. Testing /mcp/tools endpoint..."
if curl -s http://localhost:8307/mcp/tools | grep -q 'search_cve'; then
    test_passed "/mcp/tools endpoint works"
else
    test_failed "/mcp/tools endpoint failed"
fi

# 3. Test /mcp/tools/call endpoint (from README.md line 163)
echo "3. Testing /mcp/tools/call endpoint..."
if curl -s -X POST http://localhost:8307/mcp/tools/call \
    -H "Content-Type: application/json" \
    -d '{"name": "search_cve", "arguments": {"keyword": "apache", "cvss_min": 9.0, "limit": 3}}' \
    | grep -q 'CVE-'; then
    test_passed "/mcp/tools/call endpoint works"
else
    test_failed "/mcp/tools/call endpoint failed"
fi

# 4. Verify Celery task names exist
echo "4. Verifying Celery task names..."

TASKS=(
    "cve_mcp.tasks.sync_nvd.sync_nvd_full"
    "cve_mcp.tasks.sync_nvd.sync_nvd_recent"
    "cve_mcp.tasks.sync_cisa_kev.sync_cisa_kev"
    "cve_mcp.tasks.sync_epss.sync_epss_scores"
    "cve_mcp.tasks.sync_exploitdb.sync_exploitdb"
    "cve_mcp.tasks.sync_attack.sync_attack"
    "cve_mcp.tasks.sync_atlas.sync_atlas"
    "cve_mcp.tasks.sync_capec.sync_capec"
    "cve_mcp.tasks.sync_cwe.sync_cwe"
    "cve_mcp.tasks.sync_d3fend.sync_d3fend"
)

REGISTERED_TASKS=$(docker-compose exec -T celery-worker celery -A cve_mcp.tasks.celery_app inspect registered 2>/dev/null || echo "")

if [ -z "$REGISTERED_TASKS" ]; then
    echo "Warning: Could not get registered tasks (containers may not be running)"
    echo "Skipping task name validation"
else
    for task in "${TASKS[@]}"; do
        if echo "$REGISTERED_TASKS" | grep -q "$task"; then
            test_passed "Task exists: $task"
        else
            test_failed "Task missing: $task"
        fi
    done
fi

# 5. Test get_data_freshness tool (from SETUP.md line 331)
echo "5. Testing get_data_freshness tool..."
if curl -s -X POST http://localhost:8307/mcp/tools/call \
    -H "Content-Type: application/json" \
    -d '{"name": "get_data_freshness", "arguments": {}}' \
    | grep -q 'nvd'; then
    test_passed "get_data_freshness tool works"
else
    test_failed "get_data_freshness tool failed"
fi

# 6. Verify no old /call endpoint exists
echo "6. Verifying old /call endpoint does not exist..."
if curl -s -X POST http://localhost:8307/call \
    -H "Content-Type: application/json" \
    -d '{"name": "search_cve", "arguments": {"keyword": "test"}}' \
    | grep -q '404\|Not Found'; then
    test_passed "Old /call endpoint correctly does not exist"
else
    echo "Warning: Old /call endpoint may still be accessible"
fi

# Summary
echo ""
echo "=== Test Summary ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All documentation examples are working!${NC}"
    exit 0
else
    echo -e "${RED}Some documentation examples failed. See details above.${NC}"
    exit 1
fi
