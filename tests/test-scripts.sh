#!/bin/bash

# Test script for EPSS data scripts
# Tests dynamic path resolution and URL changes

# Colors for output formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== EPSS Scripts Testing ===${NC}"
echo "This script will test the dynamic path resolution and URL updates"

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASEPATH="$SCRIPT_DIR"
echo "Test script using base path: $BASEPATH"

# Keep track of test results
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function for test results
function test_result {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS:${NC} $2"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL:${NC} $2"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo -e "\n${YELLOW}1. Testing dynamic path detection in scripts${NC}"

# Test dynamic path in update-all.sh
if grep -q "SCRIPT_DIR=\"\$(cd \"\$(dirname \"\$0\")\" && pwd)\"" "$BASEPATH/update-all.sh"; then
    test_result 0 "update-all.sh has dynamic path detection"
else
    test_result 1 "update-all.sh missing dynamic path detection"
fi

# Test dynamic path in update-epss.sh
if grep -q "SCRIPT_DIR=\"\$(cd \"\$(dirname \"\$0\")\" && pwd)\"" "$BASEPATH/update-epss.sh"; then
    test_result 0 "update-epss.sh has dynamic path detection"
else
    test_result 1 "update-epss.sh missing dynamic path detection"
fi

# Test dynamic path in update-kev.sh
if grep -q "SCRIPT_DIR=\"\$(cd \"\$(dirname \"\$0\")\" && pwd)\"" "$BASEPATH/update-kev.sh"; then
    test_result 0 "update-kev.sh has dynamic path detection"
else
    test_result 1 "update-kev.sh missing dynamic path detection"
fi

# Test dynamic path in update-vulnrich.sh
if grep -q "SCRIPT_DIR=\"\$(cd \"\$(dirname \"\$0\")\" && pwd)\"" "$BASEPATH/update-vulnrich.sh"; then
    test_result 0 "update-vulnrich.sh has dynamic path detection"
else
    test_result 1 "update-vulnrich.sh missing dynamic path detection"
fi

# Test dynamic path in subprogram/epss-add.sh
if grep -q "SCRIPT_DIR=\"\$(cd \"\$(dirname \"\$0\")\" && pwd)\"" "$BASEPATH/subprogram/epss-add.sh"; then
    test_result 0 "subprogram/epss-add.sh has dynamic path detection"
else
    test_result 1 "subprogram/epss-add.sh missing dynamic path detection"
fi

# Test dynamic path in init-script/epss-init.sh
if grep -q "SCRIPT_DIR=\"\$(cd \"\$(dirname \"\$0\")\" && pwd)\"" "$BASEPATH/init-script/epss-init.sh"; then
    test_result 0 "init-script/epss-init.sh has dynamic path detection"
else
    test_result 1 "init-script/epss-init.sh missing dynamic path detection"
fi

echo -e "\n${YELLOW}2. Testing configuration file access${NC}"

# Test if my.cnf exists
if [ -f "$BASEPATH/my.cnf" ]; then
    test_result 0 "my.cnf exists at $BASEPATH/my.cnf"
else
    test_result 1 "my.cnf not found at $BASEPATH/my.cnf"
fi

echo -e "\n${YELLOW}3. Testing URL updates${NC}"

# Test EPSS URLs
echo -e "${YELLOW}3.1. EPSS URLs${NC}"

# Test if epss-add.sh is using the correct URL
if grep -q "https://epss.empiricalsecurity.com/epss_scores-" "$BASEPATH/subprogram/epss-add.sh"; then
    test_result 0 "epss-add.sh is using the correct URL"
else
    test_result 1 "epss-add.sh is NOT using the correct URL"
fi

# Test if epss-init.sh is using the correct URL
if grep -q "https://epss.empiricalsecurity.com/epss_scores-" "$BASEPATH/init-script/epss-init.sh"; then
    test_result 0 "epss-init.sh is using the correct URL"
else
    test_result 1 "epss-init.sh is NOT using the correct URL"
fi

# Test EPSS URL accessibility
if curl --output /dev/null --silent --head --fail "https://epss.empiricalsecurity.com/epss_scores-2022-02-04.csv.gz"; then
    test_result 0 "EPSS URL is accessible"
else
    test_result 1 "EPSS URL is NOT accessible"
fi

# Test KEV URLs
echo -e "${YELLOW}3.2. KEV URLs${NC}"

# Test if update-kev.sh has the correct KEV URL
EXPECTED_KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Direct check for the URL string, more reliable than extraction
if grep -q "$EXPECTED_KEV_URL" "$BASEPATH/update-kev.sh"; then
    test_result 0 "update-kev.sh contains the correct KEV URL"
else
    test_result 1 "update-kev.sh does NOT contain the correct KEV URL"
fi

# Test KEV URL accessibility
echo "Testing KEV URL accessibility: $EXPECTED_KEV_URL"
if curl --output /dev/null --silent --fail "$EXPECTED_KEV_URL"; then
    test_result 0 "KEV URL is accessible"
else
    test_result 1 "KEV URL is NOT accessible"
fi

# Test Vulnrichment URLs
echo -e "${YELLOW}3.3. Vulnrichment Repository${NC}"

# Check if vulnrichment directory exists or can be created
if [ -d "$BASEPATH/vulnrichment" ] || mkdir -p "$BASEPATH/vulnrichment"; then
    test_result 0 "Vulnrichment directory exists or can be created"
else
    test_result 1 "Vulnrichment directory cannot be created"
fi

# Check if git is available
if command -v git >/dev/null 2>&1; then
    test_result 0 "git command is available for Vulnrichment updates"
else
    test_result 1 "git command is NOT available for Vulnrichment updates"
fi

echo -e "\n${YELLOW}4. Testing script cross-references${NC}"

# Test update-all.sh calls update-epss.sh with dynamic path
if grep -q "\"\$BASEPATH/update-epss.sh\"" "$BASEPATH/update-all.sh"; then
    test_result 0 "update-all.sh references update-epss.sh with dynamic path"
else
    test_result 1 "update-all.sh NOT using dynamic path for update-epss.sh"
fi

# Test update-epss.sh calls epss-add.sh with dynamic path
if grep -q "\"\$BASEPATH/subprogram/epss-add.sh\"" "$BASEPATH/update-epss.sh"; then
    test_result 0 "update-epss.sh references epss-add.sh with dynamic path"
else
    test_result 1 "update-epss.sh NOT using dynamic path for epss-add.sh"
fi

echo -e "\n${YELLOW}=== Test Results ===${NC}"
echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed! The scripts should work with dynamic paths and the new URL.${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed. Please review the results and fix the issues.${NC}"
    exit 1
fi
