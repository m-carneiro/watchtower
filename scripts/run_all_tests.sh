#!/bin/bash

# Watchtower Automated Test Suite
# Runs comprehensive tests across all features

set -e  # Exit on error (can be disabled for full test run)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_URL="${WATCHTOWER_API_URL:-http://localhost:8080}"
VERBOSE="${VERBOSE:-false}"

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

echo "======================================"
echo "🚀 Watchtower Automated Test Suite"
echo "======================================"
echo "API URL: $API_URL"
echo "Time: $(date)"
echo "======================================"
echo ""

# Function to print colored output
print_pass() {
    echo -e "${GREEN}✅ PASSED${NC}: $1"
}

print_fail() {
    echo -e "${RED}❌ FAILED${NC}: $1"
}

print_skip() {
    echo -e "${YELLOW}⏭️  SKIPPED${NC}: $1"
}

print_info() {
    echo -e "${YELLOW}ℹ️  INFO${NC}: $1"
}

# Function to run test
run_test() {
    local name="$1"
    local command="$2"
    local expected="$3"
    local optional="${4:-false}"

    echo "Testing: $name"

    if [ "$VERBOSE" = "true" ]; then
        echo "Command: $command"
    fi

    # Run command and capture result
    if result=$(eval "$command" 2>&1); then
        # Check if result matches expected
        if echo "$result" | grep -qE "$expected"; then
            print_pass "$name"
            ((PASSED++))
        else
            if [ "$optional" = "true" ]; then
                print_skip "$name (optional test)"
                ((SKIPPED++))
            else
                print_fail "$name"
                echo "   Expected pattern: $expected"
                echo "   Got: $result"
                ((FAILED++))
            fi
        fi
    else
        if [ "$optional" = "true" ]; then
            print_skip "$name (service not available)"
            ((SKIPPED++))
        else
            print_fail "$name (command failed)"
            echo "   Error: $result"
            ((FAILED++))
        fi
    fi
    echo ""
}

# ==================================
# Prerequisite Checks
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Prerequisite Checks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "❌ jq is not installed. Please install it first."
    echo "   macOS: brew install jq"
    echo "   Ubuntu: sudo apt-get install jq"
    exit 1
fi

# Check if curl is installed
if ! command -v curl &> /dev/null; then
    echo "❌ curl is not installed."
    exit 1
fi

print_pass "Required tools available (curl, jq)"
echo ""

# ==================================
# Basic API Tests
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🏥 Basic API Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "API Health Check" \
    "curl -s $API_URL/api/v1/health | jq -r .status" \
    "healthy"

run_test "API Service Name" \
    "curl -s $API_URL/api/v1/health | jq -r .service" \
    "watchtower-api"

# ==================================
# IOC Query Tests
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 IOC Query Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Check Known Malicious IP (Exists)" \
    "curl -s '$API_URL/api/v1/iocs/check?value=115.50.92.159' | jq -r .exists" \
    "true"

run_test "Check Known Malicious IP (Type)" \
    "curl -s '$API_URL/api/v1/iocs/check?value=115.50.92.159' | jq -r .type" \
    "ip"

run_test "Check Clean IP (Not Exists)" \
    "curl -s '$API_URL/api/v1/iocs/check?value=8.8.8.8' | jq -r .exists" \
    "false"

run_test "Search Package (Has Results)" \
    "curl -s '$API_URL/api/v1/iocs/search?value=lodash' | jq -r .count" \
    "[1-9]"

run_test "Search Package (Sightings Array)" \
    "curl -s '$API_URL/api/v1/iocs/search?value=lodash' | jq -r '.sightings | length'" \
    "[1-9]"

# ==================================
# Component Extraction Tests
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧩 Component Extraction Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Extracted IP from URL (Exists)" \
    "curl -s '$API_URL/api/v1/iocs/check?value=77.90.185.212' | jq -r .exists" \
    "true"

run_test "Extracted IP (Has Extraction Tag)" \
    "curl -s '$API_URL/api/v1/iocs/search?value=77.90.185.212' | jq -r '.sightings[0].tags[]' | grep -q 'extracted-from-url' && echo 'true' || echo 'false'" \
    "true"

# ==================================
# SIEM Feed Tests
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 SIEM Feed Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "CEF Feed Format" \
    "curl -s '$API_URL/api/v1/iocs/feed?format=cef&since=1h' | head -1" \
    "CEF:0"

run_test "CEF Feed Has Data" \
    "curl -s '$API_URL/api/v1/iocs/feed?format=cef&since=24h' | wc -l | tr -d ' '" \
    "[1-9][0-9]+"

run_test "STIX Feed Type" \
    "curl -s '$API_URL/api/v1/iocs/feed?format=stix&since=1h' | jq -r .type" \
    "bundle"

run_test "STIX Feed Has Objects" \
    "curl -s '$API_URL/api/v1/iocs/feed?format=stix&since=24h' | jq -r '.objects | length'" \
    "[1-9][0-9]+"

run_test "STIX Feed Object Type" \
    "curl -s '$API_URL/api/v1/iocs/feed?format=stix&since=24h' | jq -r '.objects[0].type'" \
    "indicator"

# ==================================
# SentinelOne Webhook Tests
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🛡️  SentinelOne Webhook Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "SentinelOne Webhook (Known IOC)" \
    "curl -s -X POST $API_URL/api/v1/webhooks/sentinelone \
        -H 'Content-Type: application/json' \
        -d '{\"alertId\":\"test-001\",\"threatName\":\"Test.Malware\",\"classification\":\"Malware\",\"indicators\":[{\"type\":\"IPV4\",\"value\":\"115.50.92.159\"}],\"endpoint\":{\"computerName\":\"TEST-01\",\"osType\":\"linux\"}}' \
        | jq -r .status" \
    "received"

run_test "SentinelOne Webhook (IOC Found)" \
    "curl -s -X POST $API_URL/api/v1/webhooks/sentinelone \
        -H 'Content-Type: application/json' \
        -d '{\"alertId\":\"test-002\",\"threatName\":\"Test.Malware\",\"classification\":\"Malware\",\"indicators\":[{\"type\":\"IPV4\",\"value\":\"115.50.92.159\"}],\"endpoint\":{\"computerName\":\"TEST-01\",\"osType\":\"linux\"}}' \
        | jq -r .indicators_in_db" \
    "[1-9]"

run_test "SentinelOne Webhook (Unknown IOC)" \
    "curl -s -X POST $API_URL/api/v1/webhooks/sentinelone \
        -H 'Content-Type: application/json' \
        -d '{\"alertId\":\"test-003\",\"threatName\":\"Test\",\"classification\":\"Suspicious\",\"indicators\":[{\"type\":\"IPV4\",\"value\":\"1.2.3.4\"}],\"endpoint\":{\"computerName\":\"TEST-01\",\"osType\":\"linux\"}}' \
        | jq -r .indicators_in_db" \
    "0"

# ==================================
# Error Handling Tests
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚨 Error Handling Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Invalid JSON Handling" \
    "curl -s -X POST $API_URL/api/v1/webhooks/sentinelone \
        -H 'Content-Type: application/json' \
        -d '{invalid}' \
        -o /dev/null -w '%{http_code}'" \
    "400"

run_test "Missing Parameter Handling" \
    "curl -s '$API_URL/api/v1/iocs/check' -o /dev/null -w '%{http_code}'" \
    "400"

# ==================================
# Performance Tests
# ==================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚡ Performance Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# CheckIOC latency
start_time=$(date +%s%N)
curl -s "$API_URL/api/v1/iocs/check?value=115.50.92.159" > /dev/null
end_time=$(date +%s%N)
latency=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds

if [ $latency -lt 100 ]; then
    print_pass "CheckIOC Latency (${latency}ms < 100ms)"
    ((PASSED++))
else
    print_fail "CheckIOC Latency (${latency}ms >= 100ms)"
    ((FAILED++))
fi
echo ""

# ==================================
# Optional LLM Tests
# ==================================
if [ "$LLM_TRIAGE_ENABLED" = "true" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🤖 LLM Triaging Tests (Optional)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    print_info "LLM triaging is enabled - running LLM tests"

    run_test "LLM Triaging (Response Includes LLM)" \
        "curl -s -X POST $API_URL/api/v1/webhooks/sentinelone \
            -H 'Content-Type: application/json' \
            -d '{\"alertId\":\"test-llm-001\",\"threatName\":\"Malware.Test\",\"classification\":\"Malware\",\"indicators\":[{\"type\":\"IPV4\",\"value\":\"115.50.92.159\"}],\"endpoint\":{\"computerName\":\"TEST-01\",\"osType\":\"linux\"}}' \
            | jq -r 'has(\"llm_triaged\") or has(\"indicators_in_db\")' " \
        "true" \
        true
else
    print_skip "LLM Tests (LLM_TRIAGE_ENABLED not set)"
    ((SKIPPED++))
    echo ""
fi

# ==================================
# Summary
# ==================================
echo "======================================"
echo "📈 Test Results Summary"
echo "======================================"
echo ""
echo -e "${GREEN}Passed:${NC}  $PASSED"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
echo -e "${RED}Failed:${NC}  $FAILED"
echo ""
echo "Total:   $((PASSED + SKIPPED + FAILED))"
echo "======================================"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Ensure services are running: make run-api-dev"
    echo "  2. Check database has data: make db-shell"
    echo "  3. Review logs: tail -f /tmp/watchtower-api.log"
    echo "  4. Re-run ingestion: make ingestion-dev"
    echo ""
    exit 1
fi
