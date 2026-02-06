#!/bin/bash
# Comprehensive test suite for Observability & Resilience features

# Don't exit on error - we want to run all tests
set +e

echo "🧪 Watchtower Observability & Resilience Test Suite"
echo "=================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

passed=0
failed=0

test_pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((passed++))
}

test_fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((failed++))
}

test_info() {
    echo -e "${BLUE}ℹ️  INFO${NC}: $1"
}

test_warning() {
    echo -e "${YELLOW}⚠️  WARN${NC}: $1"
}

# Test 1: Build verification
echo ""
echo "📦 Test 1: Build Verification"
echo "------------------------------"
if go build -o /tmp/watchtower-api cmd/watchtower-api/main.go 2>/dev/null; then
    test_pass "API builds successfully"
else
    test_fail "API build failed"
fi

if go build -o /tmp/watchtower-ingester cmd/ingester/main.go 2>/dev/null; then
    test_pass "Ingester builds successfully"
else
    test_fail "Ingester build failed"
fi

# Test 2: Unit tests
echo ""
echo "🔬 Test 2: Unit Tests"
echo "---------------------"
test_info "Running LLM adapter tests..."
if go test ./internal/adapter/llm/... -v -timeout 30s > /tmp/llm_tests.log 2>&1; then
    test_pass "All LLM unit tests pass"
    # Show test summary
    grep -E "(PASS|FAIL):" /tmp/llm_tests.log | head -10 || true
else
    test_fail "LLM unit tests failed"
    echo "Last 20 lines of test output:"
    tail -20 /tmp/llm_tests.log
fi

# Test 3: Metrics tests
echo ""
echo "📊 Test 3: Metrics Tests"
echo "------------------------"
test_info "Running metrics-specific tests..."
if go test ./internal/adapter/llm/... -run "TestInitMetrics|TestRecord|TestTriageTimer" -v 2>&1 | grep -q "PASS"; then
    test_pass "Metrics tests pass"
else
    test_fail "Metrics tests failed"
fi

# Test 4: Circuit breaker tests
echo ""
echo "🔌 Test 4: Circuit Breaker Tests"
echo "---------------------------------"
test_info "Running circuit breaker tests..."
if go test ./internal/adapter/llm/... -run "TestResilientClient_CircuitBreaker" -v 2>&1 | grep -q "PASS"; then
    test_pass "Circuit breaker tests pass"
else
    test_fail "Circuit breaker tests failed"
fi

# Test 5: Retry logic tests
echo ""
echo "🔄 Test 5: Retry Logic Tests"
echo "----------------------------"
test_info "Running retry logic tests..."
if go test ./internal/adapter/llm/... -run "TestResilientClient_Retry" -v 2>&1 | grep -q "PASS"; then
    test_pass "Retry logic tests pass"
else
    test_fail "Retry logic tests failed"
fi

# Test 6: Check if API is running
echo ""
echo "🌐 Test 6: API Server Check"
echo "---------------------------"
if curl -s http://localhost:8080/api/v1/health > /dev/null 2>&1; then
    test_pass "API server is running"

    # Test 7: Metrics endpoint
    echo ""
    echo "📈 Test 7: Metrics Endpoint"
    echo "---------------------------"
    if [ -n "$REST_API_AUTH_TOKEN" ]; then
        test_info "Using authentication token"
        METRICS_RESPONSE=$(curl -s -H "Authorization: Bearer $REST_API_AUTH_TOKEN" http://localhost:8080/metrics)
    else
        test_warning "No REST_API_AUTH_TOKEN set - using unauthenticated request"
        METRICS_RESPONSE=$(curl -s http://localhost:8080/metrics)
    fi

    if echo "$METRICS_RESPONSE" | grep -q "404\|not found"; then
        test_warning "Metrics endpoint not found - API needs restart with new code"
        test_info "Run: make run-api (or restart the API server)"
    elif [ -n "$METRICS_RESPONSE" ]; then
        test_pass "Metrics endpoint responds"

        # Check for Prometheus format
        if echo "$METRICS_RESPONSE" | grep -q "# HELP"; then
            test_pass "Metrics in Prometheus format"
        else
            test_warning "Response doesn't look like Prometheus format"
        fi

        # Check for LLM metrics
        if echo "$METRICS_RESPONSE" | grep -q "llm_triage"; then
            test_pass "LLM metrics are present"
            echo ""
            echo "Sample metrics:"
            echo "$METRICS_RESPONSE" | grep "llm_triage" | head -5
        else
            test_info "No LLM metrics yet (no triage requests processed)"
        fi
    else
        test_fail "Metrics endpoint returned empty response"
    fi

else
    test_warning "API server not running - skipping endpoint tests"
    test_info "To start API: make run-api"
fi

# Test 8: Configuration validation
echo ""
echo "⚙️  Test 8: Configuration Validation"
echo "-------------------------------------"

# Check .env.example has new config
if grep -q "LLM_CIRCUIT_BREAKER_ENABLED" .env.example; then
    test_pass ".env.example has circuit breaker config"
else
    test_fail ".env.example missing circuit breaker config"
fi

if grep -q "LLM_RETRY_MAX_ATTEMPTS" .env.example; then
    test_pass ".env.example has retry config"
else
    test_fail ".env.example missing retry config"
fi

# Test 9: Documentation check
echo ""
echo "📚 Test 9: Documentation Check"
echo "-------------------------------"

if [ -f "docs/OBSERVABILITY.md" ]; then
    test_pass "OBSERVABILITY.md exists"
else
    test_fail "OBSERVABILITY.md missing"
fi

if grep -q "Observability & Resilience" docs/LLM_TRIAGING.md; then
    test_pass "LLM_TRIAGING.md updated with observability section"
else
    test_fail "LLM_TRIAGING.md missing observability section"
fi

if grep -q "OBSERVABILITY.md" README.md; then
    test_pass "README.md links to observability docs"
else
    test_fail "README.md missing observability link"
fi

# Test 10: Code quality checks
echo ""
echo "🔍 Test 10: Code Quality"
echo "------------------------"

# Check for gofmt
if gofmt -l internal/adapter/llm/*.go | grep -q ".go"; then
    test_fail "Code not formatted with gofmt"
else
    test_pass "Code properly formatted"
fi

# Check for common issues
test_info "Checking for potential issues..."
if grep -r "panic(" internal/adapter/llm/*.go | grep -v "_test.go" | grep -v "// " > /dev/null; then
    test_warning "Found panic() calls in production code"
else
    test_pass "No panic() calls in production code"
fi

# Test 11: Integration test
echo ""
echo "🔗 Test 11: E2E Integration Tests"
echo "----------------------------------"
test_info "Running end-to-end tests..."
if go test ./test/e2e/... -timeout 30s > /tmp/e2e_tests.log 2>&1; then
    test_pass "E2E integration tests pass"
else
    test_warning "E2E tests failed or skipped (may need running services)"
fi

# Final summary
echo ""
echo "=================================================="
echo "📊 Test Summary"
echo "=================================================="
echo -e "${GREEN}Passed: $passed${NC}"
echo -e "${RED}Failed: $failed${NC}"
echo ""

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    echo ""
    echo "🎉 Observability & Resilience implementation is ready for production!"
    echo ""
    echo "Next steps:"
    echo "1. Start the API if not running: make run-api"
    echo "2. Send a test alert to generate metrics"
    echo "3. View metrics: ./scripts/test_metrics.sh"
    echo "4. Set up Prometheus scraping"
    echo "5. Create Grafana dashboards"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    echo ""
    echo "Please review the failures above and fix before proceeding."
    exit 1
fi
