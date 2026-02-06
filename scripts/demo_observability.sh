#!/bin/bash
# Live demonstration of Observability & Resilience features

set -e

echo "🎬 Watchtower Observability & Resilience Demo"
echo "============================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

demo_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

demo_result() {
    echo -e "${GREEN}✓ $1${NC}"
}

demo_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if API is running
demo_step "Step 1: Checking API status..."
if curl -s http://localhost:8080/api/v1/health > /dev/null 2>&1; then
    demo_info "API is already running on port 8080"
    echo ""
    read -p "Do you want to restart it with the new code? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        demo_step "Stopping existing API..."
        # Try to find and kill the process
        PID=$(lsof -ti:8080 || true)
        if [ -n "$PID" ]; then
            kill $PID || true
            sleep 2
            demo_result "API stopped"
        fi
    else
        demo_info "Using existing API instance"
        echo ""
    fi
else
    demo_info "No API running - will start new instance"
    echo ""
fi

# Check if we need to start API
if ! curl -s http://localhost:8080/api/v1/health > /dev/null 2>&1; then
    demo_step "Step 2: Starting Watchtower API with new code..."
    demo_info "Building..."
    go build -o /tmp/watchtower-api cmd/watchtower-api/main.go

    demo_info "Starting API in background..."
    # Start API in background
    nohup /tmp/watchtower-api > /tmp/watchtower-api.log 2>&1 &
    API_PID=$!
    echo $API_PID > /tmp/watchtower-api.pid

    demo_info "Waiting for API to start..."
    for i in {1..10}; do
        if curl -s http://localhost:8080/api/v1/health > /dev/null 2>&1; then
            demo_result "API started successfully (PID: $API_PID)"
            break
        fi
        sleep 1
    done
    echo ""
else
    demo_result "API is running"
    echo ""
fi

# Test metrics endpoint
demo_step "Step 3: Testing /metrics endpoint..."
echo ""

if [ -n "$REST_API_AUTH_TOKEN" ]; then
    demo_info "Using authentication: Bearer \$REST_API_AUTH_TOKEN"
    METRICS=$(curl -s -H "Authorization: Bearer $REST_API_AUTH_TOKEN" http://localhost:8080/metrics)
else
    demo_info "No REST_API_AUTH_TOKEN set - using unauthenticated request"
    METRICS=$(curl -s http://localhost:8080/metrics)
fi

if echo "$METRICS" | grep -q "# HELP"; then
    demo_result "Metrics endpoint working!"
    echo ""
    echo "Sample Prometheus metrics:"
    echo "$METRICS" | grep -E "^(# HELP|# TYPE|go_info)" | head -10
    echo "..."
    echo ""

    # Check for LLM metrics
    if echo "$METRICS" | grep -q "llm_triage"; then
        demo_result "LLM metrics found!"
        echo ""
        echo "LLM Metrics:"
        echo "$METRICS" | grep "llm_triage" | head -10
    else
        demo_info "No LLM metrics yet (no triage requests processed)"
        echo ""
        echo "To generate LLM metrics:"
        echo "1. Set LLM_TRIAGE_ENABLED=true"
        echo "2. Set LLM_API_KEY=your-key"
        echo "3. Send a test alert via webhook"
    fi
else
    demo_info "Metrics endpoint returned unexpected format"
    echo "Response: $METRICS"
fi

echo ""
demo_step "Step 4: Demonstrating Circuit Breaker..."
echo ""

demo_info "Setting up test with fake LLM endpoint to trigger circuit breaker..."
echo ""

# Create a test config that will fail
export LLM_TRIAGE_ENABLED=true
export LLM_API_KEY=test-key
export LLM_API_URL=http://localhost:9999/fake  # This will fail
export LLM_CIRCUIT_BREAKER_ENABLED=true
export LLM_CIRCUIT_BREAKER_MAX_FAILURES=3
export LLM_RETRY_MAX_ATTEMPTS=0  # No retries for faster demo

demo_info "Configuration:"
echo "  - LLM_API_URL: http://localhost:9999/fake (will fail)"
echo "  - Circuit breaker max failures: 3"
echo "  - Retries: disabled (for faster demo)"
echo ""

demo_info "This would normally trigger the circuit breaker after 3 failures."
demo_info "To see this in action, send alerts via the webhook endpoint."
echo ""

demo_step "Step 5: Available Metrics"
echo ""
echo "The following Prometheus metrics are available:"
echo ""
echo "1. llm_triage_requests_total"
echo "   - Tracks: Total triage requests by status and reason"
echo "   - Labels: status=[success|error|skipped], reason=[pre_filter|llm|...]"
echo ""
echo "2. llm_triage_duration_seconds"
echo "   - Tracks: Latency of triage operations"
echo "   - Type: Histogram with buckets"
echo ""
echo "3. llm_triage_guardrails_total"
echo "   - Tracks: Guardrail activations"
echo "   - Labels: type=[pre|post], action=[skip|override|boost]"
echo ""
echo "4. llm_api_errors_total"
echo "   - Tracks: API errors by type"
echo "   - Labels: error_type=[timeout|auth|rate_limit|circuit_open|...]"
echo ""
echo "5. llm_triage_confidence"
echo "   - Tracks: Distribution of confidence scores"
echo "   - Type: Histogram"
echo ""
echo "6. llm_triage_severity"
echo "   - Tracks: Distribution of severity levels"
echo "   - Labels: severity=[critical|high|medium|low|info]"
echo ""
echo "7. llm_false_positive_rate"
echo "   - Tracks: Percentage of false positives"
echo "   - Type: Gauge"
echo ""

demo_step "Step 6: Example Prometheus Queries"
echo ""
echo "# Success rate"
echo "rate(llm_triage_requests_total{status=\"success\"}[5m])"
echo ""
echo "# Pre-filter hit rate (cost savings)"
echo "rate(llm_triage_requests_total{status=\"skipped\",reason=\"pre_filter\"}[5m])"
echo ""
echo "# P95 latency"
echo "histogram_quantile(0.95, rate(llm_triage_duration_seconds_bucket[5m]))"
echo ""
echo "# Circuit breaker open events"
echo "rate(llm_api_errors_total{error_type=\"circuit_open\"}[5m])"
echo ""

demo_step "Demo Complete!"
echo ""
echo "=========================================="
echo "📊 Summary"
echo "=========================================="
echo ""
echo "✅ API is running with observability features"
echo "✅ Metrics endpoint: http://localhost:8080/metrics"
echo "✅ Circuit breaker: Enabled by default"
echo "✅ Retry logic: Enabled (3 retries with exponential backoff)"
echo ""
echo "Next steps:"
echo ""
echo "1. Set up Prometheus scraping:"
echo "   See: docs/OBSERVABILITY.md#prometheus-configuration"
echo ""
echo "2. Create Grafana dashboards:"
echo "   See: docs/OBSERVABILITY.md#grafana-dashboard"
echo ""
echo "3. Configure alerting rules:"
echo "   See: docs/OBSERVABILITY.md#alerting-rules"
echo ""
echo "4. Test with real LLM:"
echo "   export LLM_TRIAGE_ENABLED=true"
echo "   export LLM_API_KEY=your-api-key"
echo "   export LLM_API_URL=https://api.openai.com/v1/chat/completions"
echo ""

# Offer to stop API
echo ""
read -p "Stop the API? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f /tmp/watchtower-api.pid ]; then
        PID=$(cat /tmp/watchtower-api.pid)
        kill $PID || true
        rm /tmp/watchtower-api.pid
        demo_result "API stopped"
    else
        demo_info "No PID file found - API may have been started externally"
    fi
fi

echo ""
echo "🎉 Demo complete!"
