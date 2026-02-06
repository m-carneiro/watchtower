#!/bin/bash
# Test script for LLM metrics endpoint

set -e

echo "🔍 Testing Watchtower LLM Metrics Endpoint"
echo ""

# Check if REST_API_AUTH_TOKEN is set
if [ -z "$REST_API_AUTH_TOKEN" ]; then
    echo "⚠️  REST_API_AUTH_TOKEN not set - using empty token (dev mode)"
    AUTH_HEADER=""
else
    echo "✅ Using REST_API_AUTH_TOKEN for authentication"
    AUTH_HEADER="Authorization: Bearer $REST_API_AUTH_TOKEN"
fi

API_URL="${API_URL:-http://localhost:8080}"

echo ""
echo "📊 Fetching metrics from $API_URL/metrics"
echo ""

# Fetch metrics
if [ -n "$AUTH_HEADER" ]; then
    METRICS=$(curl -s -H "$AUTH_HEADER" "$API_URL/metrics")
else
    METRICS=$(curl -s "$API_URL/metrics")
fi

# Check if metrics were returned
if [ -z "$METRICS" ]; then
    echo "❌ No metrics returned - is the API running?"
    exit 1
fi

echo "✅ Metrics endpoint responding"
echo ""

# Extract LLM-specific metrics
echo "📈 LLM Triaging Metrics:"
echo ""
echo "$METRICS" | grep -E "^llm_" | grep -v "^#" || echo "⚠️  No LLM metrics found yet (no triage requests processed)"

echo ""
echo "🔧 Available Metrics:"
echo ""
echo "- llm_triage_requests_total"
echo "- llm_triage_duration_seconds"
echo "- llm_triage_guardrails_total"
echo "- llm_api_errors_total"
echo "- llm_triage_confidence"
echo "- llm_triage_severity"
echo "- llm_false_positive_rate"

echo ""
echo "💡 To see metrics in action:"
echo ""
echo "1. Enable LLM triaging: export LLM_TRIAGE_ENABLED=true"
echo "2. Set API key: export LLM_API_KEY=sk-your-key"
echo "3. Send a test alert to trigger triage"
echo "4. Re-run this script to see metrics"
echo ""
echo "🔗 Prometheus config example:"
echo ""
cat << 'EOF'
scrape_configs:
  - job_name: 'watchtower'
    authorization:
      credentials: 'your-rest-api-auth-token'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 15s
    metrics_path: /metrics
EOF
