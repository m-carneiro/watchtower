# Observability & Resilience Implementation

## Overview

This document describes the observability and resilience features added to the Watchtower LLM triaging system.

## What Was Added

### 1. Prometheus Metrics (`internal/adapter/llm/metrics.go`)

Comprehensive metrics tracking for LLM triaging operations.

#### Metrics

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `llm_triage_requests_total` | Counter | status, reason | Track request outcomes |
| `llm_triage_duration_seconds` | Histogram | - | Measure latency |
| `llm_triage_guardrails_total` | Counter | type, action | Track guardrail activations |
| `llm_api_errors_total` | Counter | error_type | Track API errors by type |
| `llm_triage_confidence` | Histogram | - | Distribution of confidence scores |
| `llm_triage_severity` | Counter | severity | Distribution of severity levels |
| `llm_false_positive_rate` | Gauge | - | False positive percentage |

#### Usage

```go
// Initialize metrics once at startup
llm.InitMetrics()

// Record metrics during triage
timer := llm.StartTimer()
defer timer.ObserveDuration()

llm.RecordTriageRequest("success", "llm")
llm.RecordResult(result)
llm.RecordGuardrail("post", "boost")
```

### 2. Resilient HTTP Client (`internal/adapter/llm/resilient_client.go`)

Circuit breaker and retry logic for LLM API calls.

#### Features

**Circuit Breaker:**
- Opens after configurable consecutive failures (default: 5)
- Timeout period before attempting recovery (default: 30s)
- Half-open state to test recovery
- Automatic state transitions
- State change logging

**Retry Logic:**
- Exponential backoff retry for transient errors
- Configurable max retries (default: 3)
- Smart error classification (retryable vs. non-retryable)
- Respects context cancellation

#### Configuration

Environment variables:

```bash
# Circuit Breaker (enabled by default)
LLM_CIRCUIT_BREAKER_ENABLED=true
LLM_CIRCUIT_BREAKER_MAX_FAILURES=5
LLM_CIRCUIT_BREAKER_TIMEOUT_SECONDS=30

# Retry Logic
LLM_RETRY_MAX_ATTEMPTS=3
LLM_RETRY_INITIAL_INTERVAL_MS=500
LLM_RETRY_MAX_INTERVAL_MS=5000
```

#### Error Classification

**Retryable (will retry):**
- 500 Internal Server Error
- 502 Bad Gateway
- 503 Service Unavailable
- 504 Gateway Timeout
- 429 Too Many Requests
- Connection refused/reset
- Timeout errors

**Non-retryable (fail immediately):**
- 4xx errors (except 429)
- Parse errors
- Circuit breaker open

### 3. Metrics HTTP Endpoint

Added `/metrics` endpoint to REST API.

#### Access

```bash
curl -H "Authorization: Bearer $REST_API_AUTH_TOKEN" \
     http://localhost:8080/metrics
```

#### Security

- Requires authentication (same as other API endpoints)
- Can be disabled in development by not setting `REST_API_AUTH_TOKEN`

#### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'watchtower'
    authorization:
      credentials: 'your-rest-api-auth-token'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 15s
    metrics_path: /metrics
```

### 4. Integration with Triager

Updated `internal/adapter/llm/triager.go`:

- Uses `ResilientClient` instead of `*http.Client`
- Records metrics at key points in triage flow
- Classifies and records errors
- Tracks pre-filter and post-guardrail activations

### 5. Integration with Guardrails

Updated `internal/adapter/llm/guardrails.go`:

- Records guardrail activations
- Tracks pre-filter skips
- Tracks post-guardrail overrides, boosts, downgrades

## Testing

### Unit Tests

Comprehensive test coverage:

- `metrics_test.go` - Tests all metrics functions
- `resilient_client_test.go` - Tests circuit breaker and retry logic
- Updated `triager_test.go` - Tests integration with metrics

### Manual Testing

```bash
# Test metrics endpoint
./scripts/test_metrics.sh

# Send test alert to generate metrics
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $REST_API_AUTH_TOKEN" \
  -d @test/fixtures/sentinelone_alert.json

# View metrics
curl -H "Authorization: Bearer $REST_API_AUTH_TOKEN" \
     http://localhost:8080/metrics | grep llm_
```

### Circuit Breaker Testing

```bash
# Set LLM API to invalid URL to trigger failures
export LLM_API_URL=http://localhost:9999/fake
export LLM_TRIAGE_ENABLED=true
export LLM_API_KEY=test-key

# Start API
go run cmd/watchtower-api/main.go

# Send multiple alerts to trip circuit breaker
for i in {1..6}; do
  curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $REST_API_AUTH_TOKEN" \
    -d '{"alertId": "test-'$i'", ...}'
done

# Watch logs for circuit breaker events
# Expected output:
# ⚡ Circuit breaker 'llm-api' changed from closed to open
```

## Monitoring & Alerting

### Key Metrics to Monitor

1. **Success Rate**
   ```promql
   rate(llm_triage_requests_total{status="success"}[5m])
     / rate(llm_triage_requests_total[5m])
   ```

2. **Pre-Filter Hit Rate** (cost savings)
   ```promql
   rate(llm_triage_requests_total{status="skipped",reason="pre_filter"}[5m])
     / rate(llm_triage_requests_total[5m])
   ```

3. **P95 Latency**
   ```promql
   histogram_quantile(0.95, rate(llm_triage_duration_seconds_bucket[5m]))
   ```

4. **Error Rate**
   ```promql
   rate(llm_api_errors_total[5m])
   ```

5. **Circuit Breaker Open Events**
   ```promql
   rate(llm_api_errors_total{error_type="circuit_open"}[5m])
   ```

### Recommended Alerts

```yaml
groups:
  - name: watchtower_llm
    rules:
      # Circuit breaker open
      - alert: LLMCircuitBreakerOpen
        expr: rate(llm_api_errors_total{error_type="circuit_open"}[2m]) > 0
        for: 2m
        annotations:
          summary: "LLM circuit breaker is open"
          description: "Circuit breaker has been open for > 2 minutes"

      # High error rate
      - alert: LLMHighErrorRate
        expr: |
          rate(llm_triage_requests_total{status="error"}[5m])
          / rate(llm_triage_requests_total[5m]) > 0.1
        for: 5m
        annotations:
          summary: "LLM error rate > 10%"

      # High latency
      - alert: LLMHighLatency
        expr: |
          histogram_quantile(0.95,
            rate(llm_triage_duration_seconds_bucket[5m])) > 5
        for: 5m
        annotations:
          summary: "LLM P95 latency > 5s"

      # Low pre-filter hit rate (cost optimization)
      - alert: LLMLowPreFilterRate
        expr: |
          rate(llm_triage_requests_total{status="skipped",reason="pre_filter"}[5m])
          / rate(llm_triage_requests_total[5m]) < 0.1
        for: 30m
        annotations:
          summary: "Pre-filter hit rate < 10%"
          description: "Consider adding more known good/bad indicators"
```

## Grafana Dashboard

Create panels for:

### LLM Performance
- P50/P95/P99 latency
- Success rate
- Requests per second
- Error rate by type

### Cost Optimization
- Pre-filter hit rate
- Estimated cost savings
- Requests skipped

### Guardrails
- Guardrail activation rate
- Override rate
- Confidence score distribution

### Reliability
- Circuit breaker state
- Retry rate
- Error types distribution

## Benefits

### Observability
- ✅ Full visibility into LLM triaging performance
- ✅ Track accuracy metrics (confidence, severity distribution)
- ✅ Monitor cost savings from pre-filters
- ✅ Identify performance bottlenecks

### Resilience
- ✅ Circuit breaker prevents cascading failures
- ✅ Retry logic handles transient errors
- ✅ Configurable timeouts and thresholds
- ✅ Automatic recovery when API becomes healthy

### Operations
- ✅ Prometheus-native metrics
- ✅ Easy integration with existing monitoring
- ✅ Alerting on key metrics
- ✅ Debug visibility via logs

## Files Modified

### New Files
- `internal/adapter/llm/metrics.go` (167 lines)
- `internal/adapter/llm/resilient_client.go` (257 lines)
- `internal/adapter/llm/metrics_test.go` (161 lines)
- `internal/adapter/llm/resilient_client_test.go` (361 lines)
- `scripts/test_metrics.sh` (executable)
- `docs/OBSERVABILITY.md` (this file)

### Modified Files
- `internal/adapter/llm/triager.go` - Added metrics and resilient client
- `internal/adapter/llm/guardrails.go` - Added metrics recording
- `cmd/watchtower-api/main.go` - Added /metrics endpoint and initialization
- `.env.example` - Added configuration options
- `docs/LLM_TRIAGING.md` - Added observability section
- `go.mod` - Added dependencies

### Dependencies Added
- `github.com/prometheus/client_golang` - Prometheus client
- `github.com/sony/gobreaker` - Circuit breaker
- `github.com/cenkalti/backoff/v4` - Exponential backoff

## Rollout Strategy

### Phase 1: Deploy with Defaults (Recommended)
Circuit breaker is **enabled by default** for immediate protection:
- No configuration changes needed
- Automatic resilience out of the box
- Monitor metrics to tune thresholds

### Phase 2: Tune Based on Metrics (After 1-2 Weeks)
- Adjust circuit breaker thresholds based on observed failure patterns
- Tune retry intervals based on API latency
- Add custom alerting rules

### Phase 3: Optional Customization
- Add more known good/bad indicators to pre-filters
- Adjust guardrail confidence thresholds
- Fine-tune retry logic per environment

## Rollback

If issues arise:

```bash
# Disable circuit breaker (not recommended)
LLM_CIRCUIT_BREAKER_ENABLED=false

# Disable retries
LLM_RETRY_MAX_ATTEMPTS=0

# Circuit breaker automatically recovers, no manual intervention needed
```

## Next Steps

1. **Deploy to production** with default settings
2. **Set up Prometheus scraping** of /metrics endpoint
3. **Create Grafana dashboard** with recommended panels
4. **Configure alerting rules** for key metrics
5. **Monitor for 1-2 weeks** to establish baselines
6. **Tune configuration** based on observed behavior
7. **Document patterns** and add to known good/bad lists

## Related Documentation

- [LLM Triaging Guide](LLM_TRIAGING.md) - Overall LLM triaging documentation
- [LLM Guardrails Guide](LLM_GUARDRAILS.md) - Detailed guardrails documentation
- [README.md](../README.md) - Main project documentation

---

**Implementation completed**: 2026-02-02

**Estimated effort**: 4-6 hours

**Risk level**: Low (additive features, can be toggled off)
