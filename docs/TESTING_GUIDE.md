# Watchtower Testing Guide

Complete guide for testing all Watchtower features including IOC queries, SentinelOne integration, LLM triaging, SIEM feeds, and more.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Basic IOC Tests](#basic-ioc-tests)
3. [SentinelOne Integration Tests](#sentinelone-integration-tests)
4. [LLM Triaging Tests](#llm-triaging-tests)
5. [SIEM Feed Tests](#siem-feed-tests)
6. [Component Extraction Tests](#component-extraction-tests)
7. [End-to-End Tests](#end-to-end-tests)
8. [Performance Tests](#performance-tests)
9. [Error Handling Tests](#error-handling-tests)

## Prerequisites

### 1. Setup Environment

```bash
# Ensure database is running
make docker-up

# Run migrations
make db-migrate

# Ingest threat intelligence
make ingestion-dev

# Start REST API (in separate terminal)
make run-api-dev
```

### 2. Verify Services

```bash
# Check API health
curl http://localhost:8080/api/v1/health

# Expected response:
# {"status":"healthy","timestamp":"2026-02-01T...","service":"watchtower-api"}

# Check database
make db-shell
# Then: SELECT COUNT(*) FROM iocs;
# Should show >1,000,000 IOCs
```

---

## Basic IOC Tests

### Test 1: Check Known Malicious IP

**Scenario:** Verify detection of a known malicious IP from threat intelligence.

**Command:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/check?value=115.50.92.159" | jq .
```

**Expected Result:**
```json
{
  "exists": true,
  "value": "115.50.92.159",
  "type": "ip",
  "source": "abusech-urlhaus",
  "threat_type": "malware_download",
  "tags": ["extracted-from-url", "elf", "mirai", "ua-wget"],
  "first_seen": "2026-02-01T22:18:12-03:00",
  "date_ingested": "2026-02-01T22:45:51-03:00"
}
```

**✅ Pass Criteria:** `exists: true` and threat intelligence data populated

---

### Test 2: Check Clean IP

**Scenario:** Verify that clean IPs return negative result.

**Command:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/check?value=8.8.8.8" | jq .
```

**Expected Result:**
```json
{
  "exists": false,
  "value": "8.8.8.8"
}
```

**✅ Pass Criteria:** `exists: false`

---

### Test 3: Search for Package (Supply Chain)

**Scenario:** Search for a malicious npm package.

**Command:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/search?value=lodash" | jq .
```

**Expected Result:**
```json
{
  "value": "lodash",
  "count": 1,
  "sightings": [
    {
      "value": "lodash",
      "type": "package",
      "source": "google-osv-npm",
      "threat_type": "supply_chain_malware",
      "tags": ["MAL-2026-XX", "osv"],
      "version": "",
      "first_seen": "...",
      "date_ingested": "..."
    }
  ]
}
```

**✅ Pass Criteria:** `count > 0` with sightings array populated

---

### Test 4: Search with Version Specific

**Scenario:** Search for package with specific version.

**Command:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/search?value=lodash@4.17.0" | jq .
```

**Expected Result:**
```json
{
  "value": "lodash@4.17.0",
  "count": 1,
  "sightings": [...]
}
```

**✅ Pass Criteria:** Returns version-specific results

---

### Test 5: Component Extraction - IP from URL

**Scenario:** Search for IP that was extracted from a URL.

**Setup:**
```bash
# Verify URL exists in database
curl -s "http://localhost:8080/api/v1/iocs/check?value=http://77.90.185.212/huhu/titanjr.arm5" | jq .
# Should return exists: true

# Now search for extracted IP component
curl -s "http://localhost:8080/api/v1/iocs/search?value=77.90.185.212" | jq .
```

**Expected Result:**
```json
{
  "value": "77.90.185.212",
  "count": 1,
  "sightings": [
    {
      "value": "77.90.185.212",
      "type": "ip",
      "source": "abusech-urlhaus",
      "tags": ["extracted-from-url", "elf", "mirai", ...],
      ...
    }
  ]
}
```

**✅ Pass Criteria:** Finds extracted IP component even though original was URL

---

## SentinelOne Integration Tests

### Test 6: Basic SentinelOne Webhook (Without LLM)

**Scenario:** Receive and process SentinelOne alert without LLM triaging.

**Setup:**
```bash
# Ensure LLM is disabled
export LLM_TRIAGE_ENABLED=false
```

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-secret" \
  -d '{
    "alertId": "test-001",
    "threatName": "Test.Malware.Generic",
    "classification": "Malware",
    "indicators": [
      {"type": "IPV4", "value": "115.50.92.159"}
    ],
    "endpoint": {
      "computerName": "TEST-SERVER-01",
      "osType": "linux",
      "agentVersion": "23.1.2.5"
    },
    "timestamp": "2026-02-01T12:00:00Z"
  }' | jq .
```

**Expected Result:**
```json
{
  "status": "received",
  "alert_id": "test-001",
  "indicators_enriched": 1,
  "indicators_in_db": 1,
  "slack_notification": false
}
```

**✅ Pass Criteria:**
- Status 200 OK
- `indicators_in_db: 1` (IP found in database)
- Log shows: "📥 Received SentinelOne alert: test-001"

---

### Test 7: SentinelOne with Unknown IOC

**Scenario:** Send alert with IOC not in database.

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-002",
    "threatName": "Unknown.Suspicious.Activity",
    "classification": "Suspicious",
    "indicators": [
      {"type": "IPV4", "value": "1.2.3.4"},
      {"type": "SHA256", "value": "abc123def456..."}
    ],
    "endpoint": {
      "computerName": "WORKSTATION-05",
      "osType": "windows"
    }
  }' | jq .
```

**Expected Result:**
```json
{
  "status": "received",
  "alert_id": "test-002",
  "indicators_enriched": 2,
  "indicators_in_db": 0,
  "slack_notification": false
}
```

**✅ Pass Criteria:**
- `indicators_in_db: 0` (IOCs not found)
- No errors in logs

---

### Test 8: SentinelOne with Pattern Matching Fallback

**Scenario:** IP should be found via pattern matching (LIKE query) when not in exact match.

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-003",
    "threatName": "C2.Communication",
    "classification": "Malware",
    "indicators": [
      {"type": "IPV4", "value": "77.90.185.212"}
    ],
    "endpoint": {
      "computerName": "SERVER-DMZ-02",
      "osType": "linux"
    }
  }' | jq .
```

**Check Logs:**
```
Expected log entries:
- "🔍 Exact match failed for 77.90.185.212, trying pattern search..."
- "✅ Found via pattern matching"
```

**✅ Pass Criteria:**
- IP found via fallback search
- `indicators_in_db: 1`

---

## LLM Triaging Tests

### Test 9: LLM Triaging - Known Malicious IOC

**Scenario:** LLM analyzes confirmed malicious IOC and assigns high severity.

**Setup:**
```bash
# Enable LLM triaging
export LLM_TRIAGE_ENABLED=true
export LLM_API_KEY=sk-your-openai-key
export LLM_MODEL=gpt-4o-mini

# Restart API
pkill -f watchtower-api && make run-api-dev &
```

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-llm-001",
    "threatName": "Emotet.C2.Communication",
    "classification": "Malware",
    "indicators": [
      {"type": "IPV4", "value": "115.50.92.159"}
    ],
    "endpoint": {
      "computerName": "FINANCE-WS-12",
      "osType": "windows"
    }
  }' | jq .
```

**Expected Logs:**
```
🤖 Running LLM triaging for alert test-llm-001...
✅ LLM triaging complete - Severity: high, Priority: 2, Confidence: 95%
✅ Slack notification sent for alert test-llm-001
```

**Expected Slack Message:**
```
🟠 HIGH Severity Threat Detected

🤖 AI Analysis
Confirmed malicious IP with known threat intelligence sources

Alert ID: test-llm-001
Threat: Emotet.C2.Communication
Endpoint: FINANCE-WS-12
Priority: P2

📊 Detailed Analysis
The endpoint communicated with a known malicious IP associated
with Emotet botnet infrastructure...

✅ Recommended Actions
• Immediately isolate the endpoint
• Capture memory dump for forensic analysis
• Review network logs for lateral movement
...

🟢 AI Confidence: 95%
```

**✅ Pass Criteria:**
- LLM analysis in logs
- Severity: high or critical
- Confidence: > 80%
- Slack message contains AI insights

---

### Test 10: LLM Triaging - False Positive Detection

**Scenario:** LLM identifies benign activity and suppresses alert.

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-llm-002",
    "threatName": "Suspicious.DNS.Query",
    "classification": "Suspicious",
    "indicators": [
      {"type": "DOMAIN", "value": "update.microsoft.com"}
    ],
    "endpoint": {
      "computerName": "LAPTOP-HR-05",
      "osType": "windows"
    }
  }' | jq .
```

**Expected Response:**
```json
{
  "status": "received",
  "alert_id": "test-llm-002",
  "indicators_enriched": 1,
  "indicators_in_db": 0,
  "slack_notification": false,
  "llm_triaged": true,
  "false_positive": true
}
```

**Expected Logs:**
```
🤖 Running LLM triaging for alert test-llm-002...
✅ LLM triaging complete - Severity: info, Priority: 5, Confidence: 95%
⏭️  Skipping notification - LLM identified as likely false positive
```

**✅ Pass Criteria:**
- `false_positive: true`
- No Slack notification sent
- Log shows alert suppression

---

### Test 11: LLM Triaging - Medium Severity

**Scenario:** Ambiguous threat gets medium severity and analyst recommendation.

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-llm-003",
    "threatName": "Unusual.Outbound.Connection",
    "classification": "Suspicious",
    "indicators": [
      {"type": "IPV4", "value": "203.0.113.100"}
    ],
    "endpoint": {
      "computerName": "DEV-WORKSTATION-08",
      "osType": "linux"
    }
  }' | jq .
```

**Expected Logs:**
```
✅ LLM triaging complete - Severity: medium, Priority: 3, Confidence: 70%
```

**Expected Slack Message:**
```
🟡 MEDIUM Severity Threat Detected

🤖 AI Analysis
Suspicious activity requires investigation - low confidence in threat classification

Priority: P3

✅ Recommended Actions
• Review connection logs
• Interview endpoint user
• Monitor for additional suspicious activity
...
```

**✅ Pass Criteria:**
- Severity: medium
- Priority: 3
- Confidence: 60-80%
- Recommended manual review

---

### Test 12: LLM Triaging - Fallback on API Failure

**Scenario:** LLM API fails, system falls back to standard notification.

**Setup:**
```bash
# Use invalid API key
export LLM_API_KEY=invalid-key
```

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-llm-004",
    "threatName": "Test.Fallback",
    "classification": "Malware",
    "indicators": [{"type": "IPV4", "value": "115.50.92.159"}],
    "endpoint": {"computerName": "TEST-01", "osType": "windows"}
  }' | jq .
```

**Expected Logs:**
```
🤖 Running LLM triaging for alert test-llm-004...
⚠️  LLM triaging failed: LLM API error (status 401): ...
✅ Slack notification sent for alert test-llm-004
```

**✅ Pass Criteria:**
- Error logged but not fatal
- Falls back to standard notification
- No LLM insights in Slack message

---

## SIEM Feed Tests

### Test 13: CEF Feed Export

**Scenario:** Export IOC feed in CEF format for SIEM ingestion.

**Command:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/feed?format=cef&since=24h" | head -20
```

**Expected Result:**
```
CEF:0|Watchtower|ThreatIntel|1.0|package|PACKAGE IOC Detected|6|src=x-clients-features cn1Label=ConfidenceScore cn1=70 cs1Label=ThreatType cs1=supply_chain_malware cs2Label=Sources cs2=google-osv-npm cs3Label=Tags cs3=MAL-2026-95,osv rt=1767864886000
CEF:0|Watchtower|ThreatIntel|1.0|package|PACKAGE IOC Detected|6|src=shopify-perf-kit cn1Label=ConfidenceScore cn1=70 cs1Label=ThreatType cs1=supply_chain_malware cs2Label=Sources cs2=google-osv-npm cs3Label=Tags cs3=MAL-2026-94,osv rt=1767864715000
...
```

**Validation:**
```bash
# Count entries
curl -s "http://localhost:8080/api/v1/iocs/feed?format=cef&since=24h" | wc -l
# Expected: ~10,000 lines
```

**✅ Pass Criteria:**
- Valid CEF format
- Contains real IOC data
- Returns up to 10,000 entries

---

### Test 14: STIX Feed Export

**Scenario:** Export IOC feed in STIX 2.1 format.

**Command:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/feed?format=stix&since=24h" | jq '.objects | length'
```

**Expected Result:**
```
10000
```

**Detailed Inspection:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/feed?format=stix&since=24h" | jq '.objects[0]'
```

**Expected Structure:**
```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--...",
  "created": "2026-02-02T01:55:06Z",
  "modified": "2026-02-02T01:55:06Z",
  "name": "PACKAGE Indicator",
  "pattern": "[software:name = 'package-name']",
  "pattern_type": "stix",
  "valid_from": "...",
  "indicator_types": ["malicious-activity", "supply-chain-compromise"],
  "confidence": 70,
  "labels": ["MAL-2026-XX", "osv"],
  "external_references": [
    {
      "source_name": "google-osv-npm",
      "url": "https://osv.dev"
    }
  ]
}
```

**✅ Pass Criteria:**
- Valid STIX 2.1 JSON
- Objects array populated
- Correct pattern types for each IOC type

---

### Test 15: SIEM Feed Time Range

**Scenario:** Test different time range parameters.

**Commands:**
```bash
# Last hour
curl -s "http://localhost:8080/api/v1/iocs/feed?format=cef&since=1h" | wc -l

# Last 6 hours
curl -s "http://localhost:8080/api/v1/iocs/feed?format=cef&since=6h" | wc -l

# Last 7 days
curl -s "http://localhost:8080/api/v1/iocs/feed?format=cef&since=168h" | wc -l
```

**✅ Pass Criteria:**
- 1h < 6h < 7d (more results for longer timeframes)
- All return valid data
- Max 10,000 entries per request

---

## Component Extraction Tests

### Test 16: URL Component Extraction - Multiple Components

**Scenario:** Verify URL is split into URL + IP + domain components.

**Setup:**
```bash
# Check database for example
psql postgres://admin:secretpassword@localhost:5432/watchtower \
  -c "SELECT value, type FROM iocs WHERE value = 'http://115.50.92.159:53819/bin.sh';"
```

**Test Queries:**
```bash
# 1. Original URL
curl -s "http://localhost:8080/api/v1/iocs/check?value=http://115.50.92.159:53819/bin.sh" | jq '.exists'
# Expected: true

# 2. Extracted IP
curl -s "http://localhost:8080/api/v1/iocs/check?value=115.50.92.159" | jq '.exists'
# Expected: true

# 3. Verify extraction tag
curl -s "http://localhost:8080/api/v1/iocs/search?value=115.50.92.159" | jq '.sightings[0].tags'
# Expected: Contains "extracted-from-url"
```

**✅ Pass Criteria:**
- Both URL and IP findable
- Extracted component has correct tag
- Both share same threat information

---

### Test 17: Domain Extraction from URL

**Scenario:** Extract domain from URL with domain host.

**Query Database:**
```bash
psql postgres://admin:secretpassword@localhost:5432/watchtower \
  -c "SELECT value, type FROM iocs WHERE value LIKE 'http://example-malware.com%' LIMIT 1;"
```

**Test:**
```bash
# If you find a domain-based URL, test extraction
curl -s "http://localhost:8080/api/v1/iocs/search?value=example-malware.com" | jq .
```

**✅ Pass Criteria:**
- Domain extracted separately
- Type: "domain"
- Contains "extracted-from-url" tag

---

## End-to-End Tests

### Test 18: Complete SentinelOne → Slack Flow

**Scenario:** Full workflow from alert reception to Slack notification with LLM triaging.

**Prerequisites:**
```bash
# Configure all services
export LLM_TRIAGE_ENABLED=true
export LLM_API_KEY=sk-your-key
export SLACK_BOT_TOKEN=xoxb-your-token
export SLACK_CHANNEL_SECURITY=#security-alerts
```

**Execute:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "e2e-test-001",
    "threatName": "Ransomware.Detected",
    "classification": "Malware",
    "indicators": [
      {"type": "IPV4", "value": "115.50.92.159"},
      {"type": "SHA256", "value": "abc123..."}
    ],
    "endpoint": {
      "computerName": "PROD-DB-SERVER-01",
      "osType": "linux",
      "agentVersion": "23.1.2.5"
    },
    "timestamp": "2026-02-01T12:00:00Z"
  }'
```

**Verification Steps:**
1. **Check API Response:**
   - Status: 200 OK
   - indicators_in_db: 1

2. **Check Logs:**
   ```
   📥 Received SentinelOne alert: e2e-test-001
   🤖 Running LLM triaging...
   ✅ LLM triaging complete - Severity: critical
   ✅ Slack notification sent
   ```

3. **Check Slack Channel:**
   - Message received
   - Contains AI analysis
   - Shows enriched IOC data
   - Has recommended actions

**✅ Pass Criteria:**
- All steps complete successfully
- <5 seconds total latency
- Slack message matches expected format

---

### Test 19: Datadog SIEM Integration (End-to-End)

**Scenario:** Test full ingestion pipeline to Datadog.

**Setup:**
```bash
# Configure Datadog
cp .env.datadog.example .env.datadog
# Edit with your credentials

# Install dependencies
pip3 install datadog-api-client requests
```

**Execute:**
```bash
source .env.datadog
python3 scripts/datadog_ingester.py
```

**Expected Output:**
```
🚀 Watchtower → Datadog Ingestion
📥 Fetching CEF feed from Watchtower...
✅ Fetched feed successfully
📤 Sending 10000 IOCs to Datadog...
  ✅ Sent batch 1/100 (100 IOCs)
  ✅ Sent batch 2/100 (100 IOCs)
  ...
✅ Ingestion complete
```

**Verification in Datadog:**
```
1. Go to Logs → Explorer
2. Filter: source:watchtower
3. Verify logs appear
4. Check CEF parsing
```

**✅ Pass Criteria:**
- No errors during ingestion
- Logs visible in Datadog
- CEF fields parsed correctly

---

### Test 20: Elastic Cloud SIEM Integration (End-to-End)

**Scenario:** Test full ingestion pipeline to Elastic Cloud.

**Setup:**
```bash
# Configure Elastic
cp .env.elastic.example .env.elastic
# Edit with your credentials

# Install dependencies
pip3 install elasticsearch requests
```

**Execute:**
```bash
source .env.elastic
python3 scripts/elastic_ingester.py
```

**Expected Output:**
```
🚀 Watchtower → Elastic Cloud Ingestion
🔌 Connecting to Elastic Cloud...
✅ Connected to Elasticsearch cluster
📥 Fetching STIX feed from Watchtower...
✅ Fetched feed successfully
📤 Ingesting 10000 STIX indicators...
  ✅ Successfully indexed: 10000
✅ Ingestion complete
```

**Verification in Kibana:**
```
1. Go to Discover
2. Index pattern: watchtower-iocs-*
3. Verify documents appear
4. Check field mappings
```

**✅ Pass Criteria:**
- No errors during ingestion
- Documents indexed in Elasticsearch
- Kibana shows data

---

## Performance Tests

### Test 21: API Response Time

**Scenario:** Measure API latency under normal load.

**Commands:**
```bash
# CheckIOC latency
time curl -s "http://localhost:8080/api/v1/iocs/check?value=115.50.92.159" > /dev/null

# SearchIOC latency
time curl -s "http://localhost:8080/api/v1/iocs/search?value=lodash" > /dev/null

# Feed export latency
time curl -s "http://localhost:8080/api/v1/iocs/feed?format=cef&since=1h" > /dev/null
```

**Expected Performance:**
- CheckIOC: < 50ms
- SearchIOC: < 100ms
- Feed (1h): < 2s
- Feed (24h): < 5s

**✅ Pass Criteria:** All within expected ranges

---

### Test 22: Concurrent Requests

**Scenario:** Test API under concurrent load.

**Command:**
```bash
# 100 concurrent requests
for i in {1..100}; do
  curl -s "http://localhost:8080/api/v1/iocs/check?value=115.50.92.159" > /dev/null &
done
wait

echo "All requests completed"
```

**Monitor:**
```bash
# Check logs for errors
tail -f /tmp/watchtower-api.log

# Check response times
```

**✅ Pass Criteria:**
- No errors
- All requests complete
- Average latency < 200ms

---

## Error Handling Tests

### Test 23: Invalid JSON Payload

**Scenario:** Send malformed JSON to webhook.

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{invalid json}'
```

**Expected Response:**
```json
{
  "error": "invalid JSON payload"
}
```

**Expected Status:** 400 Bad Request

**✅ Pass Criteria:** Graceful error handling, no crash

---

### Test 24: Missing Required Fields

**Scenario:** Send incomplete webhook payload.

**Command:**
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-incomplete"
  }'
```

**Expected Behavior:**
- Accepts request (partial data better than none)
- Logs warning
- Returns 200 OK

**✅ Pass Criteria:** No crash, error logged

---

### Test 25: Database Connection Failure

**Scenario:** Test behavior when database is unavailable.

**Setup:**
```bash
# Stop database
docker stop watchtower-postgres-1
```

**Command:**
```bash
curl -s "http://localhost:8080/api/v1/iocs/check?value=test" | jq .
```

**Expected:**
- Error response
- Status: 500 Internal Server Error
- Error logged

**Cleanup:**
```bash
# Restart database
docker start watchtower-postgres-1
```

**✅ Pass Criteria:** Graceful degradation, clear error message

---

## Test Summary Script

### Run All Tests Automatically

**Create:** `scripts/run_all_tests.sh`

```bash
#!/bin/bash

echo "======================================"
echo "Watchtower Automated Test Suite"
echo "======================================"
echo ""

# Test counter
PASSED=0
FAILED=0

# Function to run test
run_test() {
    local name="$1"
    local command="$2"
    local expected="$3"

    echo "Running: $name"
    result=$(eval "$command" 2>&1)

    if echo "$result" | grep -q "$expected"; then
        echo "✅ PASSED: $name"
        ((PASSED++))
    else
        echo "❌ FAILED: $name"
        echo "   Expected: $expected"
        echo "   Got: $result"
        ((FAILED++))
    fi
    echo ""
}

# Run tests
run_test "Health Check" \
    "curl -s http://localhost:8080/api/v1/health | jq -r .status" \
    "healthy"

run_test "Known Malicious IP" \
    "curl -s 'http://localhost:8080/api/v1/iocs/check?value=115.50.92.159' | jq -r .exists" \
    "true"

run_test "Clean IP" \
    "curl -s 'http://localhost:8080/api/v1/iocs/check?value=8.8.8.8' | jq -r .exists" \
    "false"

run_test "Package Search" \
    "curl -s 'http://localhost:8080/api/v1/iocs/search?value=lodash' | jq -r .count" \
    "[0-9]+"

run_test "CEF Feed Export" \
    "curl -s 'http://localhost:8080/api/v1/iocs/feed?format=cef&since=1h' | head -1 | grep -o 'CEF:0'" \
    "CEF:0"

# Summary
echo "======================================"
echo "Test Results:"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"
echo "======================================"

if [ $FAILED -eq 0 ]; then
    echo "✅ All tests passed!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
```

**Run:**
```bash
chmod +x scripts/run_all_tests.sh
./scripts/run_all_tests.sh
```

---

## Troubleshooting

### Common Issues

**Issue:** Tests failing with "Connection refused"
**Solution:**
```bash
# Ensure API is running
make run-api-dev

# Check port
netstat -an | grep 8080
```

**Issue:** No IOCs returned
**Solution:**
```bash
# Re-run ingestion
make ingestion-dev

# Verify database
make db-shell
SELECT COUNT(*) FROM iocs;
```

**Issue:** LLM tests timeout
**Solution:**
```bash
# Check API key
echo $LLM_API_KEY

# Try with haiku (faster)
export LLM_MODEL=gpt-4o-mini
```

---

## Continuous Integration

### GitHub Actions Example

```yaml
name: Watchtower Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v2

      - name: Start services
        run: |
          make docker-up
          make db-migrate
          make ingestion &
          make run-api-dev &
          sleep 10

      - name: Run tests
        run: ./scripts/run_all_tests.sh
```

---

## Test Coverage Summary

| Category | Tests | Coverage |
|----------|-------|----------|
| Basic IOC Queries | 5 | Core functionality |
| SentinelOne Integration | 3 | Webhook handling |
| LLM Triaging | 4 | AI analysis |
| SIEM Feeds | 3 | CEF/STIX export |
| Component Extraction | 2 | URL parsing |
| End-to-End | 3 | Full workflows |
| Performance | 2 | Latency/load |
| Error Handling | 3 | Edge cases |

**Total: 25 test scenarios** covering all major features

---

## Next Steps

After running tests:
1. ✅ Fix any failing tests
2. ✅ Add tests to CI/CD pipeline
3. ✅ Monitor production with same test patterns
4. ✅ Create alerts for test failures
5. ✅ Document any new features with tests

---

**Questions?** Open an issue or check [README.md](../README.md)
