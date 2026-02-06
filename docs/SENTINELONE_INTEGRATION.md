# SentinelOne Integration with Watchtower

## Overview

This integration enables **bi-directional threat intelligence enrichment** between SentinelOne EDR and Watchtower threat intelligence platform, with Slack notifications and SIEM feed capabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Threat Intelligence Sources                  │
│  (OSV, AlienVault OTX, URLhaus, DigitalSide, Tor Exit Nodes)   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           v
                  ┌────────────────┐
                  │   Watchtower   │
                  │  (PostgreSQL)  │
                  └───────┬────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        v                 v                 v
┌───────────────┐  ┌─────────────┐  ┌──────────────┐
│  gRPC API     │  │  REST API   │  │  Slack Bot   │
│  (existing)   │  │  (new)      │  │  (new)       │
└───────────────┘  └──────┬──────┘  └──────┬───────┘
                          │                 │
        ┌─────────────────┼─────────────────┤
        │                 │                 │
        v                 v                 v
┌───────────────┐  ┌─────────────┐  ┌──────────────┐
│ SentinelOne   │  │    SIEM     │  │    Slack     │
│   Webhook     │  │ (CEF/STIX)  │  │   Channel    │
└───────────────┘  └─────────────┘  └──────────────┘
```

## Use Cases

### 1. SentinelOne Threat Enrichment (Primary)
**Flow**: SentinelOne → Watchtower → Slack

When SentinelOne detects a threat on an endpoint:
1. SentinelOne sends webhook to Watchtower
2. Watchtower enriches with multi-source intelligence
3. Enriched alert posted to Slack with @mention

**Example Scenario:**
- Endpoint downloads `malicious-package.tar.gz`
- SentinelOne detects file hash: `a3f5d8...`
- Queries Watchtower: finds IOC in URLhaus + AlienVault OTX
- Slack alert: "⚠️ Malware detected on SERVER-42 | Hash: a3f5d8... | Sources: URLhaus, OTX | Confidence: 85 | @security-team"

### 2. Supply Chain Monitoring
**Flow**: Watchtower Ingestion → Notification Engine → Slack

When Watchtower ingests new supply chain threat:
1. OSV provider detects malicious package version
2. Notification engine evaluates: type=package, confidence≥80
3. Slack alert: "🚨 Supply Chain Threat: lodash@4.17.0 | Source: Google OSV | CVE-2021-23337 | Block in CI/CD | @devops @security"

### 3. Manual Enrichment via Slack
**Flow**: Slack Command → Watchtower → Slack Response

Security analyst investigates suspicious indicator:
1. Types in Slack: `/watchtower check 192.0.2.1`
2. Watchtower queries IOC database
3. Response: "192.0.2.1 | Type: IP | Sources: OTX (C2 server), Tor Exit Node | First seen: 2026-01-15 | Threat: botnet"

### 4. SIEM IOC Feed
**Flow**: SIEM Polling → Watchtower API → SIEM Ingestion

SIEM regularly fetches fresh threat intelligence:
1. SIEM calls `/api/v1/iocs/feed?format=cef&since=1h`
2. Watchtower returns CEF-formatted IOC feed
3. SIEM ingests and correlates with logs

## Implementation Plan

### Phase 1: REST API Framework (Foundation)
**Files to create:**
- `cmd/watchtower-api/main.go` - HTTP server alongside gRPC
- `internal/adapter/handler/rest_handler.go` - REST endpoints
- `internal/adapter/handler/middleware.go` - Auth, logging, rate limiting

**Endpoints:**
- `POST /api/v1/webhooks/sentinelone` - Receive SentinelOne alerts
- `GET /api/v1/iocs/search?value=X` - REST version of SearchIOC
- `GET /api/v1/iocs/check?value=X` - REST version of CheckIOC
- `GET /api/v1/health` - Health check

### Phase 2: Notification Engine
**Files to create:**
- `internal/core/domain/notification.go` - Notification domain model
- `internal/core/ports/notifier.go` - Notifier interface
- `internal/adapter/notifier/slack.go` - Slack adapter

**Notification Rules:**
```go
type NotificationRule struct {
    Name      string
    Condition func(ioc domain.IOC) bool
    Channel   string
    Mentions  []string
}

// Example rules
rules := []NotificationRule{
    {
        Name: "high-confidence-ioc",
        Condition: func(ioc domain.IOC) bool {
            return ioc.Score >= 80
        },
        Channel: "#security-alerts",
        Mentions: []string{"@security-team"},
    },
    {
        Name: "supply-chain-threat",
        Condition: func(ioc domain.IOC) bool {
            return ioc.Type == domain.Package
        },
        Channel: "#security-alerts",
        Mentions: []string{"@devops", "@security"},
    },
}
```

### Phase 3: SentinelOne Integration
**Files to create:**
- `internal/adapter/handler/sentinelone_webhook.go` - Webhook handler
- `internal/adapter/provider/sentinelone_ioc.go` - Optional: ingest SentinelOne IOCs

**Webhook Payload (from SentinelOne):**
```json
{
  "alertId": "1234567890",
  "threatName": "Trojan.GenericKD.12345678",
  "classification": "Malware",
  "indicators": [
    {
      "type": "SHA256",
      "value": "a3f5d8c2b9e1f7a6d4c8e3b5a9f2d6c1e8a4b7d3f9c2a5e8b1d4f7a3c6e9b2d5"
    },
    {
      "type": "IPV4",
      "value": "192.0.2.1"
    }
  ],
  "endpoint": {
    "computerName": "SERVER-42",
    "osType": "linux",
    "agentVersion": "23.1.2.5"
  },
  "timestamp": "2026-02-01T12:34:56Z"
}
```

**Enrichment Logic:**
1. Extract indicators from webhook
2. Query Watchtower for each indicator (SearchIOC)
3. Aggregate results from multiple sources
4. Format Slack message
5. Post to Slack with mentions

### Phase 4: Slack Bot
**Files to create:**
- `cmd/watchtower-slack/main.go` - Slack bot service
- `internal/adapter/notifier/slack_formatter.go` - Message formatting

**Slack Commands:**
- `/watchtower check <IOC>` - Check single IOC
- `/watchtower search <package>` - Search supply chain packages
- `/watchtower stats` - Show database statistics
- `/watchtower help` - Command help

**Slack Message Format:**
```
⚠️ *Threat Detection Alert*

*Endpoint*: SERVER-42 (Linux)
*Detection Time*: 2026-02-01 12:34:56 UTC
*Threat*: Trojan.GenericKD.12345678

*IOC Details*:
• *SHA256*: `a3f5d8c2b9e1...`
  - Sources: URLhaus, AlienVault OTX
  - Confidence: 85/100
  - Tags: malware, trojan, generic
  - First Seen: 2026-01-28

• *IP Address*: `192.0.2.1`
  - Sources: AlienVault OTX, Tor Exit Nodes
  - Confidence: 90/100
  - Tags: c2, botnet, tor-exit
  - First Seen: 2026-01-15

*Recommended Actions*:
✓ Isolate endpoint SERVER-42
✓ Block IP 192.0.2.1 at firewall
✓ Scan other endpoints for same hash

cc: @security-team @incident-response
```

### Phase 5: SIEM Feed API
**Files to create:**
- `internal/adapter/exporter/cef_exporter.go` - CEF format exporter
- `internal/adapter/exporter/stix_exporter.go` - STIX 2.1 exporter

**Endpoints:**
- `GET /api/v1/iocs/feed?format=cef&since=24h` - CEF format
- `GET /api/v1/iocs/feed?format=stix&since=24h` - STIX 2.1 format
- `GET /api/v1/iocs/feed?format=json&since=24h` - Raw JSON

**CEF Format Example:**
```
CEF:0|Watchtower|ThreatIntel|1.0|IOC_DETECTED|Malicious IP Address|8|
src=192.0.2.1
cn1Label=ConfidenceScore cn1=85
cs1Label=ThreatType cs1=c2_server
cs2Label=Sources cs2=alienvault-otx,tor-exit-nodes
cs3Label=Tags cs3=malware,botnet,c2
```

**STIX 2.1 Format Example:**
```json
{
  "type": "bundle",
  "id": "bundle--a3f5d8c2-b9e1-f7a6-d4c8-e3b5a9f2d6c1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--12345678-1234-1234-1234-123456789012",
      "created": "2026-02-01T12:00:00Z",
      "modified": "2026-02-01T12:00:00Z",
      "name": "Malicious IP Address",
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "pattern_type": "stix",
      "valid_from": "2026-01-15T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85,
      "labels": ["malware", "botnet", "c2"],
      "external_references": [
        {
          "source_name": "alienvault-otx",
          "url": "https://otx.alienvault.com"
        }
      ]
    }
  ]
}
```

## Database Schema Updates

No schema changes required - existing IOC table supports all use cases.

Optional: Add `notifications` table to track sent alerts (prevent duplicates):
```sql
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_id UUID REFERENCES iocs(id),
    notification_type VARCHAR(50), -- 'slack', 'siem', 'webhook'
    recipient VARCHAR(200),
    payload JSONB,
    sent_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_notifications_ioc_id ON notifications(ioc_id);
CREATE INDEX idx_notifications_sent_at ON notifications(sent_at);
```

## Configuration

### Environment Variables
```bash
# Slack Configuration
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_SIGNING_SECRET=your-signing-secret
SLACK_CHANNEL_SECURITY=#security-alerts
SLACK_MENTION_TEAM=@security-team

# SentinelOne Configuration
SENTINELONE_WEBHOOK_SECRET=shared-secret-for-webhook-validation

# REST API Configuration
REST_API_PORT=8080
REST_API_AUTH_TOKEN=your-api-token
REST_API_RATE_LIMIT=100 # requests per minute

# Notification Rules
NOTIFY_HIGH_CONFIDENCE_THRESHOLD=80
NOTIFY_SUPPLY_CHAIN=true
NOTIFY_SENTINELONE_DETECTIONS=true

# SIEM Configuration
SIEM_FEED_ENABLED=true
SIEM_FEED_FORMAT=cef # cef, stix, json
SIEM_FEED_AUTH_TOKEN=siem-api-token
```

### SentinelOne Webhook Setup
1. Login to SentinelOne Management Console
2. Navigate to Settings → Integrations → Webhooks
3. Create new webhook:
   - **URL**: `https://watchtower.example.com/api/v1/webhooks/sentinelone`
   - **Events**: Threat Detected, Alert Created
   - **Authentication**: Bearer token or shared secret
   - **Content Type**: application/json

### Slack App Setup
1. Create Slack app at https://api.slack.com/apps
2. Enable features:
   - Incoming Webhooks
   - Slash Commands
   - Bot Users
3. OAuth Scopes required:
   - `chat:write` - Post messages
   - `commands` - Respond to slash commands
   - `users:read` - Mention users
4. Install app to workspace
5. Copy Bot User OAuth Token to `SLACK_BOT_TOKEN`

## Testing

### Test SentinelOne Webhook
```bash
curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${SENTINELONE_WEBHOOK_SECRET}" \
  -d '{
    "alertId": "test-123",
    "threatName": "Test Malware",
    "indicators": [
      {"type": "IPV4", "value": "192.0.2.1"}
    ],
    "endpoint": {"computerName": "TEST-01"},
    "timestamp": "2026-02-01T12:00:00Z"
  }'
```

Expected: Slack notification posted to #security-alerts

### Test Slack Command
In Slack channel: `/watchtower check 192.0.2.1`

Expected: Bot responds with IOC details from Watchtower database

### Test SIEM Feed
```bash
curl -H "Authorization: Bearer ${SIEM_FEED_AUTH_TOKEN}" \
  "http://localhost:8080/api/v1/iocs/feed?format=cef&since=24h"
```

Expected: CEF-formatted IOC list

## Performance Considerations

1. **Webhook Rate Limiting**: SentinelOne can send bursts of alerts
   - Implement queue system (Redis/RabbitMQ)
   - Process webhooks asynchronously
   - Rate limit Slack notifications (max 1/minute per IOC)

2. **SIEM Feed Caching**: IOC feeds don't change frequently
   - Cache feed responses for 5 minutes
   - Use ETags for conditional requests
   - Implement pagination for large feeds

3. **Database Indexing**: Ensure fast lookups
   - Existing index on `iocs(value)` handles primary queries
   - Add index on `iocs(date_ingested)` for time-based feeds

## Security Considerations

1. **Webhook Authentication**:
   - Validate SentinelOne webhook signature
   - Use HTTPS only
   - Rate limit webhook endpoint

2. **API Authentication**:
   - Require API tokens for all REST endpoints
   - Rotate tokens regularly
   - Log all API access

3. **Slack Security**:
   - Validate Slack request signatures
   - Store bot token securely (environment variable, not code)
   - Limit bot permissions to minimum required

4. **Data Sanitization**:
   - Sanitize IOC values before displaying in Slack
   - Prevent injection in CEF/STIX exports
   - Validate all webhook payloads

## Deployment

### Docker Compose Updates
```yaml
# Add to docker-compose.yml
services:
  watchtower-api:
    build:
      context: .
      dockerfile: Dockerfile.api
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://admin:secretpassword@postgres:5432/watchtower
      - SLACK_BOT_TOKEN=${SLACK_BOT_TOKEN}
      - SENTINELONE_WEBHOOK_SECRET=${SENTINELONE_WEBHOOK_SECRET}
    depends_on:
      - postgres
    restart: unless-stopped

  watchtower-grpc:
    # Existing gRPC service
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "50051:50051"
    # ... rest of config
```

### Makefile Targets
```makefile
## run-api: Start REST API server
run-api:
	@echo "🚀 Starting Watchtower REST API..."
	@go run cmd/watchtower-api/main.go

## run-api-dev: Start REST API without building
run-api-dev:
	@echo "🚀 Starting Watchtower REST API (dev mode)..."
	@go run cmd/watchtower-api/main.go

## test-webhook: Test SentinelOne webhook integration
test-webhook:
	@echo "🧪 Testing SentinelOne webhook..."
	@curl -X POST http://localhost:8080/api/v1/webhooks/sentinelone \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer test-secret" \
		-d @testdata/sentinelone_webhook_sample.json

## test-slack: Test Slack notification
test-slack:
	@echo "🧪 Testing Slack notification..."
	@go run cmd/test-slack/main.go
```

## Monitoring

### Metrics to Track
- Webhook requests received
- Slack notifications sent
- SIEM feed requests
- API response times
- IOC enrichment success rate

### Logging
- Log all webhook events (info level)
- Log Slack notifications (info level)
- Log SIEM feed requests (debug level)
- Log errors and enrichment failures (error level)

## Future Enhancements

### Phase 6: Advanced Features
1. **Bidirectional Sync**: Push Watchtower IOCs to SentinelOne threat intelligence
2. **Playbook Automation**: Auto-remediation actions (isolate endpoint, block IP)
3. **Machine Learning**: Score IOCs based on SentinelOne telemetry
4. **Dashboard**: Web UI for viewing alerts, statistics, trends
5. **Alert Deduplication**: Smart grouping of related alerts
6. **Custom Slack Workflows**: Interactive buttons (Approve/Block/Investigate)

## Success Metrics

After implementation, track:
- **MTTD (Mean Time to Detect)**: How quickly threats are identified
- **MTTR (Mean Time to Respond)**: How quickly team responds to Slack alerts
- **False Positive Rate**: Alerts that don't require action
- **Enrichment Coverage**: % of SentinelOne alerts matched in Watchtower
- **SIEM Integration Success**: Number of SIEM systems consuming feed

## Support

For issues or questions:
- Check logs: `make logs`
- Verify configuration: `make info`
- Test endpoints: `make test-webhook`
- Review [MAKEFILE_GUIDE.md](MAKEFILE_GUIDE.md) for commands

---

**Status**: 📋 Design phase - ready for implementation
**Priority**: High - Security operations critical
**Estimated Effort**: 3-4 weeks for Phases 1-4
