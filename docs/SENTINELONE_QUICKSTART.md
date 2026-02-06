# SentinelOne Integration - Quick Start Guide

## Overview

This guide will help you set up the SentinelOne + Watchtower + Slack integration in under 30 minutes.

## Architecture at a Glance

```
SentinelOne Detection
         ↓
  [Webhook to Watchtower]
         ↓
  Query IOC Database
  (Multi-source enrichment)
         ↓
  Slack Notification
  (@mention security team)
         ↓
  SIEM Feed (CEF/STIX)
```

## Prerequisites

- Watchtower already running (see [README.md](README.md))
- SentinelOne account with admin access
- Slack workspace (optional, for notifications)
- Access to network firewall (for webhook endpoint)

## Step 1: Install Dependencies

```bash
# Update Go dependencies
go mod tidy

# Install new dependencies
go get github.com/gorilla/mux@v1.8.1
go get github.com/google/uuid@v1.6.0
```

## Step 2: Configure Environment

```bash
# Create .env if you haven't already
make env-setup

# Edit .env and add:
# - SLACK_BOT_TOKEN (optional, for Slack notifications)
# - REST_API_AUTH_TOKEN (for API authentication)
# - SENTINELONE_WEBHOOK_SECRET (shared secret with SentinelOne)
```

Example `.env` configuration:
```bash
# Slack (optional)
SLACK_BOT_TOKEN=xoxb-your-token-here
SLACK_CHANNEL_SECURITY=#security-alerts
SLACK_MENTION_TEAM=@security-team

# API
REST_API_PORT=8080
REST_API_AUTH_TOKEN=your-secure-token-123

# SentinelOne
SENTINELONE_WEBHOOK_SECRET=shared-secret-456
```

## Step 3: Build and Start Services

```bash
# Terminal 1: Start gRPC server (for existing functionality)
make run-dev

# Terminal 2: Start REST API server (for webhooks & SIEM)
make run-api-dev

# Terminal 3: Verify both are running
curl http://localhost:8080/api/v1/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2026-02-01T12:00:00Z",
  "service": "watchtower-api"
}
```

## Step 4: Test the Integration Locally

```bash
# Test the webhook endpoint
make test-webhook
```

You should see:
```json
{
  "status": "received",
  "alert_id": "test-12345",
  "indicators_enriched": 2,
  "indicators_in_db": 0,
  "slack_notification": false
}
```

## Step 5: Configure SentinelOne Webhook

### 5.1: Expose Watchtower API to the Internet

**Option A: ngrok (for testing)**
```bash
ngrok http 8080
# Copy the HTTPS URL (e.g., https://abc123.ngrok.io)
```

**Option B: Production deployment**
- Deploy Watchtower API behind a reverse proxy (nginx, Cloudflare, etc.)
- Use HTTPS with valid certificate
- Example: `https://watchtower.yourcompany.com`

### 5.2: Create Webhook in SentinelOne

1. Login to SentinelOne Management Console
2. Navigate to: **Settings → Integrations → Webhooks**
3. Click **Create Webhook**
4. Fill in details:
   - **Name**: Watchtower Threat Enrichment
   - **URL**: `https://your-domain.com/api/v1/webhooks/sentinelone`
   - **Method**: POST
   - **Content Type**: application/json
   - **Authentication**: Bearer Token
   - **Token**: (use value from `REST_API_AUTH_TOKEN` in .env)
   - **Events to trigger**:
     - ✓ Threat Detected
     - ✓ Alert Created
     - ✓ Threat Mitigation Report
5. **Test Connection** (SentinelOne will send a test webhook)
6. Click **Save**

### 5.3: Verify Webhook Configuration

Check Watchtower logs for incoming webhook:
```bash
# In Terminal 2 (where run-api-dev is running)
# You should see:
# 📥 Received SentinelOne alert: test-12345 (endpoint: TEST-01)
```

## Step 6: Configure Slack (Optional)

### 6.1: Create Slack App

1. Go to https://api.slack.com/apps
2. Click **Create New App** → **From scratch**
3. Name: "Watchtower Security Alerts"
4. Choose your workspace

### 6.2: Configure Bot Permissions

1. Navigate to **OAuth & Permissions**
2. Add **Bot Token Scopes**:
   - `chat:write` - Post messages
   - `users:read` - Mention users
3. Click **Install to Workspace**
4. Copy **Bot User OAuth Token** (starts with `xoxb-`)
5. Add to `.env`:
   ```bash
   SLACK_BOT_TOKEN=xoxb-your-actual-token
   ```

### 6.3: Invite Bot to Channel

In your Slack workspace:
```
/invite @Watchtower Security Alerts
```

### 6.4: Test Slack Notification

```bash
# Restart API server to load new SLACK_BOT_TOKEN
# Then test webhook again
make test-webhook
```

Check `#security-alerts` channel for message like:
```
⚠️ Threat Detection Alert

Endpoint: TEST-SERVER-01
OS Type: linux
Threat: Test.Malware.Generic
Classification: Malware

IPV4: 192.0.2.1
  Not found in Watchtower database

SHA256: a3f5d8c2b9e1...
  Not found in Watchtower database

Recommended Actions:
✓ Isolate endpoint TEST-SERVER-01
✓ Investigate recent activity
✓ Scan other endpoints

cc: @security-team
```

## Step 7: Test with Real IOCs

### 7.1: Add Test IOC to Database

```bash
# Add a test malicious IP to the database
docker exec -it watchtower-postgres-1 psql -U admin -d watchtower -c "
INSERT INTO iocs (value, type, source, threat_type, tags, version, first_seen, date_ingested)
VALUES (
  '192.0.2.1',
  'ip',
  'test-source',
  'c2_server',
  ARRAY['malware', 'c2', 'botnet'],
  '',
  NOW(),
  NOW()
);
"
```

### 7.2: Send Webhook with Test IOC

```bash
make test-webhook
```

Now you should see enriched data in the response:
```json
{
  "status": "received",
  "alert_id": "test-12345",
  "indicators_enriched": 2,
  "indicators_in_db": 1,  // <-- IOC found!
  "slack_notification": true
}
```

And Slack should show enriched information:
```
⚠️ Threat Detection Alert

IPV4: 192.0.2.1
• Sources: test-source
• Tags: malware, c2, botnet
• First Seen: 2026-02-01
```

## Step 8: SIEM Integration (Optional)

### Test SIEM Feed Endpoints

```bash
# CEF format (for Splunk, QRadar, ArcSight)
curl -H "Authorization: Bearer ${REST_API_AUTH_TOKEN}" \
  "http://localhost:8080/api/v1/iocs/feed?format=cef&since=24h"

# STIX 2.1 format (for modern SIEM systems)
curl -H "Authorization: Bearer ${REST_API_AUTH_TOKEN}" \
  "http://localhost:8080/api/v1/iocs/feed?format=stix&since=24h"
```

### Configure SIEM to Poll Feed

**Splunk Example:**
```python
# Add to inputs.conf
[script://./bin/watchtower_feed.py]
interval = 3600
sourcetype = watchtower:ioc
```

**QRadar Example:**
Configure custom log source with HTTP polling:
- URL: `https://watchtower.company.com/api/v1/iocs/feed?format=cef&since=1h`
- Interval: Every hour
- Authentication: Bearer token

## Monitoring & Troubleshooting

### Check Logs

```bash
# REST API logs
# (shown in Terminal 2 where run-api-dev is running)

# Database query errors
docker logs watchtower-postgres-1

# Test endpoints
make test-api
```

### Common Issues

**1. Webhook not receiving data**
- Check firewall allows inbound HTTPS on port 443
- Verify `REST_API_AUTH_TOKEN` matches SentinelOne configuration
- Check SentinelOne webhook logs for errors

**2. Slack notifications not working**
- Verify `SLACK_BOT_TOKEN` is correct
- Check bot is invited to channel
- Test with: `curl -X POST https://slack.com/api/auth.test -H "Authorization: Bearer $SLACK_BOT_TOKEN"`

**3. Empty enrichment data**
- Run ingestion to populate database: `make ingestion-dev`
- Check database has IOCs: `make db-status`
- Verify indicators in webhook match IOC values in database

### Verify Integration Health

```bash
# Check REST API health
curl http://localhost:8080/api/v1/health

# Check database IOC count
make db-status

# Test IOC lookup
curl "http://localhost:8080/api/v1/iocs/check?value=192.0.2.1"
```

## Production Deployment

### Docker Compose (Recommended)

Update `docker-compose.yml`:
```yaml
services:
  watchtower-grpc:
    # Existing gRPC service
    ...

  watchtower-api:
    build:
      context: .
      dockerfile: Dockerfile.api
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://admin:secretpassword@postgres:5432/watchtower
      - REST_API_PORT=8080
      - REST_API_AUTH_TOKEN=${REST_API_AUTH_TOKEN}
      - SLACK_BOT_TOKEN=${SLACK_BOT_TOKEN}
      - SLACK_CHANNEL_SECURITY=${SLACK_CHANNEL_SECURITY}
      - SENTINELONE_WEBHOOK_SECRET=${SENTINELONE_WEBHOOK_SECRET}
    depends_on:
      - postgres
    restart: unless-stopped
```

Create `Dockerfile.api`:
```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN go build -o watchtower-api ./cmd/watchtower-api

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/watchtower-api .
EXPOSE 8080
CMD ["./watchtower-api"]
```

Deploy:
```bash
docker-compose up -d watchtower-api
```

### Kubernetes (Advanced)

See [k8s/watchtower-api-deployment.yaml](k8s/watchtower-api-deployment.yaml) for example manifest.

## Usage Examples

### Manual IOC Enrichment

```bash
# Check single IOC
curl "http://localhost:8080/api/v1/iocs/check?value=malicious.com"

# Search with all sources
curl "http://localhost:8080/api/v1/iocs/search?value=malicious.com"

# Check supply chain package
curl "http://localhost:8080/api/v1/iocs/search?value=lodash@4.17.0"
```

### Slack Commands (Future Enhancement)

```
/watchtower check 192.0.2.1
/watchtower search lodash
/watchtower stats
```

## Next Steps

1. **Automate Ingestion**: Set up cron job for `make ingestion`
   ```bash
   # Run every 6 hours
   0 */6 * * * cd /path/to/watchtower && make ingestion-dev
   ```

2. **Add Custom Threat Lists**: Create new providers in `internal/adapter/provider/`

3. **Enhance Scoring Logic**: Update `internal/core/domain/scoring.go` with custom rules

4. **Dashboard**: Build web UI to visualize threats (use REST API endpoints)

5. **Bidirectional Sync**: Push Watchtower IOCs to SentinelOne threat intelligence

## Resources

- [Full Integration Documentation](SENTINELONE_INTEGRATION.md)
- [Makefile Guide](MAKEFILE_GUIDE.md)
- [Version Tracking](VERSION_TRACKING.md)
- [SentinelOne API Docs](https://xsoar.pan.dev/docs/reference/integrations/sentinel-one-v2)

## Support

- GitHub Issues: https://github.com/hive-corporation/watchtower/issues
- Slack: #watchtower-support

---

**Status**: ✅ Ready for testing
**Last Updated**: 2026-02-01
