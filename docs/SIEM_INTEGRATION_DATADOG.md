# Datadog Integration Guide

## Overview

This guide explains how to integrate Watchtower threat intelligence feeds with Datadog for security monitoring and alerting.

## Architecture

```
┌─────────────┐    HTTP GET     ┌─────────────┐    HTTP POST    ┌─────────────┐
│  Watchtower │ ──────────────> │   Ingestion │ ──────────────> │   Datadog   │
│   REST API  │   CEF/STIX      │    Script   │   Logs API      │   Platform  │
└─────────────┘                 └─────────────┘                 └─────────────┘
```

## Prerequisites

- Watchtower REST API running (`make run-api`)
- Datadog account with API access
- Datadog API Key
- Datadog Application Key (for advanced features)

## Configuration

### 1. Get Datadog Credentials

1. Log into Datadog: https://app.datadoghq.com
2. Go to **Organization Settings** → **API Keys**
3. Copy your API Key
4. (Optional) Go to **Application Keys** and create one

### 2. Environment Variables

Create a `.env.datadog` file:

```bash
# Datadog Configuration
DATADOG_API_KEY=your-api-key-here
DATADOG_SITE=datadoghq.com  # or datadoghq.eu, us3.datadoghq.com, etc.

# Watchtower Configuration
WATCHTOWER_API_URL=http://localhost:8080
WATCHTOWER_API_TOKEN=your-api-token  # If auth is enabled

# Ingestion Settings
FEED_FORMAT=cef  # or stix
FETCH_INTERVAL=3600  # seconds (1 hour)
FETCH_SINCE=1h  # IOCs from last hour
```

### 3. Install Dependencies

```bash
# Python ingestion script
pip install requests datadog-api-client

# Or use curl/bash script (no dependencies)
```

## Integration Methods

### Method 1: Python Script (Recommended)

Create `scripts/datadog_ingester.py`:

```python
#!/usr/bin/env python3
import os
import sys
import time
import requests
from datetime import datetime
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.model.http_log import HTTPLog
from datadog_api_client.v2.model.http_log_item import HTTPLogItem

# Load configuration
DATADOG_API_KEY = os.getenv('DATADOG_API_KEY')
DATADOG_SITE = os.getenv('DATADOG_SITE', 'datadoghq.com')
WATCHTOWER_API_URL = os.getenv('WATCHTOWER_API_URL', 'http://localhost:8080')
WATCHTOWER_API_TOKEN = os.getenv('WATCHTOWER_API_TOKEN', '')
FEED_FORMAT = os.getenv('FEED_FORMAT', 'cef')
FETCH_SINCE = os.getenv('FETCH_SINCE', '1h')

def fetch_watchtower_feed():
    """Fetch IOC feed from Watchtower"""
    url = f"{WATCHTOWER_API_URL}/api/v1/iocs/feed"
    params = {
        'format': FEED_FORMAT,
        'since': FETCH_SINCE
    }
    headers = {}
    if WATCHTOWER_API_TOKEN:
        headers['Authorization'] = f'Bearer {WATCHTOWER_API_TOKEN}'

    print(f"📥 Fetching {FEED_FORMAT.upper()} feed from Watchtower...")
    response = requests.get(url, params=params, headers=headers, timeout=30)
    response.raise_for_status()

    return response.text

def send_to_datadog_cef(cef_data):
    """Send CEF logs to Datadog"""
    configuration = Configuration()
    configuration.api_key['apiKeyAuth'] = DATADOG_API_KEY
    configuration.server_variables['site'] = DATADOG_SITE

    with ApiClient(configuration) as api_client:
        api_instance = LogsApi(api_client)

        # Parse CEF lines
        cef_lines = [line for line in cef_data.split('\n') if line.strip()]

        print(f"📤 Sending {len(cef_lines)} IOCs to Datadog...")

        # Send in batches of 100
        batch_size = 100
        for i in range(0, len(cef_lines), batch_size):
            batch = cef_lines[i:i+batch_size]

            logs = []
            for cef_line in batch:
                log_item = HTTPLogItem(
                    ddsource='watchtower',
                    ddtags='source:watchtower,format:cef,type:threat-intel',
                    hostname='watchtower-api',
                    message=cef_line,
                    service='threat-intelligence'
                )
                logs.append(log_item)

            body = HTTPLog(logs)
            api_instance.submit_log(body=body)
            print(f"  ✅ Sent batch {i//batch_size + 1}/{(len(cef_lines)-1)//batch_size + 1}")
            time.sleep(0.5)  # Rate limiting

def send_to_datadog_stix(stix_data):
    """Send STIX bundle to Datadog as structured logs"""
    import json

    configuration = Configuration()
    configuration.api_key['apiKeyAuth'] = DATADOG_API_KEY
    configuration.server_variables['site'] = DATADOG_SITE

    with ApiClient(configuration) as api_client:
        api_instance = LogsApi(api_client)

        # Parse STIX bundle
        bundle = json.loads(stix_data)
        indicators = bundle.get('objects', [])

        print(f"📤 Sending {len(indicators)} STIX indicators to Datadog...")

        # Send in batches of 100
        batch_size = 100
        for i in range(0, len(indicators), batch_size):
            batch = indicators[i:i+batch_size]

            logs = []
            for indicator in batch:
                log_item = HTTPLogItem(
                    ddsource='watchtower',
                    ddtags='source:watchtower,format:stix,type:threat-intel',
                    hostname='watchtower-api',
                    message=json.dumps(indicator),
                    service='threat-intelligence'
                )
                logs.append(log_item)

            body = HTTPLog(logs)
            api_instance.submit_log(body=body)
            print(f"  ✅ Sent batch {i//batch_size + 1}/{(len(indicators)-1)//batch_size + 1}")
            time.sleep(0.5)

def main():
    print("🚀 Watchtower → Datadog Ingestion Starting...")
    print(f"   Format: {FEED_FORMAT.upper()}")
    print(f"   Fetching IOCs since: {FETCH_SINCE}")

    try:
        # Fetch feed
        feed_data = fetch_watchtower_feed()

        # Send to Datadog
        if FEED_FORMAT == 'cef':
            send_to_datadog_cef(feed_data)
        elif FEED_FORMAT == 'stix':
            send_to_datadog_stix(feed_data)
        else:
            print(f"❌ Unsupported format: {FEED_FORMAT}")
            sys.exit(1)

        print(f"✅ Ingestion complete at {datetime.now()}")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
```

Make it executable:
```bash
chmod +x scripts/datadog_ingester.py
```

### Method 2: Bash Script (Simple)

Create `scripts/datadog_ingester.sh`:

```bash
#!/bin/bash

# Load environment
source .env.datadog

# Fetch feed
echo "📥 Fetching IOC feed from Watchtower..."
FEED_DATA=$(curl -s "${WATCHTOWER_API_URL}/api/v1/iocs/feed?format=${FEED_FORMAT}&since=${FETCH_SINCE}" \
  -H "Authorization: Bearer ${WATCHTOWER_API_TOKEN}")

# Send to Datadog (CEF format)
if [ "$FEED_FORMAT" = "cef" ]; then
  echo "📤 Sending CEF logs to Datadog..."

  # Read line by line and send via Datadog HTTP API
  echo "$FEED_DATA" | while IFS= read -r line; do
    if [ -n "$line" ]; then
      curl -X POST "https://http-intake.logs.${DATADOG_SITE}/api/v2/logs" \
        -H "Content-Type: application/json" \
        -H "DD-API-KEY: ${DATADOG_API_KEY}" \
        -d "{
          \"ddsource\": \"watchtower\",
          \"ddtags\": \"source:watchtower,format:cef\",
          \"hostname\": \"watchtower-api\",
          \"message\": $(echo "$line" | jq -Rs .),
          \"service\": \"threat-intelligence\"
        }" > /dev/null 2>&1
    fi
  done

  echo "✅ Ingestion complete"
fi
```

Make it executable:
```bash
chmod +x scripts/datadog_ingester.sh
```

## Scheduling

### Using Cron (Linux/macOS)

```bash
# Edit crontab
crontab -e

# Add entry (run every hour)
0 * * * * cd /path/to/watchtower && source .env.datadog && python3 scripts/datadog_ingester.py >> /var/log/datadog_ingester.log 2>&1
```

### Using Systemd Timer (Linux)

Create `/etc/systemd/system/watchtower-datadog.service`:

```ini
[Unit]
Description=Watchtower Datadog Ingestion
After=network.target

[Service]
Type=oneshot
User=watchtower
WorkingDirectory=/opt/watchtower
EnvironmentFile=/opt/watchtower/.env.datadog
ExecStart=/usr/bin/python3 /opt/watchtower/scripts/datadog_ingester.py
```

Create `/etc/systemd/system/watchtower-datadog.timer`:

```ini
[Unit]
Description=Watchtower Datadog Ingestion Timer
Requires=watchtower-datadog.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable watchtower-datadog.timer
sudo systemctl start watchtower-datadog.timer
```

## Datadog Configuration

### 1. Create Custom Log Pipeline

1. Go to **Logs** → **Configuration** → **Pipelines**
2. Click **New Pipeline**
3. Name: "Watchtower Threat Intelligence"
4. Filter: `source:watchtower`

### 2. Add CEF Parser

For CEF format, add a Grok parser:

```
watchtower_cef CEF:%{number:cef.version}\|%{data:cef.vendor}\|%{data:cef.product}\|%{data:cef.device_version}\|%{data:cef.signature_id}\|%{data:cef.name}\|%{number:cef.severity}\|%{data:cef.extension}
```

### 3. Create Threat Intelligence Dashboard

Create widgets:
- **Timeseries**: IOC ingestion rate
- **Top List**: IOCs by threat type
- **Top List**: IOCs by source
- **Heatmap**: IOC confidence scores
- **Query Value**: Total IOCs ingested

Example query:
```
source:watchtower service:threat-intelligence
```

### 4. Set Up Alerts

Create monitors for:
- **High confidence IOCs**: `@cef.confidence:[90 TO 100]`
- **Supply chain threats**: `@cef.threat_type:supply_chain_malware`
- **Malware downloads**: `@cef.threat_type:malware_download`

## Verification

### Check Ingestion

```bash
# View logs in Datadog
# Go to Logs → Explorer
# Filter: source:watchtower

# Or use Datadog API
curl -X POST "https://api.${DATADOG_SITE}/api/v1/logs-queries/list" \
  -H "Content-Type: application/json" \
  -H "DD-API-KEY: ${DATADOG_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DATADOG_APP_KEY}" \
  -d '{
    "query": "source:watchtower",
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "limit": 10
  }'
```

## Troubleshooting

### Issue: No logs appearing in Datadog

**Solution:**
1. Check API key: `echo $DATADOG_API_KEY`
2. Verify Datadog site: `echo $DATADOG_SITE`
3. Test connection:
   ```bash
   curl -X POST "https://http-intake.logs.${DATADOG_SITE}/api/v2/logs" \
     -H "DD-API-KEY: ${DATADOG_API_KEY}" \
     -d '{"message": "test", "ddsource": "test"}'
   ```

### Issue: Rate limiting

**Solution:**
- Reduce batch size in script
- Increase sleep time between batches
- Contact Datadog support for higher limits

### Issue: Large feed size

**Solution:**
- Use `since` parameter to limit time range
- Filter by IOC type
- Increase fetch interval

## Best Practices

1. **Rate Limiting**: Don't fetch more often than every 15 minutes
2. **Incremental Updates**: Use `since` parameter to avoid duplicate data
3. **Error Handling**: Log failures and retry with exponential backoff
4. **Monitoring**: Set up alerts for ingestion failures
5. **Cost Management**: Monitor Datadog log ingestion volume

## Cost Estimation

Datadog pricing (as of 2026):
- Log ingestion: ~$0.10 per GB
- Log retention (15 days): ~$1.27 per million log events

Example cost for 10,000 IOCs/hour:
- Size: ~1.5 MB (CEF) or ~5 MB (STIX)
- Monthly volume: ~1-3.6 GB
- Estimated cost: $1-5/month for ingestion

## Next Steps

- [Elastic Cloud Integration](SIEM_INTEGRATION_ELASTIC.md)
- [SentinelOne Integration](SENTINELONE_INTEGRATION.md)
- [Slack Notifications](../README.md#slack-notifications)

## Support

- Datadog Docs: https://docs.datadoghq.com/logs/
- Watchtower Issues: https://github.com/hive-corporation/watchtower/issues
