# Elastic Cloud Integration Guide

## Overview

This guide explains how to integrate Watchtower threat intelligence feeds with Elastic Cloud (Elasticsearch + Kibana) for security monitoring, threat hunting, and alerting.

## Architecture

```
┌─────────────┐    HTTP GET     ┌─────────────┐    HTTP POST    ┌──────────────┐
│  Watchtower │ ──────────────> │  Filebeat / │ ──────────────> │    Elastic   │
│   REST API  │   CEF/STIX      │  Logstash   │   Bulk API      │    Cloud     │
└─────────────┘                 └─────────────┘                 └──────────────┘
                                                                        │
                                                                        ▼
                                                                 ┌──────────────┐
                                                                 │    Kibana    │
                                                                 │  Dashboard   │
                                                                 └──────────────┘
```

## Prerequisites

- Watchtower REST API running (`make run-api`)
- Elastic Cloud deployment
- Elastic Cloud API Key or credentials
- Filebeat or Logstash installed (choose one)

## Configuration

### 1. Get Elastic Cloud Credentials

1. Log into Elastic Cloud: https://cloud.elastic.co
2. Go to your deployment
3. Click **Management** → **API Keys**
4. Create a new API key with permissions:
   - `write` on indices
   - `create_index` permission

### 2. Environment Variables

Create a `.env.elastic` file:

```bash
# Elastic Cloud Configuration
ELASTIC_CLOUD_ID=your-cloud-id-here
ELASTIC_API_KEY=your-api-key-here
# Or use username/password
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=your-password

# Elasticsearch endpoints
ELASTIC_ENDPOINT=https://your-deployment.es.us-central1.gcp.cloud.es.io:443

# Watchtower Configuration
WATCHTOWER_API_URL=http://localhost:8080
WATCHTOWER_API_TOKEN=your-api-token  # If auth is enabled

# Ingestion Settings
FEED_FORMAT=stix  # or cef
FETCH_INTERVAL=3600  # seconds (1 hour)
FETCH_SINCE=1h  # IOCs from last hour
INDEX_NAME=watchtower-iocs
```

## Integration Methods

### Method 1: Filebeat (Recommended for CEF)

#### Install Filebeat

```bash
# macOS
brew install filebeat

# Ubuntu/Debian
sudo apt-get install filebeat

# RHEL/CentOS
sudo yum install filebeat
```

#### Configure Filebeat

Create `filebeat.watchtower.yml`:

```yaml
filebeat.inputs:
  - type: http_endpoint
    enabled: true
    listen_address: localhost
    listen_port: 8088
    url: "/watchtower"

  - type: log
    enabled: true
    paths:
      - /tmp/watchtower-feed.cef
    fields:
      source: watchtower
      format: cef
    fields_under_root: true

# CEF parsing
processors:
  - dissect:
      tokenizer: "CEF:%{cef.version}|%{cef.vendor}|%{cef.product}|%{cef.device_version}|%{cef.signature_id}|%{cef.name}|%{cef.severity}|%{cef.extension}"
      field: "message"
      target_prefix: ""

  - kv:
      field: "cef.extension"
      field_split: " "
      value_split: "="
      target_field: "cef.extension_fields"
      ignore_missing: true

  - drop_fields:
      fields: ["agent", "ecs", "host"]
      ignore_missing: true

# Output to Elastic Cloud
output.elasticsearch:
  cloud.id: "${ELASTIC_CLOUD_ID}"
  api_key: "${ELASTIC_API_KEY}"
  index: "watchtower-iocs-%{+yyyy.MM.dd}"

  # Or use username/password
  # username: "${ELASTIC_USERNAME}"
  # password: "${ELASTIC_PASSWORD}"

# Index template
setup.template.name: "watchtower-iocs"
setup.template.pattern: "watchtower-iocs-*"
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 1

# Kibana dashboards
setup.kibana:
  host: "${ELASTIC_ENDPOINT}:5601"

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
```

#### Create Ingestion Script for Filebeat

Create `scripts/elastic_filebeat_ingester.sh`:

```bash
#!/bin/bash

# Load environment
source .env.elastic

# Fetch feed from Watchtower
echo "📥 Fetching ${FEED_FORMAT} feed from Watchtower..."
curl -s "${WATCHTOWER_API_URL}/api/v1/iocs/feed?format=${FEED_FORMAT}&since=${FETCH_SINCE}" \
  -H "Authorization: Bearer ${WATCHTOWER_API_TOKEN}" \
  -o /tmp/watchtower-feed.${FEED_FORMAT}

# Filebeat will pick up the file automatically
echo "✅ Feed saved to /tmp/watchtower-feed.${FEED_FORMAT}"
echo "📤 Filebeat will ingest it automatically"

# Optional: Manually trigger filebeat (for testing)
# filebeat -c filebeat.watchtower.yml -e
```

#### Start Filebeat

```bash
# Run with config
filebeat -c filebeat.watchtower.yml -e

# Or as systemd service
sudo systemctl start filebeat
```

### Method 2: Logstash (Recommended for STIX)

#### Install Logstash

```bash
# macOS
brew install logstash

# Ubuntu/Debian
sudo apt-get install logstash

# RHEL/CentOS
sudo yum install logstash
```

#### Configure Logstash

Create `logstash.watchtower.conf`:

```ruby
input {
  http_poller {
    urls => {
      watchtower => {
        method => get
        url => "${WATCHTOWER_API_URL}/api/v1/iocs/feed"
        headers => {
          Authorization => "Bearer ${WATCHTOWER_API_TOKEN}"
        }
        query => {
          format => "${FEED_FORMAT}"
          since => "${FETCH_SINCE}"
        }
      }
    }
    schedule => { cron => "0 * * * *" }  # Every hour
    codec => "json"
    metadata_target => "http_metadata"
  }
}

filter {
  # Parse STIX bundle
  if [type] == "bundle" {
    split {
      field => "objects"
    }

    mutate {
      rename => { "objects" => "indicator" }
      add_field => { "[@metadata][index]" => "watchtower-iocs" }
    }
  }

  # Parse CEF format
  if [format] == "cef" {
    grok {
      match => {
        "message" => "CEF:%{NUMBER:cef_version}\|%{DATA:device_vendor}\|%{DATA:device_product}\|%{DATA:device_version}\|%{DATA:signature_id}\|%{DATA:name}\|%{NUMBER:severity}\|%{GREEDYDATA:extension}"
      }
    }

    kv {
      source => "extension"
      field_split => " "
      value_split => "="
      target => "cef_extension"
    }
  }

  # Add timestamp
  date {
    match => [ "rt", "UNIX_MS" ]
    target => "@timestamp"
  }

  # Add metadata
  mutate {
    add_field => {
      "source" => "watchtower"
      "ingestion_time" => "%{@timestamp}"
    }
  }
}

output {
  elasticsearch {
    cloud_id => "${ELASTIC_CLOUD_ID}"
    api_key => "${ELASTIC_API_KEY}"
    index => "watchtower-iocs-%{+YYYY.MM.dd}"

    # Or use username/password
    # user => "${ELASTIC_USERNAME}"
    # password => "${ELASTIC_PASSWORD}"
  }

  stdout {
    codec => rubydebug
  }
}
```

#### Start Logstash

```bash
# Run with config
logstash -f logstash.watchtower.conf

# Or as systemd service
sudo systemctl start logstash
```

### Method 3: Python Script (Direct to Elasticsearch)

Create `scripts/elastic_ingester.py`:

```python
#!/usr/bin/env python3
import os
import sys
import json
import requests
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Load configuration
ELASTIC_CLOUD_ID = os.getenv('ELASTIC_CLOUD_ID')
ELASTIC_API_KEY = os.getenv('ELASTIC_API_KEY')
ELASTIC_USERNAME = os.getenv('ELASTIC_USERNAME', 'elastic')
ELASTIC_PASSWORD = os.getenv('ELASTIC_PASSWORD')
WATCHTOWER_API_URL = os.getenv('WATCHTOWER_API_URL', 'http://localhost:8080')
WATCHTOWER_API_TOKEN = os.getenv('WATCHTOWER_API_TOKEN', '')
FEED_FORMAT = os.getenv('FEED_FORMAT', 'stix')
FETCH_SINCE = os.getenv('FETCH_SINCE', '1h')
INDEX_NAME = os.getenv('INDEX_NAME', 'watchtower-iocs')

def fetch_watchtower_feed():
    """Fetch IOC feed from Watchtower"""
    url = f"{WATCHTOWER_API_URL}/api/v1/iocs/feed"
    params = {'format': FEED_FORMAT, 'since': FETCH_SINCE}
    headers = {}
    if WATCHTOWER_API_TOKEN:
        headers['Authorization'] = f'Bearer {WATCHTOWER_API_TOKEN}'

    print(f"📥 Fetching {FEED_FORMAT.upper()} feed from Watchtower...")
    response = requests.get(url, params=params, headers=headers, timeout=30)
    response.raise_for_status()

    return response.text if FEED_FORMAT == 'cef' else response.json()

def connect_elasticsearch():
    """Connect to Elasticsearch"""
    print("🔌 Connecting to Elastic Cloud...")

    if ELASTIC_API_KEY:
        es = Elasticsearch(
            cloud_id=ELASTIC_CLOUD_ID,
            api_key=ELASTIC_API_KEY
        )
    else:
        es = Elasticsearch(
            cloud_id=ELASTIC_CLOUD_ID,
            basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD)
        )

    # Test connection
    if not es.ping():
        raise Exception("Failed to connect to Elasticsearch")

    print(f"✅ Connected to Elasticsearch cluster")
    return es

def ingest_stix(es, stix_bundle):
    """Ingest STIX bundle into Elasticsearch"""
    indicators = stix_bundle.get('objects', [])
    print(f"📤 Ingesting {len(indicators)} STIX indicators...")

    # Prepare bulk actions
    actions = []
    for indicator in indicators:
        action = {
            '_index': f"{INDEX_NAME}-{datetime.now().strftime('%Y.%m.%d')}",
            '_source': {
                **indicator,
                'source': 'watchtower',
                'format': 'stix',
                'ingestion_timestamp': datetime.utcnow().isoformat()
            }
        }
        actions.append(action)

    # Bulk insert
    success, failed = bulk(es, actions, raise_on_error=False)
    print(f"  ✅ Successfully indexed: {success}")
    if failed:
        print(f"  ⚠️  Failed: {len(failed)}")

    return success

def ingest_cef(es, cef_data):
    """Ingest CEF logs into Elasticsearch"""
    cef_lines = [line for line in cef_data.split('\n') if line.strip()]
    print(f"📤 Ingesting {len(cef_lines)} CEF entries...")

    actions = []
    for cef_line in cef_lines:
        # Parse CEF (simple parsing, enhance as needed)
        parts = cef_line.split('|')
        if len(parts) >= 8:
            action = {
                '_index': f"{INDEX_NAME}-{datetime.now().strftime('%Y.%m.%d')}",
                '_source': {
                    'message': cef_line,
                    'cef': {
                        'version': parts[0].replace('CEF:', ''),
                        'vendor': parts[1],
                        'product': parts[2],
                        'device_version': parts[3],
                        'signature_id': parts[4],
                        'name': parts[5],
                        'severity': parts[6],
                        'extension': parts[7] if len(parts) > 7 else ''
                    },
                    'source': 'watchtower',
                    'format': 'cef',
                    'ingestion_timestamp': datetime.utcnow().isoformat()
                }
            }
            actions.append(action)

    success, failed = bulk(es, actions, raise_on_error=False)
    print(f"  ✅ Successfully indexed: {success}")
    if failed:
        print(f"  ⚠️  Failed: {len(failed)}")

    return success

def main():
    print("🚀 Watchtower → Elastic Cloud Ingestion Starting...")
    print(f"   Format: {FEED_FORMAT.upper()}")
    print(f"   Fetching IOCs since: {FETCH_SINCE}")

    try:
        # Connect to Elasticsearch
        es = connect_elasticsearch()

        # Fetch feed
        feed_data = fetch_watchtower_feed()

        # Ingest
        if FEED_FORMAT == 'stix':
            ingest_stix(es, feed_data)
        elif FEED_FORMAT == 'cef':
            ingest_cef(es, feed_data)
        else:
            print(f"❌ Unsupported format: {FEED_FORMAT}")
            sys.exit(1)

        print(f"✅ Ingestion complete at {datetime.now()}")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
```

Make it executable:
```bash
chmod +x scripts/elastic_ingester.py
pip install elasticsearch requests
```

## Scheduling

### Using Cron

```bash
crontab -e

# Add entry (run every hour)
0 * * * * cd /path/to/watchtower && source .env.elastic && python3 scripts/elastic_ingester.py >> /var/log/elastic_ingester.log 2>&1
```

### Using Systemd Timer

Similar to Datadog setup, create service and timer files.

## Kibana Configuration

### 1. Create Index Pattern

1. Open Kibana
2. Go to **Stack Management** → **Index Patterns**
3. Click **Create index pattern**
4. Pattern: `watchtower-iocs-*`
5. Time field: `@timestamp` or `ingestion_timestamp`

### 2. Create Visualizations

#### IOC Timeline
- Type: Line chart
- X-axis: Date histogram on `@timestamp`
- Y-axis: Count

#### Top IOC Sources
- Type: Pie chart
- Slice by: `cef.extension_fields.cs2.keyword` (source)

#### Threat Type Distribution
- Type: Bar chart
- X-axis: `cef.extension_fields.cs1.keyword` (threat_type)
- Y-axis: Count

#### Confidence Score Heatmap
- Type: Heatmap
- X-axis: Date histogram
- Y-axis: Range buckets on `cef.extension_fields.cn1` (confidence)

### 3. Create Dashboard

1. Go to **Dashboard** → **Create dashboard**
2. Add all visualizations
3. Add filters:
   - Source: `watchtower`
   - Time range selector
4. Save as "Watchtower Threat Intelligence"

### 4. Set Up Alerts

Go to **Alerting** → **Rules** → **Create rule**

**Example: High Confidence IOC Alert**
```json
{
  "name": "High Confidence Threat Detected",
  "schedule": {
    "interval": "5m"
  },
  "conditions": {
    "query": {
      "bool": {
        "filter": [
          { "term": { "source.keyword": "watchtower" }},
          { "range": { "cef.extension_fields.cn1": { "gte": 90 }}}
        ]
      }
    }
  },
  "actions": [
    {
      "action_type_id": ".slack",
      "params": {
        "message": "High confidence threat detected: {{context.hits}}"
      }
    }
  ]
}
```

## Index Lifecycle Management (ILM)

Create ILM policy to manage index size:

```bash
PUT _ilm/policy/watchtower-iocs-policy
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "30d"
          }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          }
        }
      },
      "cold": {
        "min_age": "90d",
        "actions": {
          "freeze": {}
        }
      },
      "delete": {
        "min_age": "180d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

## Verification

### Check Ingestion

```bash
# Check index count
curl -u elastic:password \
  "${ELASTIC_ENDPOINT}/watchtower-iocs-*/_count"

# Search recent IOCs
curl -u elastic:password \
  "${ELASTIC_ENDPOINT}/watchtower-iocs-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "range": {
        "@timestamp": {
          "gte": "now-1h"
        }
      }
    },
    "size": 10
  }'
```

## Troubleshooting

### Issue: Connection refused

**Solution:**
- Verify Elastic Cloud ID and endpoint
- Check API key/credentials
- Ensure firewall allows outbound HTTPS

### Issue: Index not found

**Solution:**
- Check index name in Kibana
- Verify index pattern matches
- Run ingestion script to create index

### Issue: Slow queries

**Solution:**
- Add index template with proper mappings
- Use keyword fields for aggregations
- Enable index refresh interval tuning

## Best Practices

1. **Index Templates**: Define field mappings upfront
2. **ILM Policies**: Manage storage costs
3. **Sharding**: Use 1 shard for small indices (< 50GB)
4. **Field Types**: Use `keyword` for exact match, `text` for full-text
5. **Monitoring**: Enable Elastic Stack monitoring

## Cost Estimation

Elastic Cloud pricing (as of 2026):
- Standard tier: ~$0.14/hour (~$100/month)
- Storage: ~$0.12/GB/month

Example cost for 10,000 IOCs/hour:
- Daily volume: ~36 MB (STIX)
- Monthly storage: ~1 GB
- With 90-day retention: ~3 GB
- Estimated cost: $100-120/month (includes compute + storage)

## Next Steps

- [Datadog Integration](SIEM_INTEGRATION_DATADOG.md)
- [Create Custom Kibana Dashboards](#kibana-configuration)
- [Set Up Alerting](#set-up-alerts)

## Support

- Elastic Docs: https://www.elastic.co/guide/
- Watchtower Issues: https://github.com/hive-corporation/watchtower/issues
