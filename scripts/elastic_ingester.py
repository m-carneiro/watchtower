#!/usr/bin/env python3
"""
Watchtower → Elastic Cloud Ingestion Script

Fetches IOC feeds from Watchtower REST API and indexes them in Elastic Cloud
for security monitoring, threat hunting, and alerting.

Usage:
    python3 elastic_ingester.py

Environment Variables:
    ELASTIC_CLOUD_ID     - Elastic Cloud ID (required if using cloud)
    ELASTIC_API_KEY      - Elastic API key (recommended)
    ELASTIC_USERNAME     - Elastic username (alternative to API key)
    ELASTIC_PASSWORD     - Elastic password (alternative to API key)
    ELASTIC_ENDPOINT     - Elastic endpoint URL (for self-hosted)
    WATCHTOWER_API_URL   - Watchtower API URL (default: http://localhost:8080)
    WATCHTOWER_API_TOKEN - Watchtower API token (optional)
    FEED_FORMAT          - Feed format: cef or stix (default: stix)
    FETCH_SINCE          - Time range: 1h, 24h, 7d (default: 1h)
    INDEX_NAME           - Elasticsearch index name (default: watchtower-iocs)
"""

import os
import sys
import json
import requests
from datetime import datetime

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
except ImportError:
    print("❌ Error: elasticsearch library not installed")
    print("Install with: pip install elasticsearch requests")
    sys.exit(1)

# Load configuration from environment
ELASTIC_CLOUD_ID = os.getenv('ELASTIC_CLOUD_ID')
ELASTIC_API_KEY = os.getenv('ELASTIC_API_KEY')
ELASTIC_USERNAME = os.getenv('ELASTIC_USERNAME', 'elastic')
ELASTIC_PASSWORD = os.getenv('ELASTIC_PASSWORD')
ELASTIC_ENDPOINT = os.getenv('ELASTIC_ENDPOINT')
WATCHTOWER_API_URL = os.getenv('WATCHTOWER_API_URL', 'http://localhost:8080')
WATCHTOWER_API_TOKEN = os.getenv('WATCHTOWER_API_TOKEN', '')
FEED_FORMAT = os.getenv('FEED_FORMAT', 'stix')
FETCH_SINCE = os.getenv('FETCH_SINCE', '1h')
INDEX_NAME = os.getenv('INDEX_NAME', 'watchtower-iocs')


def fetch_watchtower_feed():
    """Fetch IOC feed from Watchtower API"""
    url = f"{WATCHTOWER_API_URL}/api/v1/iocs/feed"
    params = {'format': FEED_FORMAT, 'since': FETCH_SINCE}
    headers = {}
    if WATCHTOWER_API_TOKEN:
        headers['Authorization'] = f'Bearer {WATCHTOWER_API_TOKEN}'

    print(f"📥 Fetching {FEED_FORMAT.upper()} feed from Watchtower...")
    print(f"   URL: {url}")
    print(f"   Since: {FETCH_SINCE}")

    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        print(f"✅ Fetched feed successfully")

        if FEED_FORMAT == 'stix':
            return response.json()
        else:
            return response.text
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to fetch feed: {e}")
        sys.exit(1)


def connect_elasticsearch():
    """Connect to Elasticsearch"""
    print("🔌 Connecting to Elastic Cloud...")

    try:
        if ELASTIC_CLOUD_ID and ELASTIC_API_KEY:
            # Using Cloud ID and API key (recommended)
            es = Elasticsearch(
                cloud_id=ELASTIC_CLOUD_ID,
                api_key=ELASTIC_API_KEY
            )
        elif ELASTIC_CLOUD_ID:
            # Using Cloud ID with username/password
            es = Elasticsearch(
                cloud_id=ELASTIC_CLOUD_ID,
                basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD)
            )
        elif ELASTIC_ENDPOINT:
            # Using direct endpoint
            if ELASTIC_API_KEY:
                es = Elasticsearch(
                    [ELASTIC_ENDPOINT],
                    api_key=ELASTIC_API_KEY
                )
            else:
                es = Elasticsearch(
                    [ELASTIC_ENDPOINT],
                    basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD)
                )
        else:
            print("❌ Error: No Elasticsearch connection configured")
            print("   Set either ELASTIC_CLOUD_ID or ELASTIC_ENDPOINT")
            sys.exit(1)

        # Test connection
        if not es.ping():
            raise Exception("Failed to ping Elasticsearch cluster")

        info = es.info()
        print(f"✅ Connected to Elasticsearch cluster")
        print(f"   Cluster: {info['cluster_name']}")
        print(f"   Version: {info['version']['number']}")

        return es

    except Exception as e:
        print(f"❌ Failed to connect to Elasticsearch: {e}")
        sys.exit(1)


def ingest_stix(es, stix_bundle):
    """Ingest STIX bundle into Elasticsearch"""
    indicators = stix_bundle.get('objects', [])
    print(f"📤 Ingesting {len(indicators)} STIX indicators...")

    # Prepare bulk actions
    actions = []
    timestamp = datetime.utcnow().isoformat()
    index_name = f"{INDEX_NAME}-{datetime.now().strftime('%Y.%m.%d')}"

    for indicator in indicators:
        action = {
            '_index': index_name,
            '_source': {
                **indicator,
                'source': 'watchtower',
                'format': 'stix',
                'ingestion_timestamp': timestamp,
                '@timestamp': timestamp
            }
        }
        actions.append(action)

    # Bulk insert
    try:
        success, errors = bulk(es, actions, raise_on_error=False, stats_only=False)
        print(f"  ✅ Successfully indexed: {success}")

        if errors:
            print(f"  ⚠️  Failed: {len(errors)}")
            for error in errors[:5]:  # Show first 5 errors
                print(f"     {error}")

        return success
    except Exception as e:
        print(f"❌ Bulk indexing failed: {e}")
        return 0


def ingest_cef(es, cef_data):
    """Ingest CEF logs into Elasticsearch"""
    cef_lines = [line for line in cef_data.split('\n') if line.strip()]
    print(f"📤 Ingesting {len(cef_lines)} CEF entries...")

    actions = []
    timestamp = datetime.utcnow().isoformat()
    index_name = f"{INDEX_NAME}-{datetime.now().strftime('%Y.%m.%d')}"

    for cef_line in cef_lines:
        # Parse CEF (simple parsing)
        parts = cef_line.split('|')
        if len(parts) >= 8:
            action = {
                '_index': index_name,
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
                    'ingestion_timestamp': timestamp,
                    '@timestamp': timestamp
                }
            }
            actions.append(action)

    try:
        success, errors = bulk(es, actions, raise_on_error=False, stats_only=False)
        print(f"  ✅ Successfully indexed: {success}")

        if errors:
            print(f"  ⚠️  Failed: {len(errors)}")
            for error in errors[:5]:
                print(f"     {error}")

        return success
    except Exception as e:
        print(f"❌ Bulk indexing failed: {e}")
        return 0


def main():
    print("=" * 60)
    print("🚀 Watchtower → Elastic Cloud Ingestion")
    print("=" * 60)
    print(f"   Format: {FEED_FORMAT.upper()}")
    print(f"   Fetching IOCs since: {FETCH_SINCE}")
    print(f"   Index: {INDEX_NAME}")
    print(f"   Timestamp: {datetime.now()}")
    print("=" * 60)

    try:
        # Connect to Elasticsearch
        es = connect_elasticsearch()

        # Fetch feed from Watchtower
        feed_data = fetch_watchtower_feed()

        # Ingest based on format
        if FEED_FORMAT == 'stix':
            count = ingest_stix(es, feed_data)
        elif FEED_FORMAT == 'cef':
            count = ingest_cef(es, feed_data)
        else:
            print(f"❌ Unsupported format: {FEED_FORMAT}")
            print("   Supported formats: cef, stix")
            sys.exit(1)

        print("=" * 60)
        print(f"✅ Ingestion complete at {datetime.now()}")
        print(f"   Total indexed: {count}")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\n⚠️  Ingestion interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
