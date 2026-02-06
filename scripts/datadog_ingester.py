#!/usr/bin/env python3
"""
Watchtower → Datadog Ingestion Script

Fetches IOC feeds from Watchtower REST API and sends them to Datadog for
security monitoring and alerting.

Usage:
    python3 datadog_ingester.py

Environment Variables:
    DATADOG_API_KEY      - Datadog API key (required)
    DATADOG_SITE         - Datadog site (default: datadoghq.com)
    WATCHTOWER_API_URL   - Watchtower API URL (default: http://localhost:8080)
    WATCHTOWER_API_TOKEN - Watchtower API token (optional)
    FEED_FORMAT          - Feed format: cef or stix (default: cef)
    FETCH_SINCE          - Time range: 1h, 24h, 7d (default: 1h)
"""

import os
import sys
import time
import requests
from datetime import datetime

try:
    from datadog_api_client import ApiClient, Configuration
    from datadog_api_client.v2.api.logs_api import LogsApi
    from datadog_api_client.v2.model.http_log import HTTPLog
    from datadog_api_client.v2.model.http_log_item import HTTPLogItem
except ImportError:
    print("❌ Error: datadog-api-client not installed")
    print("Install with: pip install datadog-api-client requests")
    sys.exit(1)

# Load configuration from environment
DATADOG_API_KEY = os.getenv('DATADOG_API_KEY')
DATADOG_SITE = os.getenv('DATADOG_SITE', 'datadoghq.com')
WATCHTOWER_API_URL = os.getenv('WATCHTOWER_API_URL', 'http://localhost:8080')
WATCHTOWER_API_TOKEN = os.getenv('WATCHTOWER_API_TOKEN', '')
FEED_FORMAT = os.getenv('FEED_FORMAT', 'cef')
FETCH_SINCE = os.getenv('FETCH_SINCE', '1h')


def fetch_watchtower_feed():
    """Fetch IOC feed from Watchtower API"""
    url = f"{WATCHTOWER_API_URL}/api/v1/iocs/feed"
    params = {
        'format': FEED_FORMAT,
        'since': FETCH_SINCE
    }
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
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to fetch feed: {e}")
        sys.exit(1)


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
        total_batches = (len(cef_lines) - 1) // batch_size + 1

        for i in range(0, len(cef_lines), batch_size):
            batch = cef_lines[i:i + batch_size]
            batch_num = i // batch_size + 1

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
            try:
                api_instance.submit_log(body=body)
                print(f"  ✅ Sent batch {batch_num}/{total_batches} ({len(batch)} IOCs)")
            except Exception as e:
                print(f"  ❌ Failed to send batch {batch_num}: {e}")

            # Rate limiting
            time.sleep(0.5)


def send_to_datadog_stix(stix_data):
    """Send STIX bundle to Datadog as structured logs"""
    import json

    configuration = Configuration()
    configuration.api_key['apiKeyAuth'] = DATADOG_API_KEY
    configuration.server_variables['site'] = DATADOG_SITE

    with ApiClient(configuration) as api_client:
        api_instance = LogsApi(api_client)

        # Parse STIX bundle
        try:
            bundle = json.loads(stix_data)
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse STIX bundle: {e}")
            sys.exit(1)

        indicators = bundle.get('objects', [])

        print(f"📤 Sending {len(indicators)} STIX indicators to Datadog...")

        # Send in batches of 100
        batch_size = 100
        total_batches = (len(indicators) - 1) // batch_size + 1

        for i in range(0, len(indicators), batch_size):
            batch = indicators[i:i + batch_size]
            batch_num = i // batch_size + 1

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
            try:
                api_instance.submit_log(body=body)
                print(f"  ✅ Sent batch {batch_num}/{total_batches} ({len(batch)} indicators)")
            except Exception as e:
                print(f"  ❌ Failed to send batch {batch_num}: {e}")

            time.sleep(0.5)


def main():
    print("=" * 60)
    print("🚀 Watchtower → Datadog Ingestion")
    print("=" * 60)
    print(f"   Format: {FEED_FORMAT.upper()}")
    print(f"   Fetching IOCs since: {FETCH_SINCE}")
    print(f"   Timestamp: {datetime.now()}")
    print("=" * 60)

    # Validate configuration
    if not DATADOG_API_KEY:
        print("❌ Error: DATADOG_API_KEY environment variable not set")
        sys.exit(1)

    try:
        # Fetch feed from Watchtower
        feed_data = fetch_watchtower_feed()

        # Send to Datadog based on format
        if FEED_FORMAT == 'cef':
            send_to_datadog_cef(feed_data)
        elif FEED_FORMAT == 'stix':
            send_to_datadog_stix(feed_data)
        else:
            print(f"❌ Unsupported format: {FEED_FORMAT}")
            print("   Supported formats: cef, stix")
            sys.exit(1)

        print("=" * 60)
        print(f"✅ Ingestion complete at {datetime.now()}")
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
