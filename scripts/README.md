# Watchtower SIEM Integration Scripts

This directory contains ingestion scripts for integrating Watchtower threat intelligence feeds with various SIEM platforms.

## Available Scripts

### 1. Datadog Ingestion (`datadog_ingester.py`)

Fetches IOC feeds from Watchtower and sends them to Datadog via the Logs API.

**Setup:**
```bash
# Install dependencies
pip install datadog-api-client requests

# Copy and configure environment
cp ../.env.datadog.example ../.env.datadog
# Edit .env.datadog with your credentials

# Run manually
source ../.env.datadog
python3 datadog_ingester.py
```

**Documentation:** [docs/SIEM_INTEGRATION_DATADOG.md](../docs/SIEM_INTEGRATION_DATADOG.md)

### 2. Elastic Cloud Ingestion (`elastic_ingester.py`)

Fetches IOC feeds from Watchtower and indexes them in Elasticsearch.

**Setup:**
```bash
# Install dependencies
pip install elasticsearch requests

# Copy and configure environment
cp ../.env.elastic.example ../.env.elastic
# Edit .env.elastic with your credentials

# Run manually
source ../.env.elastic
python3 elastic_ingester.py
```

**Documentation:** [docs/SIEM_INTEGRATION_ELASTIC.md](../docs/SIEM_INTEGRATION_ELASTIC.md)

## Scheduling

### Using Cron (Recommended)

```bash
# Edit crontab
crontab -e

# Add entries
# Datadog ingestion (every hour)
0 * * * * cd /path/to/watchtower && source .env.datadog && python3 scripts/datadog_ingester.py >> /var/log/datadog_ingester.log 2>&1

# Elastic ingestion (every hour)
0 * * * * cd /path/to/watchtower && source .env.elastic && python3 scripts/elastic_ingester.py >> /var/log/elastic_ingester.log 2>&1
```

### Using Systemd (Linux)

See full setup instructions in the integration guides.

## Troubleshooting

### Script fails with "Module not found"

**Solution:**
```bash
pip install datadog-api-client elasticsearch requests
```

### "Connection refused" error

**Solution:**
- Check that Watchtower REST API is running: `curl http://localhost:8080/api/v1/health`
- Start API if needed: `make run-api` or `make run-api-dev`

### SIEM connection fails

**Datadog:**
- Verify API key: `echo $DATADOG_API_KEY`
- Check Datadog site setting matches your region

**Elastic:**
- Verify Cloud ID and API key
- Test connection: `curl -u elastic:password $ELASTIC_ENDPOINT`

### No IOCs being fetched

**Solution:**
- Check `FETCH_SINCE` value (try `24h` for testing)
- Verify Watchtower has ingested IOCs: `make db-shell` → `SELECT COUNT(*) FROM iocs;`
- Test feed manually: `curl "http://localhost:8080/api/v1/iocs/feed?format=cef&since=24h"`

## Best Practices

1. **Rate Limiting**: Don't fetch more often than every 15 minutes
2. **Incremental Updates**: Use `FETCH_SINCE` to avoid duplicates
3. **Error Logging**: Always redirect output to log files
4. **Monitoring**: Set up alerts for script failures
5. **Testing**: Test manually before scheduling

## Support

- [Datadog Integration Guide](../docs/SIEM_INTEGRATION_DATADOG.md)
- [Elastic Cloud Integration Guide](../docs/SIEM_INTEGRATION_ELASTIC.md)
- [GitHub Issues](https://github.com/hive-corporation/watchtower/issues)
