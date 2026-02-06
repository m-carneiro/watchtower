# Watchtower Deployment Guide

Complete guide for deploying Watchtower in production with Datadog and Elastic Cloud SIEM integration.

## 🎯 Deployment Overview

This guide covers:
1. Production environment setup
2. Watchtower deployment
3. SIEM integration (Datadog + Elastic Cloud)
4. Monitoring and alerting
5. Maintenance procedures

## 📋 Prerequisites

### Infrastructure
- Linux server (Ubuntu 22.04 LTS or RHEL 8+ recommended)
- Minimum: 2 CPU cores, 4GB RAM, 20GB disk
- Recommended: 4 CPU cores, 8GB RAM, 50GB disk
- Docker and Docker Compose installed

### External Services
- Datadog account and API key
- Elastic Cloud deployment
- (Optional) Slack workspace with bot token
- (Optional) AlienVault OTX API key

## 🚀 Quick Deployment (30 minutes)

### 1. Server Setup

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Python dependencies (for ingestion scripts)
sudo apt-get install -y python3-pip
pip3 install datadog-api-client elasticsearch requests
```

### 2. Clone and Configure Watchtower

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/hive-corporation/watchtower.git
cd watchtower

# Set permissions
sudo chown -R $USER:$USER /opt/watchtower

# Create environment file
cp .env.example .env

# Edit configuration
nano .env
```

**Minimal `.env` configuration:**
```bash
# Database
DATABASE_URL=postgres://admin:secretpassword@localhost:5432/watchtower

# Threat Intelligence (optional)
OTX_API_KEY=your-otx-key-if-you-have-one

# Slack (optional)
SLACK_BOT_TOKEN=xoxb-your-token
SLACK_CHANNEL_SECURITY=#security-alerts

# REST API
REST_API_PORT=8080
REST_API_AUTH_TOKEN=generate-strong-token-here

# SentinelOne (optional)
SENTINELONE_WEBHOOK_SECRET=shared-secret-with-s1
```

### 3. Start Watchtower

```bash
# Full setup (installs tools, starts DB, runs migrations, ingests data)
make full-setup

# Start gRPC server
make run &

# Start REST API
make run-api &

# Verify services
curl http://localhost:8080/api/v1/health
```

### 4. Configure SIEM Integration

#### Datadog Setup

```bash
# Create Datadog configuration
cp .env.datadog.example .env.datadog
nano .env.datadog
```

Fill in:
```bash
DATADOG_API_KEY=your-datadog-api-key
DATADOG_SITE=datadoghq.com
WATCHTOWER_API_URL=http://localhost:8080
WATCHTOWER_API_TOKEN=your-rest-api-token
FEED_FORMAT=cef
FETCH_SINCE=1h
```

Test manually:
```bash
source .env.datadog
python3 scripts/datadog_ingester.py
```

#### Elastic Cloud Setup

```bash
# Create Elastic configuration
cp .env.elastic.example .env.elastic
nano .env.elastic
```

Fill in:
```bash
ELASTIC_CLOUD_ID=your-cloud-id
ELASTIC_API_KEY=your-api-key
WATCHTOWER_API_URL=http://localhost:8080
WATCHTOWER_API_TOKEN=your-rest-api-token
FEED_FORMAT=stix
FETCH_SINCE=1h
INDEX_NAME=watchtower-iocs
```

Test manually:
```bash
source .env.elastic
python3 scripts/elastic_ingester.py
```

### 5. Schedule Automated Ingestion

```bash
# Edit crontab
crontab -e

# Add ingestion jobs (every hour)
0 * * * * cd /opt/watchtower && source .env.datadog && python3 scripts/datadog_ingester.py >> /var/log/watchtower/datadog.log 2>&1
0 * * * * cd /opt/watchtower && source .env.elastic && python3 scripts/elastic_ingester.py >> /var/log/watchtower/elastic.log 2>&1

# Re-ingest threat feeds (daily at 2 AM)
0 2 * * * cd /opt/watchtower && make ingestion >> /var/log/watchtower/ingestion.log 2>&1
```

Create log directory:
```bash
sudo mkdir -p /var/log/watchtower
sudo chown $USER:$USER /var/log/watchtower
```

## 🔒 Production Hardening

### 1. Enable Authentication

Edit `.env`:
```bash
REST_API_AUTH_TOKEN=$(openssl rand -hex 32)
```

Update SIEM configurations with the new token.

### 2. Use HTTPS (with Nginx)

Install Nginx:
```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

Create `/etc/nginx/sites-available/watchtower`:
```nginx
server {
    listen 443 ssl http2;
    server_name watchtower.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/watchtower.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/watchtower.yourdomain.com/privkey.pem;

    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Enable and get certificate:
```bash
sudo ln -s /etc/nginx/sites-available/watchtower /etc/nginx/sites-enabled/
sudo certbot --nginx -d watchtower.yourdomain.com
sudo systemctl restart nginx
```

### 3. Firewall Configuration

```bash
# Allow SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Block direct access to Watchtower ports
sudo ufw deny 8080/tcp
sudo ufw deny 50051/tcp

# Enable firewall
sudo ufw enable
```

### 4. Systemd Services

Create `/etc/systemd/system/watchtower-grpc.service`:
```ini
[Unit]
Description=Watchtower gRPC Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=watchtower
WorkingDirectory=/opt/watchtower
EnvironmentFile=/opt/watchtower/.env
ExecStart=/usr/bin/make run-dev
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/watchtower-api.service`:
```ini
[Unit]
Description=Watchtower REST API
After=network.target docker.service watchtower-grpc.service
Requires=docker.service

[Service]
Type=simple
User=watchtower
WorkingDirectory=/opt/watchtower
EnvironmentFile=/opt/watchtower/.env
ExecStart=/usr/bin/make run-api-dev
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable services:
```bash
sudo systemctl daemon-reload
sudo systemctl enable watchtower-grpc watchtower-api
sudo systemctl start watchtower-grpc watchtower-api
```

## 📊 Monitoring Setup

### 1. Health Checks

Create `/usr/local/bin/watchtower-health-check.sh`:
```bash
#!/bin/bash

# Check gRPC server (via REST API health endpoint)
if ! curl -sf http://localhost:8080/api/v1/health > /dev/null; then
    echo "❌ Watchtower API is down"
    # Send alert (Slack, email, PagerDuty, etc.)
    exit 1
fi

# Check database
if ! docker exec watchtower-postgres-1 pg_isready -U admin > /dev/null; then
    echo "❌ PostgreSQL is down"
    exit 1
fi

echo "✅ All services healthy"
```

Add to cron (every 5 minutes):
```bash
*/5 * * * * /usr/local/bin/watchtower-health-check.sh >> /var/log/watchtower/health.log 2>&1
```

### 2. Metrics Collection

Monitor these metrics:
- IOC ingestion rate
- Database size
- API response times
- SIEM ingestion success rate
- Error rates in logs

### 3. Alerting

Set up alerts for:
- Service downtime
- Ingestion failures
- High error rates
- Database connection issues
- Disk space warnings

## 🔄 Maintenance Procedures

### Daily
- Monitor ingestion logs
- Check SIEM dashboards
- Review high-confidence IOC alerts

### Weekly
- Review IOC database growth
- Check for failed ingestion jobs
- Verify SIEM data retention

### Monthly
- Update Watchtower (pull latest from GitHub)
- Review and update threat feeds
- Audit access logs
- Database vacuum and analyze

### Quarterly
- Security audit
- Review and update firewall rules
- Test disaster recovery procedures
- Update documentation

## 🔍 Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u watchtower-grpc -n 50
journalctl -u watchtower-api -n 50

# Check Docker
docker ps
docker logs watchtower-postgres-1
```

### Ingestion Failing

```bash
# Check ingestion logs
tail -f /var/log/watchtower/datadog.log
tail -f /var/log/watchtower/elastic.log

# Test API manually
curl "http://localhost:8080/api/v1/iocs/feed?format=cef&since=1h"

# Check SIEM credentials
source .env.datadog && echo $DATADOG_API_KEY
source .env.elastic && echo $ELASTIC_API_KEY
```

### Database Issues

```bash
# Check database status
make db-status

# Check disk space
df -h

# Manual database inspection
make db-shell
```

## 📈 Scaling Considerations

### Vertical Scaling
- Upgrade to 8GB RAM for 1M+ IOCs
- Add CPU cores for faster ingestion
- Use SSD storage for better query performance

### Horizontal Scaling
- Deploy multiple REST API instances (load balanced)
- Use external PostgreSQL (AWS RDS, Google Cloud SQL)
- Distribute ingestion across multiple workers

### Database Optimization
- Add indexes for frequent queries
- Partition tables by date
- Archive old IOCs to cold storage

## 🔐 Security Best Practices

1. **Authentication**: Always enable REST_API_AUTH_TOKEN
2. **Encryption**: Use HTTPS for all external access
3. **Secrets Management**: Use environment files, never commit secrets
4. **Least Privilege**: Run services as non-root user
5. **Updates**: Keep dependencies updated
6. **Audit Logs**: Enable and monitor access logs
7. **Backup**: Regular database backups
8. **Network Segmentation**: Isolate Watchtower network

## 📞 Support

- Documentation: [README.md](../README.md)
- Issues: https://github.com/hive-corporation/watchtower/issues
- Slack: (if you have a community Slack)

## ✅ Deployment Checklist

- [ ] Server provisioned and secured
- [ ] Docker and Docker Compose installed
- [ ] Watchtower cloned and configured
- [ ] Database initialized with migrations
- [ ] Initial threat intelligence ingested
- [ ] gRPC server running
- [ ] REST API running
- [ ] Health checks passing
- [ ] Datadog configured and tested
- [ ] Elastic Cloud configured and tested
- [ ] Cron jobs scheduled
- [ ] Systemd services enabled
- [ ] HTTPS configured (if applicable)
- [ ] Firewall rules applied
- [ ] Monitoring and alerting set up
- [ ] Documentation updated with custom configs
- [ ] Team trained on operations

## 🎉 Next Steps

Once deployed:
1. Configure Datadog/Kibana dashboards
2. Set up SIEM alerting rules
3. Integrate with SentinelOne (if applicable)
4. Enable Slack notifications
5. Document custom configurations
6. Train security team on usage

---

**Questions?** Open an issue or check the documentation in [docs/](../docs/)
