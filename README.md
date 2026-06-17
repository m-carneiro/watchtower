# Watchtower

**Threat Intelligence Aggregation Platform** with Supply Chain Security, SentinelOne Integration, and Multi-Source IOC Enrichment.

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Architecture](https://img.shields.io/badge/Architecture-Hexagonal-blue)](docs/CLAUDE.md)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 🎯 Overview

Watchtower is a centralized threat intelligence platform that:

- ✅ **Aggregates** IOCs from multiple sources (AlienVault OTX, URLhaus, Google OSV, DigitalSide, Tor Exit Nodes)
- ✅ **Enriches** security alerts with multi-source context and confidence scoring
- ✅ **Detects** supply chain malware across npm, PyPI, Maven, and Go ecosystems
- ✅ **Tracks** specific vulnerable package versions to reduce false positives
- ✅ **Integrates** with SentinelOne EDR for real-time threat enrichment
- ✅ **Notifies** security teams via Slack with actionable intelligence
- ✅ **Exports** IOC feeds in CEF/STIX formats for SIEM ingestion

## 🚀 Quick Start

```bash
# 1. Complete setup (installs tools, starts DB, runs migrations, ingests data)
make full-setup

# 2. Start the gRPC server
make run

# 3. (Optional) Start REST API for SentinelOne integration
make run-api
```

That's it! Watchtower is now running on:
- **gRPC**: `localhost:50051`
- **REST API**: `localhost:8080`

## 📋 Features

### Threat Intelligence Sources

- **AlienVault OTX** - Community threat intelligence with pulses and indicators
- **URLhaus** - Malware distribution URLs from Abuse.ch
- **Google OSV** - Open Source Vulnerabilities database (npm, PyPI, Maven, Go)
- **DigitalSide** - Real-time malicious IPs and URLs
- **Tor Exit Nodes** - Anonymization network monitoring
- **Custom feeds** - Extensible provider architecture

### Supply Chain Security

- **Version-aware detection** - Tracks specific vulnerable package versions
- **Multi-ecosystem support** - npm, PyPI, Maven/Gradle, Go modules
- **Automated extraction** - Parses versions from OSV vulnerability data
- **Smart queries** - Search by package name or `package@version` format

See [docs/VERSION_TRACKING.md](docs/VERSION_TRACKING.md) for details.

### SentinelOne Integration

- **Real-time enrichment** - Webhook receives SentinelOne alerts
- **Multi-source intelligence** - Aggregates context from all IOC sources
- **Slack notifications** - Alerts security team with enriched data
- **SIEM feeds** - Export IOCs in CEF/STIX formats

See [docs/SENTINELONE_INTEGRATION.md](docs/SENTINELONE_INTEGRATION.md) and [docs/SENTINELONE_QUICKSTART.md](docs/SENTINELONE_QUICKSTART.md).

### IOC Component Extraction

Automatically extracts IPs and domains from URLs:
- Database has: `http://198.0.2.12/malware.sh`
- SentinelOne sends: `198.0.2.12`
- Watchtower finds: ✅ Match (smart pattern search)

See [docs/IOC_EXTRACTION.md](docs/IOC_EXTRACTION.md).

## 🏗️ Architecture

Watchtower follows **Hexagonal (Ports & Adapters) Architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                     External Systems                        │
│  (OTX, URLhaus, OSV, SentinelOne, Slack, SIEM)            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         v
              ┌──────────────────────┐
              │      Adapters        │
              │  (Providers, REST,   │
              │   Notifiers, Repos)  │
              └──────────┬───────────┘
                         │
                         v
              ┌──────────────────────┐
              │        Ports         │
              │    (Interfaces)      │
              └──────────┬───────────┘
                         │
                         v
              ┌──────────────────────┐
              │    Domain Layer      │
              │  (Pure Go, No I/O)   │
              └──────────────────────┘
```

**Key principles:**
- Domain layer is pure Go (no I/O, database, or network dependencies)
- Dependencies point inward
- Adapters implement port interfaces
- Backward-compatible gRPC API

See [docs/CLAUDE.md](docs/CLAUDE.md) for architectural constraints.

## 📊 API

### gRPC API

```bash
# Check if IOC exists (returns first match)
grpcurl -plaintext -d '{"value": "192.0.2.1"}' \
  localhost:50051 watchtower.Watchtower/CheckIOC

# Search IOC (returns all sources)
grpcurl -plaintext -d '{"value": "lodash"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC

# Search specific package version
grpcurl -plaintext -d '{"value": "lodash@4.17.0"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC
```

> These examples rely on server reflection, which is off by default. Either run
> with `GRPC_ENABLE_REFLECTION=true` (dev) or pass the proto via `grpcurl -proto`.
> If `GRPC_AUTH_TOKEN`/TLS are set, add `-H "authorization: Bearer <token>"` and
> drop `-plaintext`.

### REST API

```bash
# Health check
curl http://localhost:8080/api/v1/health

# Check IOC
curl "http://localhost:8080/api/v1/iocs/check?value=192.0.2.1"

# Search IOC
curl "http://localhost:8080/api/v1/iocs/search?value=lodash"

# SIEM feed (CEF format)
curl "http://localhost:8080/api/v1/iocs/feed?format=cef&since=24h"

# SIEM feed (STIX 2.1 format)
curl "http://localhost:8080/api/v1/iocs/feed?format=stix&since=24h"
```

## 🛠️ Development

### Prerequisites

- Go 1.25+
- Docker & Docker Compose
- PostgreSQL (via Docker)

### Build

```bash
# Build all binaries
make build

# Build individual components
make build-server     # gRPC server
make build-api        # REST API server
make build-ingester   # Threat intelligence ingester
```

### Run

```bash
# Development mode (no build, fast iteration)
make run-dev          # gRPC server
make run-api-dev      # REST API server
make ingestion-dev    # Run ingestion

# Production mode (with build)
make run
make run-api
make ingestion
```

### Test

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run unit tests only
make test-unit

# Security checks
make security

# Architecture compliance
make arch-check
```

### Database

```bash
# Start PostgreSQL with Docker
make docker-up

# Run migrations
make db-migrate

# Check database status
make db-status

# Reset database
make db-reset

# Open PostgreSQL shell
make db-shell
```

All database commands use Docker internally - no local PostgreSQL installation needed!

## 📚 Documentation

- **[Makefile Guide](docs/MAKEFILE_GUIDE.md)** - Complete guide to all make commands
- **[Architecture](docs/CLAUDE.md)** - Hexagonal architecture constraints and rules
- **[Version Tracking](docs/VERSION_TRACKING.md)** - Supply chain version-aware detection
- **[IOC Extraction](docs/IOC_EXTRACTION.md)** - Smart component extraction and pattern matching
- **[SentinelOne Integration](docs/SENTINELONE_INTEGRATION.md)** - Full integration specification
- **[SentinelOne Quick Start](docs/SENTINELONE_QUICKSTART.md)** - 30-minute setup guide
- **[LLM-Powered Triaging](docs/LLM_TRIAGING.md)** - AI-powered threat analysis with OpenAI/Claude
- **[LLM Guardrails](docs/LLM_GUARDRAILS.md)** - Multi-layer protection to reduce false positives (75% reduction)
- **[Observability & Resilience](docs/OBSERVABILITY.md)** - Prometheus metrics, circuit breaker, and retry logic
- **[Datadog SIEM Integration](docs/SIEM_INTEGRATION_DATADOG.md)** - Integrate with Datadog for threat monitoring
- **[Elastic Cloud SIEM Integration](docs/SIEM_INTEGRATION_ELASTIC.md)** - Integrate with Elastic Cloud + Kibana
- **[Testing Guide](docs/TESTING_GUIDE.md)** - Complete test scenarios and automated test suite
- **[Security Fixes](docs/SECURITY_FIXES.md)** - Security improvements and best practices

## 🔧 Configuration

Create `.env` file (optional - only needed for API keys):

```bash
make env-setup
```

Edit `.env` and add your credentials:

```bash
# Database (defaults to a local dev connection string if unset)
DATABASE_URL=postgres://admin:password@localhost:5432/watchtower

# Threat intelligence
OTX_API_KEY=your-otx-key

# Slack notifications
SLACK_BOT_TOKEN=xoxb-your-token
SLACK_CHANNEL_SECURITY=#security-alerts

# SentinelOne webhook
# Required to accept webhooks — sent by SentinelOne as "Authorization: Bearer <secret>".
# The endpoint fails closed (401) when this is unset.
SENTINELONE_WEBHOOK_SECRET=shared-secret

# REST API
# Auth fails closed (401) when REST_API_AUTH_TOKEN is unset.
REST_API_AUTH_TOKEN=your-api-token
REST_API_PORT=8080

# gRPC API
GRPC_LISTEN_ADDR=localhost:50051
# Token auth (defense in depth). When set, clients must send
# "authorization: Bearer <token>" metadata.
GRPC_AUTH_TOKEN=your-grpc-token
# Transport security: set cert+key for TLS; add the client CA to require
# client certificates (mutual TLS).
GRPC_TLS_CERT=/path/to/server.crt
GRPC_TLS_KEY=/path/to/server.key
GRPC_TLS_CLIENT_CA=/path/to/client-ca.crt
# Reflection leaks the service schema; off by default, enable only in dev.
GRPC_ENABLE_REFLECTION=false
```

> **Security note:** REST auth and the SentinelOne webhook both fail closed when
> their secrets are unset. The gRPC server runs plaintext on localhost for local
> development; set `GRPC_TLS_*` and `GRPC_AUTH_TOKEN` to secure it for production.

## 🎯 Use Cases

### 1. Security Operations Center (SOC)

Enrich security alerts with multi-source threat intelligence:

```bash
# Analyst receives alert with IP 198.0.2.12
# Query Watchtower via Slack
/watchtower check 198.0.2.12

# Response: Confirmed malicious (3 sources, confidence 90%)
# Decision: Escalate to incident response
```

### 2. Supply Chain Security

Monitor for malicious packages in CI/CD:

```bash
# Check if package version is safe
grpcurl -d '{"value": "lodash@4.17.0"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC

# If vulnerable: Block deployment
# If safe: Continue pipeline
```

### 3. Threat Hunting

Search for indicators across endpoints:

```bash
# Get all known malicious IPs
curl "http://localhost:8080/api/v1/iocs/feed?format=json&since=7d"

# Query EDR for connections to these IPs
# Identify compromised endpoints
```

### 4. Incident Response

Enrich IOCs during investigations:

```bash
# Suspicious IP found: 203.0.113.5
grpcurl -d '{"value": "203.0.113.5"}' \
  localhost:50051 watchtower.Watchtower/SearchIOC

# Response shows:
# - URLhaus: http://203.0.113.5/malware.sh
# - OTX: C2 server (3 pulses)
# - First seen: 3 days ago
```

## 📈 Performance

- **Ingestion**: Processes 100,000+ IOCs in < 5 minutes
- **Query latency**: < 10ms for exact match, < 100ms for pattern search
- **Database size**: ~50-100MB after full ingestion
- **Memory usage**: ~200MB (gRPC server), ~300MB (REST API)

## 🐳 Deployment

### Docker Compose

```bash
docker-compose up -d
```

Services:
- `watchtower-grpc` - gRPC server (port 50051)
- `watchtower-api` - REST API server (port 8080)
- `postgres` - PostgreSQL database (port 5432)

### Kubernetes

See `k8s/` directory for manifests.

## 🤝 Contributing

1. Follow [architectural constraints](docs/CLAUDE.md)
2. Run `make check` before committing
3. Maintain domain layer purity (no I/O)
4. Add tests for new features
5. Update documentation

## 📊 Project Status

- ✅ **gRPC API** - Production ready
- ✅ **Threat intelligence ingestion** - Production ready
- ✅ **Supply chain detection** - Production ready
- ✅ **Version tracking** - Production ready
- ✅ **IOC component extraction** - Production ready
- ✅ **REST API** - Ready for testing
- ✅ **SentinelOne integration** - Ready for testing
- ✅ **Slack notifications** - Ready for testing
- 🚧 **SIEM feeds** - CEF/STIX exporters implemented, needs testing

## 🔗 Resources

- **Threat Feeds**:
  - [AlienVault OTX](https://otx.alienvault.com/)
  - [URLhaus](https://urlhaus.abuse.ch/)
  - [Google OSV](https://osv.dev/)
  - [DigitalSide Threat Intel](https://osint.digitalside.it/)

- **Integrations**:
  - [SentinelOne API](https://xsoar.pan.dev/docs/reference/integrations/sentinel-one-v2)
  - [Slack API](https://api.slack.com/)

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

- Run `make help` for all available commands
- Check [docs/MAKEFILE_GUIDE.md](docs/MAKEFILE_GUIDE.md) for troubleshooting
- Open GitHub issues for bugs or feature requests

---

**Built with ❤️ for security teams** | Made with Go 🐹 | Powered by PostgreSQL 🐘
