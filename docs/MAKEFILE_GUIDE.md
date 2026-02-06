# Watchtower Makefile Guide

Quick reference for common development workflows using the Makefile.

## 🚀 Quick Start

### First Time Setup
```bash
# Complete setup (installs tools, starts DB, runs migrations, ingests data)
make full-setup

# Optional: Add API keys for additional threat feeds
make env-setup          # Creates .env from .env.example
# Edit .env and add your OTX_API_KEY if you have one

# Start the server
make run
```

### Daily Development
```bash
# Start database
make docker-up

# Run server in dev mode (fast iteration)
make run-dev

# In another terminal: run ingestion
make ingestion-dev
```

## 📋 Common Commands

### Building
```bash
make build              # Build all binaries (server, ingester, cli)
make build-server       # Build only the gRPC server
make build-ingester     # Build only the ingester
```

### Running
```bash
make run               # Build and run server
make run-dev           # Run server without building (faster)
make ingestion         # Run threat intelligence ingestion
make ingestion-dev     # Run ingestion without building (faster)
```

### Testing
```bash
make test              # Run all tests
make test-coverage     # Run tests with HTML coverage report
make test-unit         # Run only unit tests
make benchmark         # Run performance benchmarks
```

### Security & Quality
```bash
make security          # Run security scans (gosec, go vet, staticcheck)
make lint              # Run linters (golangci-lint)
make fmt               # Format all code with gofmt
make check             # Run all checks (fmt + lint + security + test)
make arch-check        # Verify hexagonal architecture compliance
```

### Database
```bash
make docker-up         # Start PostgreSQL with Docker
make docker-down       # Stop Docker containers
make docker-status     # Check Docker container status
make db-migrate        # Run database migrations (uses Docker, no psql needed)
make db-reset          # Drop and recreate database
make db-status         # Show IOC counts by type and source
make db-shell          # Open psql shell inside Docker container
make logs              # View PostgreSQL logs
```

**Note:** All database commands use Docker internally - you don't need PostgreSQL installed locally!

### Maintenance
```bash
make clean             # Remove built binaries and coverage files
make deps              # Download and verify dependencies
make deps-update       # Update all dependencies
make mod-tidy          # Clean up go.mod and go.sum
make install-tools     # Install development tools (gosec, staticcheck, etc.)
make env-setup         # Create .env file from .env.example (optional)
```

## 🎯 Common Workflows

### 1. First Time Setup
```bash
# Install tools, start DB, migrate, ingest data
make full-setup

# Start the server
make run
```

### 2. Adding New Features
```bash
# Format and check code
make fmt
make arch-check

# Run tests and security checks
make check

# Build and test
make build
make run-dev
```

### 3. Testing Supply Chain Detection
```bash
# Start database and server
make docker-up
make db-migrate
make run-dev

# In another terminal: ingest data
make ingestion-dev

# Test queries
make supply-chain-test

# Or manually with grpcurl:
grpcurl -plaintext -d '{"value": "lodash"}' localhost:50051 watchtower.Watchtower/SearchIOC
```

### 4. Before Committing
```bash
# Run all quality checks
make check

# Verify architecture
make arch-check

# Clean up
make clean
```

### 5. CI/CD Pipeline
```bash
# Install tools
make install-tools

# Run all checks
make check

# Build binaries
make build

# Optional: Run integration tests with DB
make docker-up
make db-migrate
make test
```

## 🔍 Useful Commands

### Check Database Status
```bash
make db-status
```
Shows IOC counts by type and source.

### View Project Info
```bash
make info
```
Shows Go version, paths, and project structure.

### Architecture Compliance
```bash
make arch-check
```
Verifies domain layer has no I/O dependencies.

### Coverage Report
```bash
make test-coverage
```
Generates `coverage.html` with visual coverage report.

### Quick Server Restart
```bash
make stop
make run-dev
```

### Reset Everything
```bash
make clean
make docker-down
make docker-up
make db-migrate
make ingestion
```

## 🐳 Docker Integration

The Makefile integrates with Docker Compose for PostgreSQL:

```bash
# Start PostgreSQL
make docker-up

# Check logs
make logs

# Stop everything
make docker-down
```

## 🛠️ Tool Installation

Required tools are automatically installed:
- `gosec` - Security scanning
- `staticcheck` - Static analysis
- `golangci-lint` - Comprehensive linting

```bash
make install-tools
```

## 📊 Development Metrics

### Build Times
- `make build`: Full rebuild (~5-10s)
- `make run-dev`: Skip build, direct run (~1s)
- `make ingestion`: Full ingestion (~2-5 minutes depending on feeds)

### Database Size Estimates
- After full ingestion: ~50-100MB
- Supply chain packages: ~10,000+ IOCs per ecosystem
- Traditional feeds: ~5,000-20,000 IOCs

## 🎓 Tips & Tricks

### Fast Iteration During Development
```bash
# Terminal 1: Auto-restart on changes (using watchexec or similar)
watchexec -r -e go make run-dev

# Terminal 2: Keep database running
make docker-up
```

### Check What Changed
```bash
git status
make fmt  # Format before checking
git diff
```

### Quick Test Specific Package
```bash
go test -v ./internal/adapter/handler/
```

### Debug Mode
```bash
# Run with verbose logging
go run -v ./cmd/watchtower/main.go
```

### Performance Testing
```bash
# Build optimized binary
go build -ldflags="-s -w" -o bin/watchtower ./cmd/watchtower

# Run benchmarks
make benchmark
```

## 🔗 Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Install tools
  run: make install-tools

- name: Run checks
  run: make check

- name: Build
  run: make build
```

### Pre-commit Hook
```bash
#!/bin/bash
make fmt
make arch-check
make test-unit
```

## 📚 Additional Resources

- Run `make help` to see all available commands
- Check [CLAUDE.md](CLAUDE.md) for architectural constraints
- See [README.md](README.md) for project overview

## 🆘 Troubleshooting

### Database Connection Issues
```bash
make docker-down
make docker-up
sleep 5
make db-migrate
```

### Build Failures
```bash
make clean
make deps
make build
```

### Test Failures
```bash
# Check if database is running
make db-status

# Reset database
make db-reset
```

### Port Already in Use
```bash
# Check what's using port 50051
lsof -i :50051

# Stop any running servers
make stop
```

### Missing .env file
The `.env` file is **optional**. The ingester works fine without it!

Only needed if you want to add API keys for additional providers like AlienVault OTX:
```bash
make env-setup          # Create .env from template
# Edit .env and add your API keys
```

### "psql: command not found"
No worries! The Makefile uses Docker for all database operations, so you don't need PostgreSQL installed locally.

Make sure Docker is running:
```bash
docker ps
make docker-status
```

If you see "Cannot connect to Docker daemon", start Docker Desktop.

### Database Connection Refused
```bash
# Check if container is running
make docker-status

# Restart database
make docker-down
make docker-up

# Wait a bit longer for startup
sleep 10
make db-migrate
```

### Interactive Database Access
Need to run SQL manually?
```bash
make db-shell           # Opens psql inside Docker container
```

Then you can run any SQL commands:
```sql
\dt                    -- List tables
SELECT * FROM iocs LIMIT 10;
\q                     -- Quit
```

---

**Need help?** Run `make help` to see all available commands.
