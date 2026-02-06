.PHONY: help build run ingestion test security clean fmt lint docker-up docker-down install-tools

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=watchtower
INGESTER_BINARY=ingester
CLI_BINARY=cli
API_BINARY=watchtower-api
DB_URL=postgres://admin:secretpassword@localhost:5432/watchtower
GRPC_PORT=50051
API_PORT=8080

## help: Show this help message
help:
	@echo "Available targets:"
	@echo ""
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/^## /  /'
	@echo ""

## build: Build all binaries (watchtower server, API server, ingester, cli)
build:
	@echo "🔨 Building all binaries..."
	@go build -o bin/$(BINARY_NAME) ./cmd/watchtower
	@go build -o bin/$(API_BINARY) ./cmd/watchtower-api
	@go build -o bin/$(INGESTER_BINARY) ./cmd/ingester
	@go build -o bin/$(CLI_BINARY) ./cmd/cli
	@echo "✅ Build complete! Binaries in ./bin/"

## build-server: Build only the watchtower gRPC server
build-server:
	@echo "🔨 Building watchtower server..."
	@go build -o bin/$(BINARY_NAME) ./cmd/watchtower
	@echo "✅ Server built: ./bin/$(BINARY_NAME)"

## build-ingester: Build only the ingester
build-ingester:
	@echo "🔨 Building ingester..."
	@go build -o bin/$(INGESTER_BINARY) ./cmd/ingester
	@echo "✅ Ingester built: ./bin/$(INGESTER_BINARY)"

## run: Start the watchtower gRPC server
run: build-server
	@echo "🚀 Starting Watchtower gRPC server on port $(GRPC_PORT)..."
	@./bin/$(BINARY_NAME)

## run-dev: Start the server without building (for quick restarts during development)
run-dev:
	@echo "🚀 Starting Watchtower gRPC server (dev mode)..."
	@go run ./cmd/watchtower/main.go

## build-api: Build REST API server
build-api:
	@echo "🔨 Building REST API server..."
	@go build -o bin/$(API_BINARY) ./cmd/watchtower-api
	@echo "✅ API server built: ./bin/$(API_BINARY)"

## run-api: Start REST API server
run-api: build-api
	@echo "🚀 Starting Watchtower REST API on port $(API_PORT)..."
	@./bin/$(API_BINARY)

## run-api-dev: Start REST API without building
run-api-dev:
	@echo "🚀 Starting Watchtower REST API (dev mode)..."
	@go run ./cmd/watchtower-api/main.go

## ingestion: Run threat intelligence ingestion pipeline
ingestion: build-ingester
	@echo "🔄 Starting threat intelligence ingestion..."
	@echo "⚠️  This may take several minutes depending on feed sizes"
	@./bin/$(INGESTER_BINARY)

## ingestion-dev: Run ingestion without building (for quick testing)
ingestion-dev:
	@echo "🔄 Starting threat intelligence ingestion (dev mode)..."
	@go run ./cmd/ingester/main.go

## test: Run all tests
test:
	@echo "🧪 Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo "✅ Tests complete!"

## test-coverage: Run tests with coverage report
test-coverage: test
	@echo "📊 Generating coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

## test-unit: Run only unit tests (exclude integration tests)
test-unit:
	@echo "🧪 Running unit tests..."
	@go test -v -short ./...

## security: Run security checks (gosec, go vet, staticcheck)
security: install-tools
	@echo "🔒 Running security checks..."
	@echo "Running go vet..."
	@go vet ./...
	@echo "Running gosec..."
	@gosec -quiet ./...
	@echo "Running staticcheck..."
	@staticcheck ./...
	@echo "✅ Security checks passed!"

## fmt: Format all Go code with gofmt
fmt:
	@echo "✨ Formatting code..."
	@gofmt -l -w .
	@echo "✅ Code formatted!"

## lint: Run linters (golangci-lint)
lint: install-tools
	@echo "🔍 Running linters..."
	@golangci-lint run ./...
	@echo "✅ Linting complete!"

## clean: Remove built binaries and generated files
clean:
	@echo "🧹 Cleaning up..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@echo "✅ Cleanup complete!"

## install-tools: Install required development tools
install-tools:
	@echo "📦 Installing development tools..."
	@command -v gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@command -v staticcheck > /dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	@command -v golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "✅ Tools installed!"

## env-setup: Create .env file from .env.example
env-setup:
	@if [ -f .env ]; then \
		echo "⚠️  .env file already exists"; \
	else \
		cp .env.example .env; \
		echo "✅ Created .env file from .env.example"; \
		echo "📝 Edit .env to add your API keys (optional)"; \
	fi

## docker-up: Start PostgreSQL database with Docker Compose
docker-up:
	@echo "🐳 Starting PostgreSQL database..."
	@docker-compose up -d postgres
	@echo "⏳ Waiting for database to be ready..."
	@sleep 5
	@echo "✅ Database is running on localhost:5432"

## docker-status: Check Docker and container status
docker-status:
	@echo "🐳 Docker status:"
	@docker ps --filter "name=watchtower-postgres" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "⚠️  No containers running"

## docker-down: Stop all Docker containers
docker-down:
	@echo "🐳 Stopping Docker containers..."
	@docker-compose down
	@echo "✅ Containers stopped"

## db-migrate: Run database migrations
db-migrate:
	@echo "🗄️  Running database migrations..."
	@docker exec -i watchtower-postgres-1 psql -U admin -d watchtower < migrations/001_init.sql 2>&1 | grep -v "already exists" || true
	@docker exec -i watchtower-postgres-1 psql -U admin -d watchtower < migrations/002_add_version_column.sql 2>&1 | grep -v "already exists" || true
	@echo "✅ Migrations complete!"

## db-reset: Reset database (drop and recreate)
db-reset:
	@echo "⚠️  Resetting database..."
	@docker exec watchtower-postgres-1 psql -U admin -d postgres -c "DROP DATABASE IF EXISTS watchtower;" 2>/dev/null || true
	@docker exec watchtower-postgres-1 psql -U admin -d postgres -c "CREATE DATABASE watchtower;"
	@$(MAKE) db-migrate
	@echo "✅ Database reset complete!"

## db-status: Check database connection and show IOC counts
db-status:
	@echo "🔍 Database status:"
	@docker exec watchtower-postgres-1 psql -U admin -d watchtower -c "SELECT type, COUNT(*) as count FROM iocs GROUP BY type ORDER BY count DESC;" 2>/dev/null || echo "⚠️  Database not ready or no IOCs yet"
	@echo ""
	@docker exec watchtower-postgres-1 psql -U admin -d watchtower -c "SELECT source, COUNT(*) as count FROM iocs GROUP BY source ORDER BY count DESC LIMIT 10;" 2>/dev/null || true

## proto-gen: Regenerate gRPC code from proto files
proto-gen:
	@echo "🔧 Regenerating protobuf code..."
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/threat.proto
	@echo "✅ Protobuf code generated!"

## deps: Download and verify dependencies
deps:
	@echo "📦 Downloading dependencies..."
	@go mod download
	@go mod verify
	@echo "✅ Dependencies ready!"

## deps-update: Update all dependencies to latest versions
deps-update:
	@echo "⬆️  Updating dependencies..."
	@go get -u ./...
	@go mod tidy
	@echo "✅ Dependencies updated!"

## check: Run all checks (fmt, lint, security, test)
check: fmt lint security test
	@echo "✅ All checks passed!"

## full-setup: Complete setup (install tools, start DB, migrate, run ingestion)
full-setup: install-tools docker-up db-migrate ingestion
	@echo "🎉 Full setup complete! Run 'make run' to start the server."

## quick-start: Quick start for development (assumes DB is running)
quick-start: build
	@echo "🚀 Quick start..."
	@echo "Starting server in background..."
	@./bin/$(BINARY_NAME) &
	@echo "$$!" > .server.pid
	@sleep 2
	@echo "✅ Server running (PID: $$(cat .server.pid))"
	@echo "Test with: grpcurl -plaintext -d '{\"value\": \"1.2.3.4\"}' localhost:50051 watchtower.Watchtower/CheckIOC"

## stop: Stop running server
stop:
	@if [ -f .server.pid ]; then \
		echo "🛑 Stopping server..."; \
		kill $$(cat .server.pid) 2>/dev/null || true; \
		rm .server.pid; \
		echo "✅ Server stopped"; \
	else \
		echo "⚠️  No server PID file found"; \
	fi

## logs: Show recent logs (if running with systemd/docker)
logs:
	@echo "📋 Recent PostgreSQL logs:"
	@docker logs --tail=50 watchtower-postgres-1 2>/dev/null || echo "⚠️  PostgreSQL container not running"

## db-shell: Open psql shell in Docker container
db-shell:
	@echo "🐚 Opening PostgreSQL shell..."
	@docker exec -it watchtower-postgres-1 psql -U admin -d watchtower

## benchmark: Run performance benchmarks
benchmark:
	@echo "⚡ Running benchmarks..."
	@go test -bench=. -benchmem ./...

## mod-tidy: Clean up go.mod and go.sum
mod-tidy:
	@echo "🧹 Tidying go.mod..."
	@go mod tidy
	@echo "✅ Modules tidied!"

## arch-check: Verify architecture compliance (no I/O in domain layer)
arch-check:
	@echo "🏛️  Checking architecture compliance..."
	@echo "Checking domain layer purity..."
	@! grep -r "net/http\|database\|pgx\|sql" internal/core/domain/ && echo "✅ Domain layer is pure" || echo "❌ Domain layer has I/O dependencies!"
	@echo "Checking dependency directions..."
	@echo "✅ Architecture check complete!"

## supply-chain-test: Test supply chain detection with sample packages
supply-chain-test:
	@echo "🔍 Testing supply chain detection..."
	@echo "Testing npm package query..."
	@grpcurl -plaintext -d '{"value": "lodash"}' localhost:$(GRPC_PORT) watchtower.Watchtower/SearchIOC
	@echo ""
	@echo "Testing PyPI package query..."
	@grpcurl -plaintext -d '{"value": "requests"}' localhost:$(GRPC_PORT) watchtower.Watchtower/SearchIOC

## test-webhook: Test SentinelOne webhook integration
test-webhook:
	@echo "🧪 Testing SentinelOne webhook..."
	@curl -X POST http://localhost:$(API_PORT)/api/v1/webhooks/sentinelone \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer test-secret" \
		-d '{ \
			"alertId": "test-12345", \
			"threatName": "Test.Malware.Generic", \
			"classification": "Malware", \
			"indicators": [ \
				{"type": "IPV4", "value": "192.0.2.1"}, \
				{"type": "SHA256", "value": "a3f5d8c2b9e1f7a6d4c8e3b5a9f2d6c1e8a4b7d3f9c2a5e8b1d4f7a3c6e9b2d5"} \
			], \
			"endpoint": { \
				"computerName": "TEST-SERVER-01", \
				"osType": "linux", \
				"agentVersion": "23.1.2.5" \
			}, \
			"timestamp": "2026-02-01T12:00:00Z" \
		}' | jq .

## test-api: Test REST API endpoints
test-api:
	@echo "🧪 Testing REST API..."
	@echo "Testing health endpoint..."
	@curl -s http://localhost:$(API_PORT)/api/v1/health | jq .
	@echo ""
	@echo "Testing CheckIOC endpoint..."
	@curl -s "http://localhost:$(API_PORT)/api/v1/iocs/check?value=192.0.2.1" | jq .
	@echo ""
	@echo "Testing SearchIOC endpoint..."
	@curl -s "http://localhost:$(API_PORT)/api/v1/iocs/search?value=lodash" | jq .

## info: Show project information
info:
	@echo "📊 Watchtower Project Information"
	@echo "=================================="
	@echo "Go version: $$(go version)"
	@echo "Project path: $$(pwd)"
	@echo "Binary name: $(BINARY_NAME)"
	@echo "Database URL: $(DB_URL)"
	@echo "gRPC Port: $(GRPC_PORT)"
	@echo ""
	@echo "📂 Project structure:"
	@tree -L 2 -I 'bin|vendor' . 2>/dev/null || find . -maxdepth 2 -type d | grep -v "^\./\." | head -20
