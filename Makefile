# Makefile for Aethelred - Sovereign L1 for Verifiable AI
# The Digital Seal for Verifiable Intelligence
#
# ARCHITECTURE: This project has two independent runtime stacks:
#
#   Go Stack (Cosmos SDK)          Rust Stack (crates/)
#   ├── app/          ABCI++ app   ├── aethelred-core       Core crypto
#   ├── x/pouw/        PoUW module   ├── aethelred-consensus  VRF consensus
#   ├── x/seal/       Seal module  ├── aethelred-vm         WASM VM
#   ├── x/verify/     Verify mod   ├── aethelred-mempool    Mempool
#   └── cmd/          Node binary  ├── aethelred-bridge     Bridge relayer
#                                  └── falcon-lion          Trade demo
#
# Integration: HTTP/gRPC only (no FFI/CGo). Shared contract: proto/*.proto
# Go chain is source of truth. Rust services are stateless workers.

BINARY_NAME = aethelredd
BUILD_DIR = ./build
GO = go
# Rust uses a top-level vendor/ directory; force module mode for Go commands.
GOFLAGS ?= -mod=mod
GOCACHE ?= $(CURDIR)/.cache/go-build
LDFLAGS = -s -w -X github.com/aethelred/aethelred/app.Version=$(VERSION)

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Docker
DOCKER_IMAGE = aethelred/aethelredd
DOCKER_TAG = $(VERSION)

# Testnet
CHAIN_ID = aethelred-testnet-1
MONIKER = aethelred-node

.PHONY: all build install clean test lint fmt proto openapi openapi-validate docs docker help sdk-version-check sdk-release-check sdk-publish-dry-run audit-signoff-check loadtest loadtest-scenarios coverage-critical

## help: Show this help message
help:
	@echo "Aethelred - The Digital Seal for Verifiable Intelligence"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'

## all: Build everything
all: build

## build: Build the aethelredd binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/aethelredd

## install: Install aethelredd to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/aethelredd

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf ~/.aethelred

## test: Run all tests
test:
	@echo "Running tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v ./...

## test-unit: Run unit tests
test-unit:
	@echo "Running unit tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v -short ./...

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v -run Integration ./...

## test-consensus: Run consensus-specific tests
test-consensus:
	@echo "Running consensus tests..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v ./app/... -run Consensus

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -v -coverprofile=coverage.out ./...
	GOCACHE=$(GOCACHE) $(GO) tool cover -html=coverage.out -o coverage.html

## coverage-critical: Enforce >=95% average coverage for consensus/verification critical guardrails
coverage-critical:
	@python3 ./scripts/check_critical_coverage.py --threshold 95

## bench: Run benchmarks for core packages
bench:
	@echo "Running benchmarks..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test $(GOFLAGS) -run=^$$ -bench=. -benchmem ./x/pouw/... ./x/verify/...

## bench-report: Run benchmarks and save a timestamped report
bench-report:
	@./scripts/run_benchmarks.sh

## loadtest: Run load test with default baseline settings
loadtest:
	@echo "Running baseline load test..."
	$(GO) run ./cmd/aethelred-loadtest --scenario baseline

## loadtest-scenarios: Run all predefined stress scenarios
loadtest-scenarios:
	@echo "Running all load test scenarios..."
	$(GO) run ./cmd/aethelred-loadtest --all-scenarios

## lint: Run linters
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: brew install golangci-lint"; \
	fi

## fmt: Format code
fmt:
	@echo "Formatting code..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

## proto: Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@./scripts/protocgen.sh

## openapi: Generate OpenAPI (Swagger) specification
openapi:
	@echo "Generating OpenAPI spec..."
	@./scripts/openapi_gen.sh

## openapi-validate: Generate and validate OpenAPI artifacts
openapi-validate: openapi
	@echo "Validating OpenAPI artifacts..."
	@test -f docs/api/openapi/aethelred.openapi.yaml
	@test -f docs/api/openapi/aethelred.swagger.json
	@jq . docs/api/openapi/aethelred.swagger.json >/dev/null
	@echo "OpenAPI validation passed."

## docs: Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p $(GOCACHE)
	@GOCACHE=$(GOCACHE) $(GO) doc -all ./... > docs/api/godoc.txt

## sdk-version-check: Validate SDK/API versions against the matrix
sdk-version-check:
	@echo "Checking SDK/API version matrix..."
	@python3 ./scripts/check_sdk_versions.py

## sdk-release-check: Run SDK release gates (versions + OpenAPI)
sdk-release-check: sdk-version-check openapi-validate
	@echo "SDK release checks passed."

## sdk-publish-dry-run: Run local SDK publish dry-run (build/package only)
sdk-publish-dry-run:
	@./scripts/sdk_publish_dry_run.sh

## audit-signoff-check: Enforce completed external audit signoff for contracts + consensus
audit-signoff-check:
	@python3 ./scripts/check_contract_audit_signoff.py \
		--required-scope /contracts/ethereum \
		--required-scope "Consensus + vote extensions" \
		--require-signed-report

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

## docker-push: Push Docker image
docker-push:
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest

## init: Initialize a new node
init:
	@echo "Initializing $(MONIKER) on chain $(CHAIN_ID)..."
	$(BUILD_DIR)/$(BINARY_NAME) init $(MONIKER) --chain-id $(CHAIN_ID)

## genesis: Create genesis file
genesis:
	@echo "Creating genesis file..."
	$(BUILD_DIR)/$(BINARY_NAME) add-genesis-account $(shell $(BUILD_DIR)/$(BINARY_NAME) keys show validator -a) 1000000000uaeth
	$(BUILD_DIR)/$(BINARY_NAME) gentx validator 100000000uaeth --chain-id $(CHAIN_ID)
	$(BUILD_DIR)/$(BINARY_NAME) collect-gentxs

## start: Start a single node
start: build
	@echo "Starting $(BINARY_NAME)..."
	$(BUILD_DIR)/$(BINARY_NAME) start

## testnet-start: Start local testnet (3 validators)
testnet-start: build
	@echo "Starting local testnet..."
	@./scripts/testnet.sh start

## testnet-stop: Stop local testnet
testnet-stop:
	@echo "Stopping local testnet..."
	@./scripts/testnet.sh stop

## testnet-reset: Reset local testnet
testnet-reset:
	@echo "Resetting local testnet..."
	@./scripts/testnet.sh reset

## keys-add: Add a new key
keys-add:
	@$(BUILD_DIR)/$(BINARY_NAME) keys add $(name)

## keys-list: List all keys
keys-list:
	@$(BUILD_DIR)/$(BINARY_NAME) keys list

## status: Show node status
status:
	@$(BUILD_DIR)/$(BINARY_NAME) status

## version: Show version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

# Module-specific targets

## seal-query: Query seal module
seal-query:
	@$(BUILD_DIR)/$(BINARY_NAME) query seal $(args)

## pouw-query: Query pouw module
pouw-query:
	@$(BUILD_DIR)/$(BINARY_NAME) query pouw $(args)

## verify-query: Query verify module
verify-query:
	@$(BUILD_DIR)/$(BINARY_NAME) query verify $(args)

## submit-job: Submit a compute job
submit-job:
	@echo "Submitting compute job..."
	@$(BUILD_DIR)/$(BINARY_NAME) tx pouw submit-job $(args)

## register-model: Register an AI model
register-model:
	@echo "Registering AI model..."
	@$(BUILD_DIR)/$(BINARY_NAME) tx pouw register-model $(args)

# Development helpers

## mod-tidy: Tidy go modules
mod-tidy:
	@echo "Tidying go modules..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) mod tidy

## mod-download: Download go modules
mod-download:
	@echo "Downloading go modules..."
	@mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) mod download

## benchmark: Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

## profile: Generate CPU profile
profile:
	@echo "Generating CPU profile..."
	$(GO) test -cpuprofile=cpu.prof -bench=. ./app

## trace: Generate execution trace
trace:
	@echo "Generating execution trace..."
	$(GO) test -trace=trace.out -bench=. ./app

# ============================================================================
# Rust Targets (crates/)
# ============================================================================

## rust-build: Build all Rust crates
rust-build:
	@echo "Building Rust crates..."
	cd crates && cargo build --release --workspace

## rust-test: Run all Rust tests
rust-test:
	@echo "Running Rust tests..."
	cd crates && cargo test --all-features --workspace

## rust-lint: Run Rust linters
rust-lint:
	@echo "Running Rust linters..."
	cd crates && cargo fmt --all -- --check
	cd crates && cargo clippy --all-targets --all-features -- -D warnings

## rust-clean: Clean Rust build artifacts
rust-clean:
	@echo "Cleaning Rust build artifacts..."
	cd crates && cargo clean

# ============================================================================
# Full Stack Targets
# ============================================================================

## build-all: Build both Go and Rust stacks
build-all: build rust-build

## test-all: Test both Go and Rust stacks
test-all: test rust-test

## lint-all: Lint both Go and Rust stacks
lint-all: lint rust-lint

## clean-all: Clean both Go and Rust build artifacts
clean-all: clean rust-clean
