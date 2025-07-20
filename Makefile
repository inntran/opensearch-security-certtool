# OpenSearch Security Certificate Tool - Cross-platform build

# Application name
APP_NAME := opensearch-security-certtool
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE) -w -s"

# Output directory
BUILD_DIR := dist

# Platforms to build for
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all build clean test lint help

# Default target
all: clean test build

# Build for current platform
build:
	@echo "Building $(APP_NAME) for current platform..."
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) .

# Build for all platforms
build-all: clean
	@echo "Building $(APP_NAME) for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		output_name=$(APP_NAME)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then \
			output_name=$$output_name.exe; \
		fi; \
		echo "Building for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o $(BUILD_DIR)/$$output_name .; \
		if [ $$? -ne 0 ]; then \
			echo "Failed to build for $$os/$$arch"; \
			exit 1; \
		fi; \
	done
	@echo "Build completed! Binaries are in $(BUILD_DIR)/"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, running go vet instead"; \
		go vet ./...; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Update dependencies
update-deps:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Run the application (requires config file)
run:
	@if [ ! -f "examples/config.yml" ]; then \
		echo "Error: examples/config.yml not found"; \
		echo "Please create a config file first"; \
		exit 1; \
	fi
	go run . create-ca --config examples/config.yml --verbose

# Install to GOBIN
install:
	@echo "Installing $(APP_NAME)..."
	go install $(LDFLAGS) .

# Show help
help:
	@echo "Available targets:"
	@echo "  build      - Build for current platform"
	@echo "  build-all  - Build for all platforms"
	@echo "  test       - Run tests"
	@echo "  lint       - Run linter"
	@echo "  clean      - Clean build artifacts"
	@echo "  deps       - Install dependencies"
	@echo "  update-deps- Update dependencies"
	@echo "  run        - Run with example config"
	@echo "  install    - Install to GOBIN"
	@echo "  help       - Show this help"

# Show build info
info:
	@echo "App Name: $(APP_NAME)"
	@echo "Version:  $(VERSION)"
	@echo "Commit:   $(COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Go Version: $(shell go version)"
