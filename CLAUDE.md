# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenSearch Security Certificate Tool is a Go-based reimplementation of the Java-based Search Guard TLS Tool. It's a command-line utility for SSL/TLS certificate generation and validation for OpenSearch clusters. The tool generates X.509 certificates, certificate authorities, and OpenSearch Security configuration snippets.

## Build System & Commands

**Go-based project (Go 1.21+)**

- Build project: `go build ./...`
- Run tests: `go test ./...`  
- Package application: `make build` (creates binary in `bin/`)
- Create multi-platform binaries: `make build-all`
- Install dependencies: `go mod tidy`

**Running the tool:**
- Via binary: `./bin/opensearch-security-certtool [command] [options]`
- Development mode: `go run . [command] [options]`

**Available commands:**
- `go run . ca -c config.yml` or `go run . --create-ca -c config.yml`
- `go run . crt -c config.yml` or `go run . --create-cert -c config.yml`
- `go run . csr -c config.yml` or `go run . --create-csr -c config.yml` (planned)

## Architecture

**Main Entry Points:**
- `cmd/root.go` - Root command with hybrid CLI support (both subcommands and flags)
- `cmd/create_ca.go` - Certificate Authority generation
- `cmd/create_cert.go` - Node and client certificate generation
- `cmd/ca.go`, `cmd/crt.go`, `cmd/csr.go` - Short-form subcommand aliases

**Core Components:**
- `internal/cert/` - Certificate generation, management, and encryption/decryption
- `internal/config/` - YAML configuration parsing and OpenSearch config generation  
- `internal/templates/` - Template constants and string management
- `internal/logger/` - Structured logging with security considerations

**Key Architecture Features:**
- **Hybrid CLI**: Supports both `ca -c config.yml` and `--create-ca -c config.yml` patterns
- **Template-based**: No hardcoded strings in Go source code - all in `templates.go`
- **Encrypted Private Keys**: Full support for PKCS#8 encrypted keys with auto-generated passwords
- **Password Resolution**: Automatically resolves "auto" passwords from README files
- **2-space YAML**: All generated YAML uses 2-space indentation consistently

**Configuration:**
- Uses YAML configuration files compatible with Java Search Guard TLS Tool
- Supports certificate authorities (root and intermediate) 
- Configures nodes and clients for certificate generation
- Supports CRL Distribution Points and Node OID extensions
- Uses standard Go `gopkg.in/yaml.v3` for parsing

**Key Dependencies:**
- `crypto/x509`, `crypto/rsa` for cryptographic operations
- `github.com/spf13/cobra` for CLI framework
- `gopkg.in/yaml.v3` for YAML configuration
- Standard library only - no external crypto dependencies

**Output Structure:**
- Generates certificates and keys in PEM format
- Creates `*_opensearch_config_snippet.yml` files with 2-space indentation
- Generates README files with certificate passwords and usage instructions
- Full compatibility with Java tool's output format and naming conventions

**Security Features:**
- PKCS#8 encrypted private keys with AES-256-CBC
- Auto-generated secure passwords (12+ characters)
- CRL Distribution Points support for certificate revocation
- Subject Alternative Names (DNS and IP) for flexible certificate validation
- Node OID extensions for OpenSearch Security compatibility

## Testing

**Test Organization:**
- All tests are in `tests/` directory (not scattered in project root)
- Test configurations in `tests/*.yml`
- Generated test output in `tests/*-output/`

**Test Types:**
- Unit tests for certificate generation
- Integration tests for full workflow
- Configuration validation tests
- Password management tests

## Important Implementation Details

**Password Management:**
- Config `pkPassword: auto` generates random passwords during creation
- Actual passwords stored in `root-ca.readme` and accessible via `resolveCAPassword()`
- Encrypted keys can be loaded with `LoadCAFromPEMWithPassword()`

**Template System:**
- All user-facing strings in `internal/templates/templates.go`
- Templates use Go `text/template` for dynamic content
- Constants for file extensions, field names, etc.

**Code Quality:**
- All Go source files end with newlines
- No hardcoded strings in source code
- 2-space indentation for all YAML output
- Structured error handling with context