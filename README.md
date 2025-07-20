# OpenSearch Security Certificate Tool

A fast, cross-platform command-line tool for generating SSL/TLS certificates for OpenSearch Security clusters. This is a reimplementation of the original Java-based Search Guard TLS Tool in Go, providing easy-to-deploy single binaries for all major platforms.

## Features

-  **Create Certificate Authorities** (root and intermediate)
-  **Generate node certificates** for OpenSearch clusters with SAN support
-  **Generate client certificates** for authentication
- = **Create Certificate Signing Requests (CSRs)** (coming soon)
- = **Validate certificates and configurations** (coming soon)
-  **Cross-platform binaries** (Linux, macOS, Windows - AMD64 and ARM64)
-  **YAML configuration** compatible with original tool format
-  **No runtime dependencies** - single static binary

## Quick Start

### 1. Download Binary

Download the appropriate binary for your platform from the releases page or build from source.

### 2. Create Configuration

Create a `config.yml` file (see `examples/config.yml` for a complete example):

```yaml
ca:
  root:
    dn: CN=root.ca.example.com,OU=CA,O=Example Com\, Inc.,DC=example,DC=com
    keysize: 2048
    validityDays: 3650
    pkPassword: auto

defaults:
  validityDays: 3650
  httpsEnabled: true

nodes:
  - name: node1
    dn: CN=node1.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    dns: node1.example.com
    ip: 10.0.2.1

clients:
  - name: admin
    dn: CN=admin.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    admin: true
```

### 3. Generate Certificates

```bash
# Create Certificate Authority
./opensearch-security-certtool create-ca --config config.yml

# Generate all certificates
./opensearch-security-certtool create-cert --config config.yml

# Use verbose output
./opensearch-security-certtool create-ca --config config.yml --verbose
```

## Commands

### `create-ca`
Creates a new Certificate Authority (root and optional intermediate CA).

```bash
opensearch-security-certtool create-ca --config config.yml [--verbose] [--target output_dir]
```

### `create-cert`
Generates node and client certificates signed by the CA.

```bash
opensearch-security-certtool create-cert --config config.yml [--verbose] [--target output_dir]
```

## Configuration

The tool uses YAML configuration files compatible with the original Java tool format. Key sections:

- **`ca`**: Certificate Authority configuration (root and optional intermediate)
- **`defaults`**: Default values applied to all certificates
- **`nodes`**: OpenSearch cluster node definitions with DNS names and IP addresses
- **`clients`**: Client certificate definitions for authentication

See `examples/config.yml` for a complete configuration example.

## Building from Source

### Prerequisites
- Go 1.21 or later

### Build Commands

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
make test

# Run linter
make lint

# Update dependencies
make update-deps

# Run with example config
make run
```

### Development Features

- **Comprehensive testing** with unit and integration tests
- **Security validation** for certificates and configurations  
- **Structured error handling** with detailed context
- **Code quality checks** with golangci-lint
- **CI/CD pipeline** with automated security scanning
- **Cross-platform builds** for easy deployment

### Cross-Platform Builds

The Makefile supports building for:
- Linux (AMD64, ARM64)
- macOS (AMD64, ARM64) 
- Windows (AMD64, ARM64)

All binaries are statically linked with no runtime dependencies.

## Output

Generated certificates and keys are saved in PEM format:
- `root-ca.pem` / `root-ca.key` - Root CA certificate and private key
- `signing-ca.pem` / `signing-ca.key` - Intermediate CA (if configured)
- `{node-name}.pem` / `{node-name}.key` - Node certificates
- `{node-name}_http.pem` / `{node-name}_http.key` - HTTP certificates (if enabled)
- `{client-name}.pem` / `{client-name}.key` - Client certificates

## Compatibility

This tool generates certificates compatible with:
- OpenSearch Security
- Elasticsearch with Search Guard
- Any system requiring X.509 certificates

Certificate formats and extensions match the original Java tool for seamless migration.

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

## Migration from Java Tool

This Go implementation is designed as a drop-in replacement for the original Java-based tool:

1. **Same configuration format** - existing YAML configs work unchanged
2. **Same certificate output** - generates identical certificate structures
3. **Same command-line interface** - familiar flags and options
4. **Better deployment** - single binary instead of Java dependencies

Simply replace the Java tool with the appropriate binary for your platform.
