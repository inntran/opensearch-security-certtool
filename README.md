# OpenSearch Security Certificate Tool

A fast, cross-platform command-line tool for generating SSL/TLS certificates for OpenSearch Security clusters. This is a reimplementation of the original Java-based Search Guard TLS Tool in Go, providing easy-to-deploy single binaries for all major platforms.

## Features

- ✅ **Create Certificate Authorities** (root and intermediate CAs)
- ✅ **Generate node certificates** for OpenSearch clusters with SAN support
- ✅ **Generate client certificates** for authentication  
- ✅ **Encrypted private keys** with auto-generated passwords
- ✅ **CRL Distribution Points** support for certificate revocation
- ✅ **Node OID extensions** for OpenSearch Security compatibility
- ✅ **OpenSearch configuration generation** with 2-space YAML indentation
- 🔄 **Create Certificate Signing Requests (CSRs)** (coming soon)
- 🔄 **Certificate validation and diagnostics** (coming soon)
- ✅ **Cross-platform binaries** (Linux, macOS, Windows - AMD64 and ARM64)
- ✅ **YAML configuration** compatible with original Java tool format
- ✅ **No runtime dependencies** - single static binary

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

  # Optional intermediate CA for enhanced security
  intermediate:
    dn: CN=signing.ca.example.com,OU=CA,O=Example Com\, Inc.,DC=example,DC=com
    keysize: 2048
    validityDays: 3650
    pkPassword: auto
    # CRL distribution points for certificate revocation
    crlDistributionPoints: URI:https://example.com/revoked.crl

defaults:
  validityDays: 3650
  httpsEnabled: true
  generatedPasswordLength: 12

nodes:
  - name: node1
    dn: CN=node1.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    dns: node1.example.com
    ip: 10.0.2.1
  - name: node2
    dn: CN=node2.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    dns: node2.example.com
    ip: 10.0.2.2

clients:
  - name: admin
    dn: CN=admin.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    admin: true
```

### 3. Generate Certificates

```bash
# Create Certificate Authority
./opensearch-security-certtool ca --config config.yml

# Generate all certificates
./opensearch-security-certtool crt --config config.yml

# Alternative: Use long-form flags
./opensearch-security-certtool --create-ca --config config.yml
./opensearch-security-certtool --create-cert --config config.yml

# Use verbose output
./opensearch-security-certtool ca --config config.yml --verbose
```

## Commands

The tool supports both short-form subcommands and long-form flags for compatibility:

### `ca` / `--create-ca`
Creates a new Certificate Authority (root and optional intermediate CA).

```bash
opensearch-security-certtool ca --config config.yml [--verbose] [--target output_dir]
# OR
opensearch-security-certtool --create-ca --config config.yml [--verbose] [--target output_dir]
```

### `crt` / `--create-cert`
Generates node and client certificates signed by the CA, plus OpenSearch configuration snippets.

```bash
opensearch-security-certtool crt --config config.yml [--verbose] [--target output_dir]
# OR
opensearch-security-certtool --create-cert --config config.yml [--verbose] [--target output_dir]
```

### `csr` / `--create-csr` (Coming Soon)
Creates certificate signing requests.

```bash
opensearch-security-certtool csr --config config.yml [--verbose] [--target output_dir]
```

## Configuration

The tool uses YAML configuration files compatible with the original Java tool format. Key sections:

- **`ca`**: Certificate Authority configuration (root and optional intermediate)
- **`defaults`**: Default values applied to all certificates
- **`nodes`**: OpenSearch cluster node definitions with DNS names and IP addresses
- **`clients`**: Client certificate definitions for authentication

### Advanced Configuration Options

- **`pkPassword: auto`**: Generates secure random passwords automatically
- **`crlDistributionPoints`**: Specify CRL endpoints for certificate revocation
- **`nodeOid`**: Custom Node OID for OpenSearch Security compatibility
- **`httpsEnabled`**: Generate separate HTTP certificates for REST API

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

- **Comprehensive testing** with unit and integration tests in `tests/` directory
- **Security validation** for certificates and configurations  
- **Structured error handling** with detailed context
- **Template-based string management** - no hardcoded strings in source code
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

### Certificates and Keys (PEM format)
- `root-ca.pem` / `root-ca.key` - Root CA certificate and private key
- `signing-ca.pem` / `signing-ca.key` - Intermediate CA (if configured)
- `{node-name}.pem` / `{node-name}.key` - Node certificates with transport encryption
- `{node-name}_http.pem` / `{node-name}_http.key` - HTTP certificates (if separate from transport)
- `{client-name}.pem` / `{client-name}.key` - Client certificates for authentication

### Configuration and Documentation
- `{node-name}_opensearch_config_snippet.yml` - Configuration snippets for each node (2-space YAML indentation)
- `root-ca.readme` - Auto-generated passwords for CA private keys
- `client-certificates.readme` - Documentation for client certificate usage

The configuration snippets are ready to be inserted into each node's `opensearch.yml` file and use proper 2-space YAML indentation for consistency.

### Security Features

- **Encrypted Private Keys**: All private keys are encrypted using PKCS#8 with AES-256-CBC
- **Auto-Generated Passwords**: Secure random passwords (12+ characters) stored in README files
- **Password Resolution**: Tool automatically loads encrypted keys using stored passwords
- **CRL Support**: Certificate Revocation List distribution points for security management
- **Node OID Extensions**: Proper OpenSearch Security node identification

## Compatibility

This tool generates certificates compatible with:
- OpenSearch Security
- Elasticsearch with Search Guard
- Any system requiring X.509 certificates

Certificate formats and extensions match the original Java tool for seamless migration.

## Credits

This project is inspired by and maintains compatibility with the original [Search Guard TLS Tool](https://github.com/floragunncom/search-guard-tlstool) developed by floragunn GmbH. We acknowledge and appreciate their pioneering work in OpenSearch/Elasticsearch security tooling.

The configuration format, certificate generation workflow, and output structure are designed to be compatible with the original Java-based Search Guard TLS Tool, enabling seamless migration and cross-platform deployment.

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

## Migration from Java Tool

This Go implementation is designed as a drop-in replacement for the original Java-based tool:

1. **Same configuration format** - existing YAML configs work unchanged
2. **Same certificate output** - generates identical certificate structures with proper extensions
3. **Same command-line interface** - familiar flags and options plus convenient short-form commands
4. **Better deployment** - single binary instead of Java dependencies
5. **Enhanced security** - improved password management and encryption handling

Simply replace the Java tool with the appropriate binary for your platform. Generated certificates and configuration snippets are fully compatible.