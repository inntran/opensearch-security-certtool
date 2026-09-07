package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inntran/opensearch-security-certtool/internal/cert"
	"github.com/inntran/opensearch-security-certtool/internal/config"
	"github.com/inntran/opensearch-security-certtool/internal/logger"
)

// TestCreateCertCommandDoesNotAlterExistingCAReadme verifies that running
// `crt` against an already-existing CA (i.e. only signing node/client
// certs, not creating a new CA) never rewrites root-ca.readme. Loading an
// existing encrypted CA key does not populate certManager's in-memory
// password map (only GenerateCA does), so before this fix,
// GenerateCAReadme would blindly overwrite the file with "pkPassword: none"
// even though the CA is still password protected on disk.
func TestCreateCertCommandDoesNotAlterExistingCAReadme(t *testing.T) {
	tempDir := t.TempDir()

	origCfg, origOutputDir, origVerbose, origCertManager, origLog := cfg, outputDir, verbose, certManager, log
	t.Cleanup(func() {
		cfg, outputDir, verbose, certManager, log = origCfg, origOutputDir, origVerbose, origCertManager, origLog
	})

	// Step 1: create a root CA with a fixed password, matching what `ca`
	// would produce, including the README recording that password.
	cfg = &config.Config{
		CA: config.CAConfig{
			Root: config.CertConfig{
				DN:           "CN=root.ca.example.com,O=Example Com,C=US",
				KeySize:      2048,
				ValidityDays: 365,
				PKPassword:   "rootpass123",
			},
		},
		Defaults: config.DefaultConfig{
			ValidityDays:            365,
			GeneratedPasswordLength: 12,
		},
		Nodes: []config.NodeConfig{
			{Name: "node1", DN: "CN=node1.example.com,O=Example Com,C=US", DNS: "node1.example.com"},
		},
	}
	outputDir = tempDir
	verbose = false
	log = logger.New(false)
	certManager = cert.NewCertificateManager(outputDir, cfg.Defaults.GeneratedPasswordLength, log)

	if err := createCertCommand(); err != nil {
		t.Fatalf("First createCertCommand() (CA creation) error = %v", err)
	}

	readmePath := filepath.Join(tempDir, "root-ca.readme")
	firstReadme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read root-ca.readme after CA creation: %v", err)
	}
	if !strings.Contains(string(firstReadme), "rootpass123") {
		t.Fatalf("Expected root-ca.readme to record the CA password, got:\n%s", firstReadme)
	}

	caKeyPath := filepath.Join(tempDir, "root-ca.key")
	origKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatalf("Failed to read root-ca.key: %v", err)
	}

	// Step 2: run createCertCommand again (as if in a fresh process) with a
	// brand new CertificateManager, so no in-memory password state carries
	// over -- this simulates the real-world scenario of `crt` running in a
	// separate invocation after `ca`, only to sign more certs.
	cfg.Nodes = append(cfg.Nodes, config.NodeConfig{
		Name: "node2", DN: "CN=node2.example.com,O=Example Com,C=US", DNS: "node2.example.com",
	})
	certManager = cert.NewCertificateManager(outputDir, cfg.Defaults.GeneratedPasswordLength, log)

	if err := createCertCommand(); err != nil {
		t.Fatalf("Second createCertCommand() (sign against existing CA) error = %v", err)
	}

	secondReadme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read root-ca.readme after second run: %v", err)
	}
	if string(secondReadme) != string(firstReadme) {
		t.Errorf("Expected root-ca.readme to be left untouched when only signing against an existing CA.\nBefore:\n%s\nAfter:\n%s", firstReadme, secondReadme)
	}

	newKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatalf("Failed to read root-ca.key after second run: %v", err)
	}
	if string(newKeyBytes) != string(origKeyBytes) {
		t.Error("Expected root-ca.key to be left untouched when only signing against an existing CA")
	}
}
