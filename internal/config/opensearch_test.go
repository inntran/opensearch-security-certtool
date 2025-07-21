package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inntran/opensearch-security-certtool/internal/cert"
	"gopkg.in/yaml.v3"
)

func TestNewConfigGenerator(t *testing.T) {
	config := &Config{}
	outputDir := "/tmp/test"

	cg := NewConfigGenerator(config, outputDir)

	if cg.config != config {
		t.Error("Expected config to be set")
	}
	if cg.outputDir != outputDir {
		t.Errorf("Expected output dir %s, got %s", outputDir, cg.outputDir)
	}
}

func TestGenerateNodeConfigs(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CA: CAConfig{
			Root: CertConfig{
				DN: "CN=root.ca.example.com,O=Example Com,C=US",
			},
		},
		Defaults: DefaultConfig{
			ValidityDays:               365,
			HTTPSEnabled:               true,
			ReuseTransportCertificates: false,
			VerifyHostnames:            true,
			ResolveHostnames:           false,
			NodesDN:                    []string{"CN=*.example.com,O=Example Com,C=US"},
		},
		Nodes: []NodeConfig{
			{
				Name: "node1",
				DN:   "CN=node1.example.com,O=Example Com,C=US",
				DNS:  []string{"node1.example.com", "localhost"},
				IP:   []string{"127.0.0.1", "10.0.0.1"},
			},
			{
				Name: "node2",
				DN:   "CN=node2.example.com,O=Example Com,C=US",
				DNS:  "node2.example.com",
				IP:   "10.0.0.2",
			},
		},
		Clients: []ClientConfig{
			{
				Name:  "admin",
				DN:    "CN=admin,O=Example Com,C=US",
				Admin: true,
			},
			{
				Name:  "kibana",
				DN:    "CN=kibana,O=Example Com,C=US",
				Admin: false,
			},
		},
	}

	passwords := cert.NewCertificatePasswords()
	passwords.SetNodePasswords("node1", "transport123", "http123")
	passwords.SetNodePasswords("node2", "transport456", "")

	cg := NewConfigGenerator(config, tempDir)
	err := cg.GenerateNodeConfigs(passwords)
	if err != nil {
		t.Fatalf("GenerateNodeConfigs() error = %v", err)
	}

	// Check that config files were created
	expectedFiles := []string{
		"node1_opensearch_config_snippet.yml",
		"node2_opensearch_config_snippet.yml",
	}

	for _, filename := range expectedFiles {
		filePath := filepath.Join(tempDir, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("Expected config file not created: %s", filePath)
		}
	}

	// Read and validate node1 config
	node1ConfigPath := filepath.Join(tempDir, "node1_opensearch_config_snippet.yml")
	node1Data, err := os.ReadFile(node1ConfigPath)
	if err != nil {
		t.Fatalf("Failed to read node1 config: %v", err)
	}

	// Parse YAML and validate structure
	var node1Config OpenSearchNodeConfig
	// Skip the header comment for YAML parsing
	yamlContent := extractYAMLFromContent(string(node1Data))
	err = yaml.Unmarshal([]byte(yamlContent), &node1Config)
	if err != nil {
		t.Fatalf("Failed to parse node1 config: %v", err)
	}

	// Validate node1 configuration values
	if node1Config.TransportPemCertPath != "node1.pem" {
		t.Errorf("Expected transport cert path 'node1.pem', got %s", node1Config.TransportPemCertPath)
	}
	if node1Config.TransportPemKeyPath != "node1.key" {
		t.Errorf("Expected transport key path 'node1.key', got %s", node1Config.TransportPemKeyPath)
	}
	if node1Config.TransportPemKeyPassword != "transport123" {
		t.Errorf("Expected transport password 'transport123', got %s", node1Config.TransportPemKeyPassword)
	}
	if node1Config.TransportPemTrustedCAs != "root-ca.pem" {
		t.Errorf("Expected trusted CAs 'root-ca.pem', got %s", node1Config.TransportPemTrustedCAs)
	}

	// Validate HTTP configuration (separate certs)
	if !node1Config.HTTPEnabled {
		t.Error("Expected HTTP to be enabled")
	}
	if node1Config.HTTPPemCertPath != "node1_http.pem" {
		t.Errorf("Expected HTTP cert path 'node1_http.pem', got %s", node1Config.HTTPPemCertPath)
	}
	if node1Config.HTTPPemKeyPath != "node1_http.key" {
		t.Errorf("Expected HTTP key path 'node1_http.key', got %s", node1Config.HTTPPemKeyPath)
	}
	if node1Config.HTTPPemKeyPassword != "http123" {
		t.Errorf("Expected HTTP password 'http123', got %s", node1Config.HTTPPemKeyPassword)
	}

	// Validate node DNs
	expectedNodeDNs := []string{
		"CN=node1.example.com,O=Example Com,C=US",
		"CN=node2.example.com,O=Example Com,C=US",
		"CN=*.example.com,O=Example Com,C=US",
	}
	if len(node1Config.NodesDN) != len(expectedNodeDNs) {
		t.Errorf("Expected %d node DNs, got %d", len(expectedNodeDNs), len(node1Config.NodesDN))
	}

	// Validate admin DNs
	expectedAdminDNs := []string{"CN=admin,O=Example Com,C=US"}
	if len(node1Config.AdminDN) != len(expectedAdminDNs) {
		t.Errorf("Expected %d admin DNs, got %d", len(expectedAdminDNs), len(node1Config.AdminDN))
	}
	if node1Config.AdminDN[0] != expectedAdminDNs[0] {
		t.Errorf("Expected admin DN %s, got %s", expectedAdminDNs[0], node1Config.AdminDN[0])
	}
}

func TestGenerateNodeConfigsWithReusedCerts(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Defaults: DefaultConfig{
			HTTPSEnabled:               true,
			ReuseTransportCertificates: true, // Reuse transport certificates
		},
		Nodes: []NodeConfig{
			{
				Name: "node1",
				DN:   "CN=node1.example.com,O=Example Com,C=US",
			},
		},
		Clients: []ClientConfig{},
	}

	passwords := cert.NewCertificatePasswords()
	passwords.SetNodePasswords("node1", "transport123", "")

	cg := NewConfigGenerator(config, tempDir)
	err := cg.GenerateNodeConfigs(passwords)
	if err != nil {
		t.Fatalf("GenerateNodeConfigs() error = %v", err)
	}

	// Read and validate config
	configPath := filepath.Join(tempDir, "node1_opensearch_config_snippet.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	var nodeConfig OpenSearchNodeConfig
	yamlContent := extractYAMLFromContent(string(data))
	err = yaml.Unmarshal([]byte(yamlContent), &nodeConfig)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// When reusing transport certificates, HTTP should use same paths
	if nodeConfig.HTTPPemCertPath != nodeConfig.TransportPemCertPath {
		t.Error("Expected HTTP to reuse transport cert path")
	}
	if nodeConfig.HTTPPemKeyPath != nodeConfig.TransportPemKeyPath {
		t.Error("Expected HTTP to reuse transport key path")
	}
	if nodeConfig.HTTPPemKeyPassword != nodeConfig.TransportPemKeyPassword {
		t.Error("Expected HTTP to reuse transport key password")
	}
}

func TestGenerateNodeConfigsHTTPDisabled(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Defaults: DefaultConfig{
			HTTPSEnabled: false, // HTTP disabled
		},
		Nodes: []NodeConfig{
			{
				Name: "node1",
				DN:   "CN=node1.example.com,O=Example Com,C=US",
			},
		},
		Clients: []ClientConfig{},
	}

	passwords := cert.NewCertificatePasswords()

	cg := NewConfigGenerator(config, tempDir)
	err := cg.GenerateNodeConfigs(passwords)
	if err != nil {
		t.Fatalf("GenerateNodeConfigs() error = %v", err)
	}

	// Read and validate config
	configPath := filepath.Join(tempDir, "node1_opensearch_config_snippet.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	var nodeConfig OpenSearchNodeConfig
	yamlContent := extractYAMLFromContent(string(data))
	err = yaml.Unmarshal([]byte(yamlContent), &nodeConfig)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// HTTP should not be enabled
	if nodeConfig.HTTPEnabled {
		t.Error("Expected HTTP to be disabled")
	}
	if nodeConfig.HTTPPemCertPath != "" {
		t.Error("Expected no HTTP cert path when HTTP disabled")
	}
}

func TestBuildNodeConfig(t *testing.T) {
	config := &Config{
		Defaults: DefaultConfig{
			VerifyHostnames:  true,
			ResolveHostnames: false,
			HTTPSEnabled:     true,
		},
	}

	cg := NewConfigGenerator(config, "/tmp")

	node := NodeConfig{
		Name: "test-node",
		DN:   "CN=test-node.example.com,O=Test Org,C=US",
	}

	allNodeDNs := []string{
		"CN=node1.example.com,O=Test Org,C=US",
		"CN=node2.example.com,O=Test Org,C=US",
	}
	adminDNs := []string{"CN=admin,O=Test Org,C=US"}
	caFile := "root-ca.pem"

	passwords := cert.NewCertificatePasswords()
	passwords.SetNodePasswords("test-node", "transport456", "http456")

	nodeConfig := cg.buildNodeConfig(node, allNodeDNs, adminDNs, caFile, passwords)

	// Validate transport configuration
	if nodeConfig.TransportPemCertPath != "test-node.pem" {
		t.Errorf("Expected cert path 'test-node.pem', got %s", nodeConfig.TransportPemCertPath)
	}
	if nodeConfig.TransportPemKeyPath != "test-node.key" {
		t.Errorf("Expected key path 'test-node.key', got %s", nodeConfig.TransportPemKeyPath)
	}
	if nodeConfig.TransportPemKeyPassword != "transport456" {
		t.Errorf("Expected password 'transport456', got %s", nodeConfig.TransportPemKeyPassword)
	}
	if nodeConfig.TransportPemTrustedCAs != "root-ca.pem" {
		t.Errorf("Expected trusted CAs 'root-ca.pem', got %s", nodeConfig.TransportPemTrustedCAs)
	}

	// Validate hostname verification settings
	if !nodeConfig.TransportEnforceHostnames {
		t.Error("Expected hostname verification to be enabled")
	}
	if nodeConfig.TransportResolveHostnames {
		t.Error("Expected hostname resolution to be disabled")
	}

	// Validate node and admin DNs
	if len(nodeConfig.NodesDN) != len(allNodeDNs) {
		t.Errorf("Expected %d node DNs, got %d", len(allNodeDNs), len(nodeConfig.NodesDN))
	}
	if len(nodeConfig.AdminDN) != len(adminDNs) {
		t.Errorf("Expected %d admin DNs, got %d", len(adminDNs), len(nodeConfig.AdminDN))
	}

	// Validate HTTP configuration
	if !nodeConfig.HTTPEnabled {
		t.Error("Expected HTTP to be enabled")
	}
	if nodeConfig.HTTPPemCertPath != "test-node_http.pem" {
		t.Errorf("Expected HTTP cert path 'test-node_http.pem', got %s", nodeConfig.HTTPPemCertPath)
	}
	if nodeConfig.HTTPPemKeyPassword != "http456" {
		t.Errorf("Expected HTTP password 'http456', got %s", nodeConfig.HTTPPemKeyPassword)
	}
}

func TestGenerateClientReadme(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Clients: []ClientConfig{
			{Name: "admin", DN: "CN=admin,O=Test Org,C=US", Admin: true},
			{Name: "kibana", DN: "CN=kibana,O=Test Org,C=US", Admin: false},
		},
	}

	passwords := cert.NewCertificatePasswords()
	passwords.SetClientPassword("admin", "admin123")
	passwords.SetClientPassword("kibana", "kibana456")

	cg := NewConfigGenerator(config, tempDir)
	err := cg.GenerateClientReadme(passwords)
	if err != nil {
		t.Fatalf("GenerateClientReadme() error = %v", err)
	}

	// Check that readme file was created
	readmePath := filepath.Join(tempDir, "client-certificates.readme")
	if _, err := os.Stat(readmePath); os.IsNotExist(err) {
		t.Error("Expected client readme file to be created")
		return
	}

	// Read and validate content
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read readme: %v", err)
	}

	content := string(data)

	// Should contain client information
	if !strings.Contains(content, "admin") {
		t.Error("Expected readme to contain 'admin'")
	}
	if !strings.Contains(content, "kibana") {
		t.Error("Expected readme to contain 'kibana'")
	}
	if !strings.Contains(content, "admin123") {
		t.Error("Expected readme to contain admin password")
	}
	if !strings.Contains(content, "kibana456") {
		t.Error("Expected readme to contain kibana password")
	}
}

func TestGenerateClientReadmeNoClients(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Clients: []ClientConfig{}, // No clients
	}

	passwords := cert.NewCertificatePasswords()

	cg := NewConfigGenerator(config, tempDir)
	err := cg.GenerateClientReadme(passwords)
	if err != nil {
		t.Fatalf("GenerateClientReadme() error = %v", err)
	}

	// Should not create readme file when no clients
	readmePath := filepath.Join(tempDir, "client-certificates.readme")
	if _, err := os.Stat(readmePath); !os.IsNotExist(err) {
		t.Error("Should not create client readme when no clients configured")
	}
}

func TestGenerateCAReadme(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CA: CAConfig{
			Root:         CertConfig{DN: "CN=root.ca.example.com,O=Test Org,C=US"},
			Intermediate: CertConfig{DN: "CN=signing.ca.example.com,O=Test Org,C=US"},
		},
	}

	passwords := cert.NewCertificatePasswords()
	passwords.RootCAPassword = "rootpass123"
	passwords.IntermediateCAPassword = "intpass456"

	cg := NewConfigGenerator(config, tempDir)
	err := cg.GenerateCAReadme(passwords)
	if err != nil {
		t.Fatalf("GenerateCAReadme() error = %v", err)
	}

	// Check that readme file was created
	readmePath := filepath.Join(tempDir, "root-ca.readme")
	if _, err := os.Stat(readmePath); os.IsNotExist(err) {
		t.Error("Expected CA readme file to be created")
		return
	}

	// Read and validate content
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read readme: %v", err)
	}

	content := string(data)

	// Should contain password information
	if !strings.Contains(content, "rootpass123") {
		t.Error("Expected readme to contain root CA password")
	}
	if !strings.Contains(content, "intpass456") {
		t.Error("Expected readme to contain intermediate CA password")
	}
}

func TestGenerateCAReadmeNoPasswords(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		CA: CAConfig{
			Root: CertConfig{DN: "CN=root.ca.example.com,O=Test Org,C=US"},
		},
	}

	passwords := cert.NewCertificatePasswords()
	// No passwords set

	cg := NewConfigGenerator(config, tempDir)
	err := cg.GenerateCAReadme(passwords)
	if err != nil {
		t.Fatalf("GenerateCAReadme() error = %v", err)
	}

	// Check that readme file was created
	readmePath := filepath.Join(tempDir, "root-ca.readme")
	if _, err := os.Stat(readmePath); os.IsNotExist(err) {
		t.Error("Expected CA readme file to be created")
		return
	}

	// Read and validate content
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read readme: %v", err)
	}

	content := string(data)

	// Should contain "none" for empty passwords
	if !strings.Contains(content, "none") {
		t.Error("Expected readme to contain 'none' for empty passwords")
	}
}

func TestWriteNodeConfigYAMLFormatting(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{}
	cg := NewConfigGenerator(config, tempDir)

	nodeConfig := OpenSearchNodeConfig{
		TransportPemCertPath:   "node1.pem",
		TransportPemKeyPath:    "node1.key",
		TransportPemTrustedCAs: "root-ca.pem",
		NodesDN:                []string{"CN=node1.example.com,O=Test Org,C=US"},
		AdminDN:                []string{"CN=admin,O=Test Org,C=US"},
	}

	err := cg.writeNodeConfig("node1", nodeConfig)
	if err != nil {
		t.Fatalf("writeNodeConfig() error = %v", err)
	}

	// Read the generated file
	configPath := filepath.Join(tempDir, "node1_opensearch_config_snippet.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	content := string(data)

	// Should start with comment header
	if !strings.HasPrefix(content, "#") {
		t.Error("Expected config to start with comment header")
	}

	// Should contain proper YAML with 2-space indentation
	yamlContent := extractYAMLFromContent(content)
	lines := strings.Split(yamlContent, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, " ") {
			// Check indentation is multiple of 2
			leadingSpaces := len(line) - len(strings.TrimLeft(line, " "))
			if leadingSpaces%2 != 0 {
				t.Errorf("Expected 2-space indentation, found %d spaces in line: %s", leadingSpaces, line)
			}
		}
	}
}

// Helper function to extract YAML content from file (skip comment header)
func extractYAMLFromContent(content string) string {
	lines := strings.Split(content, "\n")
	var yamlLines []string
	inYAML := false

	for _, line := range lines {
		if !inYAML && !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.TrimSpace(line) != "" {
			inYAML = true
		}
		if inYAML {
			yamlLines = append(yamlLines, line)
		}
	}

	return strings.Join(yamlLines, "\n")
}
