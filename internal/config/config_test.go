package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Test configuration content
	validConfigYAML := `
ca:
  root:
    dn: CN=root.ca.example.com,OU=CA,O=Example Com\, Inc.,DC=example,DC=com
    keysize: 2048
    validityDays: 3650
    pkPassword: auto
    file: root-ca

  intermediate:
    dn: CN=signing.ca.example.com,OU=CA,O=Example Com\, Inc.,DC=example,DC=com
    keysize: 2048
    validityDays: 3650
    pkPassword: auto

defaults:
  validityDays: 365
  pkPassword: auto
  generatedPasswordLength: 16
  httpsEnabled: true
  reuseTransportCertificatesForHttp: false
  verifyHostnames: true
  resolveHostnames: false
  nodesDn: 
    - "CN=*.example.com,O=Example Com\\, Inc.,DC=example,DC=com"
  nodeOid: "1.2.3.4.5.5"

nodes:
  - name: node1
    dn: CN=node1.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    dns: 
      - node1.example.com
      - localhost
    ip: 
      - 127.0.0.1
      - 10.0.2.1

  - name: node2
    dn: CN=node2.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    dns: node2.example.com
    ip: 10.0.2.2

clients:
  - name: admin
    dn: CN=admin.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    admin: true

  - name: kibana
    dn: CN=kibana.example.com,OU=Ops,O=Example Com\, Inc.,DC=example,DC=com
    admin: false
`

	invalidYAML := `
ca:
  root:
    dn: 
invalid yaml structure
`

	tests := []struct {
		name      string
		content   string
		expectErr bool
		checkFunc func(*testing.T, *Config)
	}{
		{
			name:      "valid_config",
			content:   validConfigYAML,
			expectErr: false,
			checkFunc: func(t *testing.T, config *Config) {
				// Test CA configuration
				if config.CA.Root.DN != "CN=root.ca.example.com,OU=CA,O=Example Com\\, Inc.,DC=example,DC=com" {
					t.Errorf("Unexpected root CA DN: %s", config.CA.Root.DN)
				}
				if config.CA.Root.KeySize != 2048 {
					t.Errorf("Expected root CA key size 2048, got %d", config.CA.Root.KeySize)
				}
				if config.CA.Root.ValidityDays != 3650 {
					t.Errorf("Expected root CA validity 3650, got %d", config.CA.Root.ValidityDays)
				}

				// Test defaults
				if config.Defaults.ValidityDays != 365 {
					t.Errorf("Expected default validity 365, got %d", config.Defaults.ValidityDays)
				}
				if config.Defaults.GeneratedPasswordLength != 16 {
					t.Errorf("Expected password length 16, got %d", config.Defaults.GeneratedPasswordLength)
				}
				if !config.Defaults.HTTPSEnabled {
					t.Error("Expected HTTPS to be enabled")
				}

				// Test nodes
				if len(config.Nodes) != 2 {
					t.Errorf("Expected 2 nodes, got %d", len(config.Nodes))
				}

				// Test node1 with multiple DNS and IP addresses
				node1 := config.Nodes[0]
				if node1.Name != "node1" {
					t.Errorf("Expected node1 name, got %s", node1.Name)
				}
				dnsNames := node1.GetDNSNames()
				expectedDNS := []string{"node1.example.com", "localhost"}
				if !reflect.DeepEqual(dnsNames, expectedDNS) {
					t.Errorf("Expected DNS names %v, got %v", expectedDNS, dnsNames)
				}
				ipAddrs := node1.GetIPAddresses()
				expectedIPs := []string{"127.0.0.1", "10.0.2.1"}
				if !reflect.DeepEqual(ipAddrs, expectedIPs) {
					t.Errorf("Expected IP addresses %v, got %v", expectedIPs, ipAddrs)
				}

				// Test node2 with single DNS and IP
				node2 := config.Nodes[1]
				if node2.Name != "node2" {
					t.Errorf("Expected node2 name, got %s", node2.Name)
				}
				dnsNames2 := node2.GetDNSNames()
				expectedDNS2 := []string{"node2.example.com"}
				if !reflect.DeepEqual(dnsNames2, expectedDNS2) {
					t.Errorf("Expected DNS names %v, got %v", expectedDNS2, dnsNames2)
				}

				// Test clients
				if len(config.Clients) != 2 {
					t.Errorf("Expected 2 clients, got %d", len(config.Clients))
				}
				if config.Clients[0].Name != "admin" {
					t.Errorf("Expected admin client, got %s", config.Clients[0].Name)
				}
				if !config.Clients[0].Admin {
					t.Error("Expected admin client to be marked as admin")
				}
				if config.Clients[1].Admin {
					t.Error("Expected kibana client to not be admin")
				}
			},
		},
		{
			name:      "invalid_yaml",
			content:   invalidYAML,
			expectErr: true,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test config file
			configFile := filepath.Join(tempDir, tt.name+".yml")
			err := os.WriteFile(configFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write test config file: %v", err)
			}

			// Load config
			config, err := LoadConfig(configFile)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, config)
			}
		})
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yml")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	config := &Config{
		CA: CAConfig{
			Root: CertConfig{
				DN: "CN=test.example.com,O=Test Org,C=US",
			},
			Intermediate: CertConfig{
				DN: "CN=int.example.com,O=Test Org,C=US",
			},
		},
		Defaults: DefaultConfig{},
		Nodes: []NodeConfig{
			{Name: "node1", DN: "CN=node1.example.com,O=Test Org,C=US"},
		},
	}

	config.applyDefaults()

	// Check defaults were applied
	if config.Defaults.ValidityDays != 3650 {
		t.Errorf("Expected default validity 3650, got %d", config.Defaults.ValidityDays)
	}
	if config.Defaults.GeneratedPasswordLength != 12 {
		t.Errorf("Expected default password length 12, got %d", config.Defaults.GeneratedPasswordLength)
	}
	if config.CA.Root.KeySize != 2048 {
		t.Errorf("Expected default key size 2048, got %d", config.CA.Root.KeySize)
	}
	if config.CA.Intermediate.KeySize != 2048 {
		t.Errorf("Expected default key size 2048, got %d", config.CA.Intermediate.KeySize)
	}

	// Check CA validity defaults
	if config.CA.Root.ValidityDays != 3650 {
		t.Errorf("Expected root CA validity 3650, got %d", config.CA.Root.ValidityDays)
	}
	if config.CA.Intermediate.ValidityDays != 3650 {
		t.Errorf("Expected intermediate CA validity 3650, got %d", config.CA.Intermediate.ValidityDays)
	}
}

func TestConfigApplyDefaultsPreservesExisting(t *testing.T) {
	config := &Config{
		CA: CAConfig{
			Root: CertConfig{
				DN:           "CN=test.example.com,O=Test Org,C=US",
				KeySize:      4096,
				ValidityDays: 1825,
				PKPassword:   "mypassword",
			},
		},
		Defaults: DefaultConfig{
			ValidityDays:            1000,
			GeneratedPasswordLength: 20,
			PKPassword:              "defaultpass",
		},
		Nodes: []NodeConfig{
			{Name: "node1", DN: "CN=node1.example.com,O=Test Org,C=US"},
		},
	}

	config.applyDefaults()

	// Check existing values were preserved
	if config.CA.Root.KeySize != 4096 {
		t.Errorf("Expected existing key size 4096, got %d", config.CA.Root.KeySize)
	}
	if config.CA.Root.ValidityDays != 1825 {
		t.Errorf("Expected existing validity 1825, got %d", config.CA.Root.ValidityDays)
	}
	if config.CA.Root.PKPassword != "mypassword" {
		t.Errorf("Expected existing password 'mypassword', got %s", config.CA.Root.PKPassword)
	}
	if config.Defaults.ValidityDays != 1000 {
		t.Errorf("Expected existing default validity 1000, got %d", config.Defaults.ValidityDays)
	}
	if config.Defaults.GeneratedPasswordLength != 20 {
		t.Errorf("Expected existing password length 20, got %d", config.Defaults.GeneratedPasswordLength)
	}
}

func TestNodeConfigGetDNSNames(t *testing.T) {
	tests := []struct {
		name     string
		dns      interface{}
		expected []string
	}{
		{
			name:     "string_single",
			dns:      "example.com",
			expected: []string{"example.com"},
		},
		{
			name:     "string_empty",
			dns:      "",
			expected: nil,
		},
		{
			name:     "slice_interface",
			dns:      []interface{}{"example.com", "test.com"},
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "slice_interface_with_empty",
			dns:      []interface{}{"example.com", "", "test.com"},
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "slice_string",
			dns:      []string{"example.com", "test.com"},
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "slice_string_with_empty",
			dns:      []string{"example.com", "", "test.com"},
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "nil_value",
			dns:      nil,
			expected: nil,
		},
		{
			name:     "invalid_type",
			dns:      123,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := NodeConfig{DNS: tt.dns}
			result := node.GetDNSNames()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestNodeConfigGetIPAddresses(t *testing.T) {
	tests := []struct {
		name     string
		ip       interface{}
		expected []string
	}{
		{
			name:     "string_single",
			ip:       "127.0.0.1",
			expected: []string{"127.0.0.1"},
		},
		{
			name:     "string_empty",
			ip:       "",
			expected: nil,
		},
		{
			name:     "slice_interface",
			ip:       []interface{}{"127.0.0.1", "10.0.0.1"},
			expected: []string{"127.0.0.1", "10.0.0.1"},
		},
		{
			name:     "slice_interface_with_empty",
			ip:       []interface{}{"127.0.0.1", "", "10.0.0.1"},
			expected: []string{"127.0.0.1", "10.0.0.1"},
		},
		{
			name:     "slice_string",
			ip:       []string{"127.0.0.1", "10.0.0.1"},
			expected: []string{"127.0.0.1", "10.0.0.1"},
		},
		{
			name:     "nil_value",
			ip:       nil,
			expected: nil,
		},
		{
			name:     "invalid_type",
			ip:       123,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := NodeConfig{IP: tt.ip}
			result := node.GetIPAddresses()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_config",
			config: &Config{
				CA: CAConfig{
					Root: CertConfig{
						DN: "CN=test.example.com,O=Test Org,C=US",
					},
				},
				Nodes: []NodeConfig{
					{Name: "node1", DN: "CN=node1.example.com,O=Test Org,C=US"},
				},
			},
			expectErr: false,
		},
		{
			name: "empty_root_ca_dn",
			config: &Config{
				CA: CAConfig{
					Root: CertConfig{
						DN: "",
					},
				},
				Nodes: []NodeConfig{
					{Name: "node1", DN: "CN=node1.example.com,O=Test Org,C=US"},
				},
			},
			expectErr: true,
			errMsg:    "root CA DN is required",
		},
		{
			name: "no_nodes_or_clients",
			config: &Config{
				CA: CAConfig{
					Root: CertConfig{
						DN: "CN=test.example.com,O=Test Org,C=US",
					},
				},
				Nodes:   []NodeConfig{},
				Clients: []ClientConfig{},
			},
			expectErr: true,
			errMsg:    "at least one node or client must be configured",
		},
		{
			name: "node_without_name",
			config: &Config{
				CA: CAConfig{
					Root: CertConfig{
						DN: "CN=test.example.com,O=Test Org,C=US",
					},
				},
				Nodes: []NodeConfig{
					{Name: "", DN: "CN=node1.example.com,O=Test Org,C=US"},
				},
			},
			expectErr: true,
			errMsg:    "name is required",
		},
		{
			name: "node_without_dn",
			config: &Config{
				CA: CAConfig{
					Root: CertConfig{
						DN: "CN=test.example.com,O=Test Org,C=US",
					},
				},
				Nodes: []NodeConfig{
					{Name: "node1", DN: ""},
				},
			},
			expectErr: true,
			errMsg:    "DN is required",
		},
		{
			name: "client_without_name",
			config: &Config{
				CA: CAConfig{
					Root: CertConfig{
						DN: "CN=test.example.com,O=Test Org,C=US",
					},
				},
				Clients: []ClientConfig{
					{Name: "", DN: "CN=client1.example.com,O=Test Org,C=US"},
				},
			},
			expectErr: true,
			errMsg:    "name is required",
		},
		{
			name: "client_without_dn",
			config: &Config{
				CA: CAConfig{
					Root: CertConfig{
						DN: "CN=test.example.com,O=Test Org,C=US",
					},
				},
				Clients: []ClientConfig{
					{Name: "client1", DN: ""},
				},
			},
			expectErr: true,
			errMsg:    "DN is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
