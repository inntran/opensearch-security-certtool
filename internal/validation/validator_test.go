package validation

import (
	"testing"

	"github.com/inntran/opensearch-security-certtool/internal/config"
)

func TestValidator_ValidateConfig(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		config         *config.Config
		expectValid    bool
		expectedErrors int
	}{
		{
			name: "valid_basic_config",
			config: &config.Config{
				CA: config.CAConfig{
					Root: config.CertConfig{
						DN:           "CN=test.example.com,O=Test Org,C=US",
						KeySize:      2048,
						ValidityDays: 365,
						PKPassword:   "auto",
					},
				},
				Defaults: config.DefaultConfig{
					ValidityDays:            365,
					GeneratedPasswordLength: 12,
				},
				Nodes: []config.NodeConfig{
					{
						Name: "node1",
						DN:   "CN=node1.example.com,O=Test Org,C=US",
					},
				},
			},
			expectValid:    true,
			expectedErrors: 0,
		},
		{
			name: "invalid_empty_ca_dn",
			config: &config.Config{
				CA: config.CAConfig{
					Root: config.CertConfig{
						DN: "",
					},
				},
				Nodes: []config.NodeConfig{
					{
						Name: "node1",
						DN:   "CN=node1.example.com,O=Test Org,C=US",
					},
				},
			},
			expectValid:    false,
			expectedErrors: 1,
		},
		{
			name: "invalid_weak_key_size",
			config: &config.Config{
				CA: config.CAConfig{
					Root: config.CertConfig{
						DN:      "CN=test.example.com,O=Test Org,C=US",
						KeySize: 1024, // Too weak
					},
				},
				Nodes: []config.NodeConfig{
					{
						Name: "node1",
						DN:   "CN=node1.example.com,O=Test Org,C=US",
					},
				},
			},
			expectValid:    false,
			expectedErrors: 1,
		},
		{
			name: "invalid_node_name_duplicate",
			config: &config.Config{
				CA: config.CAConfig{
					Root: config.CertConfig{
						DN: "CN=test.example.com,O=Test Org,C=US",
					},
				},
				Nodes: []config.NodeConfig{
					{
						Name: "node1",
						DN:   "CN=node1.example.com,O=Test Org,C=US",
					},
					{
						Name: "node1", // Duplicate name
						DN:   "CN=node2.example.com,O=Test Org,C=US",
					},
				},
			},
			expectValid:    false,
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateConfig(tt.config)

			if result.IsValid != tt.expectValid {
				t.Errorf("ValidateConfig() isValid = %v, want %v", result.IsValid, tt.expectValid)
			}

			if len(result.Errors) != tt.expectedErrors {
				t.Errorf("ValidateConfig() errors count = %d, want %d", len(result.Errors), tt.expectedErrors)
				for _, err := range result.Errors {
					t.Logf("Error: %s - %s", err.Field, err.Message)
				}
			}
		})
	}
}

func TestValidator_ValidateDNPattern(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "valid_wildcard_pattern",
			pattern: "CN=*.example.com,O=Test Org,C=US",
			wantErr: false,
		},
		{
			name:    "valid_regex_pattern",
			pattern: "/CN=.*\\.example\\.com,O=Test Org,C=US/",
			wantErr: false,
		},
		{
			name:    "invalid_empty_pattern",
			pattern: "",
			wantErr: true,
		},
		{
			name:    "invalid_regex_pattern",
			pattern: "/CN=*invalid_regex[,O=Test/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateDNPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDNPattern() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidator_ValidateNodeName(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		nodeName string
		wantErr  bool
	}{
		{
			name:     "valid_simple_name",
			nodeName: "node1",
			wantErr:  false,
		},
		{
			name:     "valid_name_with_dash",
			nodeName: "node-1",
			wantErr:  false,
		},
		{
			name:     "valid_name_with_underscore",
			nodeName: "node_1",
			wantErr:  false,
		},
		{
			name:     "invalid_empty_name",
			nodeName: "",
			wantErr:  true,
		},
		{
			name:     "invalid_name_with_space",
			nodeName: "node 1",
			wantErr:  true,
		},
		{
			name:     "invalid_name_with_dot",
			nodeName: "node.1",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateNodeName(tt.nodeName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateNodeName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}