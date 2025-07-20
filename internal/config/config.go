package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	CA       CAConfig      `yaml:"ca"`
	Defaults DefaultConfig `yaml:"defaults"`
	Nodes    []NodeConfig  `yaml:"nodes"`
	Clients  []ClientConfig `yaml:"clients"`
}

// CAConfig represents certificate authority configuration
type CAConfig struct {
	Root         CertConfig `yaml:"root"`
	Intermediate CertConfig `yaml:"intermediate"`
}

// CertConfig represents certificate configuration
type CertConfig struct {
	DN                     string   `yaml:"dn"`
	KeySize                int      `yaml:"keysize"`
	ValidityDays           int      `yaml:"validityDays"`
	PKPassword             string   `yaml:"pkPassword"`
	File                   string   `yaml:"file"`
	CRLDistributionPoints  string   `yaml:"crlDistributionPoints"`
}

// DefaultConfig represents default values
type DefaultConfig struct {
	ValidityDays               int      `yaml:"validityDays"`
	PKPassword                 string   `yaml:"pkPassword"`
	NodesDN                    []string `yaml:"nodesDn"`
	NodeOID                    string   `yaml:"nodeOid"`
	GeneratedPasswordLength    int      `yaml:"generatedPasswordLength"`
	HTTPSEnabled               bool     `yaml:"httpsEnabled"`
	ReuseTransportCertificates bool     `yaml:"reuseTransportCertificatesForHttp"`
	VerifyHostnames            bool     `yaml:"verifyHostnames"`
	ResolveHostnames           bool     `yaml:"resolveHostnames"`
}

// NodeConfig represents node certificate configuration
type NodeConfig struct {
	Name string      `yaml:"name"`
	DN   string      `yaml:"dn"`
	DNS  interface{} `yaml:"dns"` // Can be string or []string
	IP   interface{} `yaml:"ip"`  // Can be string or []string
}

// ClientConfig represents client certificate configuration
type ClientConfig struct {
	Name  string `yaml:"name"`
	DN    string `yaml:"dn"`
	Admin bool   `yaml:"admin"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults
	config.applyDefaults()

	return &config, nil
}

// applyDefaults sets default values where not specified
func (c *Config) applyDefaults() {
	// Default validity period
	if c.Defaults.ValidityDays == 0 {
		c.Defaults.ValidityDays = 3650
	}
	
	// Default password length
	if c.Defaults.GeneratedPasswordLength == 0 {
		c.Defaults.GeneratedPasswordLength = 12
	}

	// Default key size
	if c.CA.Root.KeySize == 0 {
		c.CA.Root.KeySize = 2048
	}
	if c.CA.Intermediate.KeySize == 0 {
		c.CA.Intermediate.KeySize = 2048
	}

	// Apply defaults to CA certificates
	if c.CA.Root.ValidityDays == 0 {
		c.CA.Root.ValidityDays = c.Defaults.ValidityDays
	}
	if c.CA.Intermediate.ValidityDays == 0 {
		c.CA.Intermediate.ValidityDays = c.Defaults.ValidityDays
	}
	if c.CA.Root.PKPassword == "" {
		c.CA.Root.PKPassword = c.Defaults.PKPassword
	}
	if c.CA.Intermediate.PKPassword == "" {
		c.CA.Intermediate.PKPassword = c.Defaults.PKPassword
	}
}

// GetDNSNames returns DNS names as a slice
func (n *NodeConfig) GetDNSNames() []string {
	switch dns := n.DNS.(type) {
	case string:
		if dns == "" {
			return nil
		}
		return []string{dns}
	case []interface{}:
		var result []string
		for _, v := range dns {
			if s, ok := v.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	case []string:
		var result []string
		for _, s := range dns {
			if s != "" {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// GetIPAddresses returns IP addresses as a slice
func (n *NodeConfig) GetIPAddresses() []string {
	switch ip := n.IP.(type) {
	case string:
		if ip == "" {
			return nil
		}
		return []string{ip}
	case []interface{}:
		var result []string
		for _, v := range ip {
			if s, ok := v.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	case []string:
		var result []string
		for _, s := range ip {
			if s != "" {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// Validate performs basic configuration validation
func (c *Config) Validate() error {
	if c.CA.Root.DN == "" {
		return fmt.Errorf("root CA DN is required")
	}

	if len(c.Nodes) == 0 && len(c.Clients) == 0 {
		return fmt.Errorf("at least one node or client must be configured")
	}

	// Basic validation - for comprehensive validation use validation.Validator
	for i, node := range c.Nodes {
		if node.Name == "" {
			return fmt.Errorf("node %d: name is required", i)
		}
		if node.DN == "" {
			return fmt.Errorf("node %s: DN is required", node.Name)
		}
	}

	for i, client := range c.Clients {
		if client.Name == "" {
			return fmt.Errorf("client %d: name is required", i)
		}
		if client.DN == "" {
			return fmt.Errorf("client %s: DN is required", client.Name)
		}
	}

	return nil
}
