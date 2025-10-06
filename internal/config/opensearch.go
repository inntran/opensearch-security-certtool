package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/inntran/opensearch-security-certtool/internal/cert"
	"github.com/inntran/opensearch-security-certtool/internal/templates"
	"gopkg.in/yaml.v3"
)

// Configuration prefix that can be easily modified
const ConfigPrefix = "plugins.security"

// OpenSearchNodeConfig represents the OpenSearch Security configuration for a single node
type OpenSearchNodeConfig struct {
	// Transport layer SSL configuration
	TransportPemCertPath      string   `yaml:"plugins.security.ssl.transport.pemcert_filepath"`
	TransportPemKeyPath       string   `yaml:"plugins.security.ssl.transport.pemkey_filepath"`
	TransportPemKeyPassword   string   `yaml:"plugins.security.ssl.transport.pemkey_password,omitempty"`
	TransportPemTrustedCAs    string   `yaml:"plugins.security.ssl.transport.pemtrustedcas_filepath"`
	TransportEnforceHostnames bool     `yaml:"plugins.security.ssl.transport.enforce_hostname_verification"`
	TransportResolveHostnames bool     `yaml:"plugins.security.ssl.transport.resolve_hostname"`
	
	// HTTP layer SSL configuration
	HTTPEnabled            bool     `yaml:"plugins.security.ssl.http.enabled,omitempty"`
	HTTPPemCertPath        string   `yaml:"plugins.security.ssl.http.pemcert_filepath,omitempty"`
	HTTPPemKeyPath         string   `yaml:"plugins.security.ssl.http.pemkey_filepath,omitempty"`
	HTTPPemKeyPassword     string   `yaml:"plugins.security.ssl.http.pemkey_password,omitempty"`
	HTTPPemTrustedCAs      string   `yaml:"plugins.security.ssl.http.pemtrustedcas_filepath,omitempty"`
	
	// Node authentication
	NodesDN []string `yaml:"plugins.security.nodes_dn"`
	
	// Admin authentication
	AdminDN []string `yaml:"plugins.security.authcz.admin_dn"`
}

// ConfigGenerator handles OpenSearch configuration generation
type ConfigGenerator struct {
	config    *Config
	outputDir string
}

// NewConfigGenerator creates a new configuration generator
func NewConfigGenerator(config *Config, outputDir string) *ConfigGenerator {
	return &ConfigGenerator{
		config:    config,
		outputDir: outputDir,
	}
}

// GenerateNodeConfigs creates OpenSearch configuration snippets for all nodes
func (cg *ConfigGenerator) GenerateNodeConfigs(passwords *cert.CertificatePasswords) error {
	// Collect all node DNs
	var allNodeDNs []string
	for _, node := range cg.config.Nodes {
		allNodeDNs = append(allNodeDNs, node.DN)
	}
	
	// Add nodes from defaults if specified
	allNodeDNs = append(allNodeDNs, cg.config.Defaults.NodesDN...)
	
	// Collect admin client DNs
	var adminDNs []string
	for _, client := range cg.config.Clients {
		if client.Admin {
			adminDNs = append(adminDNs, client.DN)
		}
	}
	
	// Use root-ca.pem as trusted CA (matching Java tool behavior)
	caFile := "root-ca.pem"
	
	// Generate config for each node
	for _, node := range cg.config.Nodes {
		nodeConfig := cg.buildNodeConfig(node, allNodeDNs, adminDNs, caFile, passwords)
		
		if err := cg.writeNodeConfig(node.Name, nodeConfig); err != nil {
			return fmt.Errorf("failed to write config for node %s: %w", node.Name, err)
		}
	}
	
	return nil
}

// buildNodeConfig creates the configuration structure for a specific node
func (cg *ConfigGenerator) buildNodeConfig(
	node NodeConfig, allNodeDNs, adminDNs []string, caFile string, passwords *cert.CertificatePasswords,
) OpenSearchNodeConfig {
	nodeConfig := OpenSearchNodeConfig{
		// Transport layer (always enabled)
		TransportPemCertPath:      fmt.Sprintf("%s.pem", node.Name),
		TransportPemKeyPath:       fmt.Sprintf("%s.key", node.Name),
		TransportPemTrustedCAs:    caFile,
		TransportEnforceHostnames: cg.config.Defaults.VerifyHostnames,
		TransportResolveHostnames: cg.config.Defaults.ResolveHostnames,
		
		// Node and admin authentication
		NodesDN: allNodeDNs,
		AdminDN: adminDNs,
	}
	
	// Add transport key password if needed
	transportPassword := passwords.GetNodeTransportPassword(node.Name)
	if transportPassword != "" {
		nodeConfig.TransportPemKeyPassword = transportPassword
	}
	
	// HTTP layer configuration
	if cg.config.Defaults.HTTPSEnabled {
		nodeConfig.HTTPEnabled = true
		nodeConfig.HTTPPemTrustedCAs = caFile
		
		if cg.config.Defaults.ReuseTransportCertificates {
			// Reuse transport certificates for HTTP
			nodeConfig.HTTPPemCertPath = nodeConfig.TransportPemCertPath
			nodeConfig.HTTPPemKeyPath = nodeConfig.TransportPemKeyPath
			nodeConfig.HTTPPemKeyPassword = nodeConfig.TransportPemKeyPassword
		} else {
			// Use separate HTTP certificates
			nodeConfig.HTTPPemCertPath = fmt.Sprintf("%s_http.pem", node.Name)
			nodeConfig.HTTPPemKeyPath = fmt.Sprintf("%s_http.key", node.Name)
			
			// Add HTTP key password if needed
			httpPassword := passwords.GetNodeHTTPPassword(node.Name)
			if httpPassword != "" {
				nodeConfig.HTTPPemKeyPassword = httpPassword
			}
		}
	}
	
	return nodeConfig
}

// writeNodeConfig writes the configuration to a YAML file
func (cg *ConfigGenerator) writeNodeConfig(nodeName string, nodeConfig OpenSearchNodeConfig) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(cg.outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	
	// Generate YAML with 2-space indentation
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	err := encoder.Encode(nodeConfig)
	if closeErr := encoder.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}
	yamlData := buf.Bytes()
	
	// Create file with header comment
	filename := filepath.Join(cg.outputDir, nodeName+templates.ConfigFileExt)
	
	content := cg.buildConfigHeader(nodeName) + "\n\n" + string(yamlData) + "\n"
	
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// buildConfigHeader creates the header comment for the configuration file
func (cg *ConfigGenerator) buildConfigHeader(nodeName string) string {
	tmpl, err := template.New("nodeConfigHeader").Parse(templates.NodeConfigHeaderTemplate)
	if err != nil {
		// Fallback to simple format if template parsing fails
		return fmt.Sprintf("# Configuration snippet for node %s", nodeName)
	}
	
	var buf bytes.Buffer
	data := templates.NodeConfigHeaderData{NodeName: nodeName}
	err = tmpl.Execute(&buf, data)
	if err != nil {
		// Fallback to simple format if template execution fails
		return fmt.Sprintf("# Configuration snippet for node %s", nodeName)
	}
	
	return buf.String()
}

// GenerateClientReadme creates a README file explaining client certificate usage
// This matches the format from the Java Search Guard TLS Tool
func (cg *ConfigGenerator) GenerateClientReadme(passwords *cert.CertificatePasswords) error {
	if len(cg.config.Clients) == 0 {
		return nil
	}
	
	// Prepare template data
	var clientData []templates.ClientData
	for _, client := range cg.config.Clients {
		clientPassword := passwords.GetClientPassword(client.Name)
		if clientPassword != "" {
			clientData = append(clientData, templates.ClientData{
				DN:       client.DN,
				Password: clientPassword,
			})
		}
	}
	
	// Execute template
	tmpl, err := template.New("clientReadme").Parse(templates.ClientReadmeTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse client readme template: %w", err)
	}
	
	var buf bytes.Buffer
	data := templates.ClientReadmeData{Clients: clientData}
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return fmt.Errorf("failed to execute client readme template: %w", err)
	}
	
	filename := filepath.Join(cg.outputDir, templates.ClientReadmeFile)
	return os.WriteFile(filename, []byte(buf.String()+"\n"), 0644)
}

// GenerateCAReadme creates a README file explaining CA certificate usage and passwords
// This matches the format from the Java Search Guard TLS Tool
func (cg *ConfigGenerator) GenerateCAReadme(passwords *cert.CertificatePasswords) error {
	// Prepare template data
	rootPassword := passwords.RootCAPassword
	if rootPassword == "" {
		rootPassword = "none"
	}
	
	intermediatePassword := passwords.IntermediateCAPassword
	if intermediatePassword == "" {
		intermediatePassword = "none"
	}
	
	data := templates.CAReadmeData{
		RootPassword:         rootPassword,
		IntermediatePassword: intermediatePassword,
		HasIntermediate:      cg.config.CA.Intermediate.DN != "",
	}
	
	// Execute template
	tmpl, err := template.New("caReadme").Parse(templates.CAReadmeTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse CA readme template: %w", err)
	}
	
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return fmt.Errorf("failed to execute CA readme template: %w", err)
	}
	
	filename := filepath.Join(cg.outputDir, templates.CAReadmeFile)
	return os.WriteFile(filename, []byte(buf.String()), 0644)
}
