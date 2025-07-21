package validation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inntran/opensearch-security-certtool/internal/config"
	"github.com/inntran/opensearch-security-certtool/internal/security"
)

// ValidationResult contains the result of configuration validation
type ValidationResult struct {
	IsValid  bool                `json:"is_valid"`
	Errors   []ValidationError   `json:"errors,omitempty"`
	Warnings []ValidationWarning `json:"warnings,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field    string      `json:"field"`
	Message  string      `json:"message"`
	Value    interface{} `json:"value,omitempty"`
	Severity string      `json:"severity"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field   string      `json:"field"`
	Message string      `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// Validator handles configuration validation
type Validator struct {
	securityConfig security.SecurityConfig
}

// NewValidator creates a new configuration validator
func NewValidator() *Validator {
	return &Validator{
		securityConfig: security.DefaultSecurityConfig(),
	}
}

// ValidateConfig performs comprehensive configuration validation
func (v *Validator) ValidateConfig(cfg *config.Config) ValidationResult {
	var validationErrors []ValidationError
	var warnings []ValidationWarning

	// Validate CA configuration
	if errs, warns := v.validateCAConfig(cfg.CA); len(errs) > 0 || len(warns) > 0 {
		validationErrors = append(validationErrors, errs...)
		warnings = append(warnings, warns...)
	}

	// Validate defaults
	if errs, warns := v.validateDefaults(cfg.Defaults); len(errs) > 0 || len(warns) > 0 {
		validationErrors = append(validationErrors, errs...)
		warnings = append(warnings, warns...)
	}

	// Validate nodes
	if errs, warns := v.validateNodes(cfg.Nodes); len(errs) > 0 || len(warns) > 0 {
		validationErrors = append(validationErrors, errs...)
		warnings = append(warnings, warns...)
	}

	// Validate clients
	if errs, warns := v.validateClients(cfg.Clients); len(errs) > 0 || len(warns) > 0 {
		validationErrors = append(validationErrors, errs...)
		warnings = append(warnings, warns...)
	}

	// Cross-validation
	if errs, warns := v.validateCrossReferences(cfg); len(errs) > 0 || len(warns) > 0 {
		validationErrors = append(validationErrors, errs...)
		warnings = append(warnings, warns...)
	}

	return ValidationResult{
		IsValid:  len(validationErrors) == 0,
		Errors:   validationErrors,
		Warnings: warnings,
	}
}

func (v *Validator) validateCAConfig(ca config.CAConfig) ([]ValidationError, []ValidationWarning) {
	var validationErrors []ValidationError
	var warnings []ValidationWarning

	// Validate root CA
	if errs, warns := v.validateCertConfig(ca.Root, "ca.root"); len(errs) > 0 || len(warns) > 0 {
		validationErrors = append(validationErrors, errs...)
		warnings = append(warnings, warns...)
	}

	// Validate intermediate CA if present
	if ca.Intermediate.DN != "" {
		if errs, warns := v.validateCertConfig(ca.Intermediate, "ca.intermediate"); len(errs) > 0 || len(warns) > 0 {
			validationErrors = append(validationErrors, errs...)
			warnings = append(warnings, warns...)
		}

		// Check that intermediate is different from root
		if ca.Root.DN == ca.Intermediate.DN {
			validationErrors = append(validationErrors, ValidationError{
				Field:    "ca.intermediate.dn",
				Message:  "Intermediate CA DN must be different from root CA DN",
				Value:    ca.Intermediate.DN,
				Severity: "error",
			})
		}
	}

	return validationErrors, warnings
}

func (v *Validator) validateCertConfig(cert config.CertConfig, fieldPrefix string) ([]ValidationError, []ValidationWarning) {
	var validationErrors []ValidationError
	var warnings []ValidationWarning

	// Validate DN
	if cert.DN == "" {
		validationErrors = append(validationErrors, ValidationError{
			Field:    fieldPrefix + ".dn",
			Message:  "DN is required",
			Severity: "error",
		})
	} else {
		if err := security.ValidateDN(cert.DN); err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".dn",
				Message:  fmt.Sprintf("Invalid DN: %s", err.Error()),
				Value:    cert.DN,
				Severity: "error",
			})
		}
	}

	// Validate key size
	if cert.KeySize != 0 {
		if err := security.ValidateKeySize(cert.KeySize); err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".keysize",
				Message:  err.Error(),
				Value:    cert.KeySize,
				Severity: "error",
			})
		} else if cert.KeySize < 4096 {
			warnings = append(warnings, ValidationWarning{
				Field:   fieldPrefix + ".keysize",
				Message: "Consider using 4096-bit keys for enhanced security",
				Value:   cert.KeySize,
			})
		}
	}

	// Validate validity period
	if cert.ValidityDays != 0 {
		if err := security.ValidateValidityPeriod(cert.ValidityDays); err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".validityDays",
				Message:  err.Error(),
				Value:    cert.ValidityDays,
				Severity: "error",
			})
		} else if cert.ValidityDays > 3650 {
			warnings = append(warnings, ValidationWarning{
				Field:   fieldPrefix + ".validityDays",
				Message: "Long validity periods may pose security risks",
				Value:   cert.ValidityDays,
			})
		}
	}

	// Validate password settings
	if cert.PKPassword != "" && cert.PKPassword != "auto" && cert.PKPassword != "none" {
		if len(cert.PKPassword) < v.securityConfig.MinPasswordLength {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".pkPassword",
				Message:  fmt.Sprintf("Password must be at least %d characters", v.securityConfig.MinPasswordLength),
				Severity: "error",
			})
		}
	}

	return validationErrors, warnings
}

func (v *Validator) validateDefaults(defaults config.DefaultConfig) ([]ValidationError, []ValidationWarning) {
	var validationErrors []ValidationError
	var warnings []ValidationWarning

	// Validate default validity period
	if defaults.ValidityDays != 0 {
		if err := security.ValidateValidityPeriod(defaults.ValidityDays); err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:    "defaults.validityDays",
				Message:  err.Error(),
				Value:    defaults.ValidityDays,
				Severity: "error",
			})
		}
	}

	// Validate password length
	if defaults.GeneratedPasswordLength != 0 && defaults.GeneratedPasswordLength < v.securityConfig.MinPasswordLength {
		validationErrors = append(validationErrors, ValidationError{
			Field:    "defaults.generatedPasswordLength",
			Message:  fmt.Sprintf("Generated password length must be at least %d", v.securityConfig.MinPasswordLength),
			Value:    defaults.GeneratedPasswordLength,
			Severity: "error",
		})
	}

	// Validate nodes DN patterns
	for i, dn := range defaults.NodesDN {
		if err := v.validateDNPattern(dn); err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fmt.Sprintf("defaults.nodesDn[%d]", i),
				Message:  err.Error(),
				Value:    dn,
				Severity: "error",
			})
		}
	}

	return validationErrors, warnings
}

func (v *Validator) validateNodes(nodes []config.NodeConfig) ([]ValidationError, []ValidationWarning) {
	var validationErrors []ValidationError
	var warnings []ValidationWarning
	nodeNames := make(map[string]bool)

	for i, node := range nodes {
		fieldPrefix := fmt.Sprintf("nodes[%d]", i)

		// Validate node name
		if node.Name == "" {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".name",
				Message:  "Node name is required",
				Severity: "error",
			})
		} else {
			// Check for duplicate node names
			if nodeNames[node.Name] {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fieldPrefix + ".name",
					Message:  fmt.Sprintf("Duplicate node name: %s", node.Name),
					Value:    node.Name,
					Severity: "error",
				})
			}
			nodeNames[node.Name] = true

			// Validate node name format
			if err := v.validateNodeName(node.Name); err != nil {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fieldPrefix + ".name",
					Message:  err.Error(),
					Value:    node.Name,
					Severity: "error",
				})
			}
		}

		// Validate DN
		if node.DN == "" {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".dn",
				Message:  "Node DN is required",
				Severity: "error",
			})
		} else {
			if err := security.ValidateDN(node.DN); err != nil {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fieldPrefix + ".dn",
					Message:  fmt.Sprintf("Invalid DN: %s", err.Error()),
					Value:    node.DN,
					Severity: "error",
				})
			}
		}

		// Validate DNS names
		dnsNames := node.GetDNSNames()
		for j, dns := range dnsNames {
			if err := security.ValidateDNSName(dns); err != nil {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fmt.Sprintf("%s.dns[%d]", fieldPrefix, j),
					Message:  err.Error(),
					Value:    dns,
					Severity: "error",
				})
			}
		}

		// Validate IP addresses
		ipAddresses := node.GetIPAddresses()
		for j, ip := range ipAddresses {
			if err := security.ValidateIPAddress(ip); err != nil {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fmt.Sprintf("%s.ip[%d]", fieldPrefix, j),
					Message:  err.Error(),
					Value:    ip,
					Severity: "error",
				})
			}
		}

		// Warn if no DNS names or IP addresses
		if len(dnsNames) == 0 && len(ipAddresses) == 0 {
			warnings = append(warnings, ValidationWarning{
				Field:   fieldPrefix,
				Message: "Node has no DNS names or IP addresses, which may cause connectivity issues",
			})
		}
	}

	return validationErrors, warnings
}

func (v *Validator) validateClients(clients []config.ClientConfig) ([]ValidationError, []ValidationWarning) {
	var validationErrors []ValidationError
	var warnings []ValidationWarning
	clientNames := make(map[string]bool)
	hasAdmin := false

	for i, client := range clients {
		fieldPrefix := fmt.Sprintf("clients[%d]", i)

		// Validate client name
		if client.Name == "" {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".name",
				Message:  "Client name is required",
				Severity: "error",
			})
		} else {
			// Check for duplicate client names
			if clientNames[client.Name] {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fieldPrefix + ".name",
					Message:  fmt.Sprintf("Duplicate client name: %s", client.Name),
					Value:    client.Name,
					Severity: "error",
				})
			}
			clientNames[client.Name] = true
		}

		// Validate DN
		if client.DN == "" {
			validationErrors = append(validationErrors, ValidationError{
				Field:    fieldPrefix + ".dn",
				Message:  "Client DN is required",
				Severity: "error",
			})
		} else {
			if err := security.ValidateDN(client.DN); err != nil {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fieldPrefix + ".dn",
					Message:  fmt.Sprintf("Invalid DN: %s", err.Error()),
					Value:    client.DN,
					Severity: "error",
				})
			}
		}

		// Track admin clients
		if client.Admin {
			hasAdmin = true
		}
	}

	// Warn if no admin client
	if len(clients) > 0 && !hasAdmin {
		warnings = append(warnings, ValidationWarning{
			Field:   "clients",
			Message: "No admin client configured, you may not be able to manage the cluster",
		})
	}

	return validationErrors, warnings
}

func (v *Validator) validateCrossReferences(cfg *config.Config) ([]ValidationError, []ValidationWarning) {
	var validationErrors []ValidationError
	var warnings []ValidationWarning

	// Check if we have at least one node or client
	if len(cfg.Nodes) == 0 && len(cfg.Clients) == 0 {
		validationErrors = append(validationErrors, ValidationError{
			Field:    "config",
			Message:  "Configuration must have at least one node or client",
			Severity: "error",
		})
	}

	// Check for DN conflicts between different entities
	allDNs := make(map[string]string)
	
	// Collect all DNs
	if cfg.CA.Root.DN != "" {
		allDNs[cfg.CA.Root.DN] = "ca.root"
	}
	if cfg.CA.Intermediate.DN != "" {
		allDNs[cfg.CA.Intermediate.DN] = "ca.intermediate"
	}
	
	for i, node := range cfg.Nodes {
		if node.DN != "" {
			if existing, exists := allDNs[node.DN]; exists {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fmt.Sprintf("nodes[%d].dn", i),
					Message:  fmt.Sprintf("DN conflicts with %s", existing),
					Value:    node.DN,
					Severity: "error",
				})
			} else {
				allDNs[node.DN] = fmt.Sprintf("nodes[%d]", i)
			}
		}
	}
	
	for i, client := range cfg.Clients {
		if client.DN != "" {
			if existing, exists := allDNs[client.DN]; exists {
				validationErrors = append(validationErrors, ValidationError{
					Field:    fmt.Sprintf("clients[%d].dn", i),
					Message:  fmt.Sprintf("DN conflicts with %s", existing),
					Value:    client.DN,
					Severity: "error",
				})
			} else {
				allDNs[client.DN] = fmt.Sprintf("clients[%d]", i)
			}
		}
	}

	return validationErrors, warnings
}

// Helper functions

func (v *Validator) validateDNPattern(pattern string) error {
	// Basic validation for DN patterns (supports wildcards)
	if pattern == "" {
		return fmt.Errorf("DN pattern cannot be empty")
	}
	
	// Check if it's a regex pattern
	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		// Validate regex
		_, err := regexp.Compile(pattern[1 : len(pattern)-1])
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	} else {
		// Validate as DN with wildcards
		dnWithoutWildcards := strings.ReplaceAll(pattern, "*", "example")
		if err := security.ValidateDN(dnWithoutWildcards); err != nil {
			return fmt.Errorf("invalid DN pattern: %w", err)
		}
	}
	
	return nil
}

func (v *Validator) validateNodeName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("node name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("node name too long (max 64 characters)")
	}
	
	// Check for valid characters (alphanumeric, dash, underscore)
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') || 
			(char >= 'A' && char <= 'Z') || 
			(char >= '0' && char <= '9') || 
			char == '-' || char == '_') {
			return fmt.Errorf("node name contains invalid character: %c", char)
		}
	}
	
	return nil
}
