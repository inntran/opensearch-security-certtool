package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	MinKeySize     = 2048
	MaxKeySize     = 8192
	DefaultKeySize = 2048
	MaxValidityDays = 7300 // ~20 years
)

// SecurityConfig defines security constraints for certificate generation
type SecurityConfig struct {
	MinKeySize          int
	MaxKeySize          int
	MaxValidityDays     int
	RequiredKeyUsage    []x509.KeyUsage
	RequiredExtKeyUsage []x509.ExtKeyUsage
	AllowedDNComponents []string
	MinPasswordLength   int
}

// DefaultSecurityConfig returns secure default configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		MinKeySize:      MinKeySize,
		MaxKeySize:      MaxKeySize,
		MaxValidityDays: MaxValidityDays,
		RequiredKeyUsage: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageKeyEncipherment,
		},
		RequiredExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		AllowedDNComponents: []string{
			"CN", "O", "OU", "C", "L", "ST", "STREET", "POSTALCODE", "DC",
		},
		MinPasswordLength: 12,
	}
}

// ValidateKeySize ensures key size meets security requirements
func ValidateKeySize(keySize int) error {
	config := DefaultSecurityConfig()
	if keySize < config.MinKeySize {
		return fmt.Errorf("key size %d is below minimum %d", keySize, config.MinKeySize)
	}
	if keySize > config.MaxKeySize {
		return fmt.Errorf("key size %d exceeds maximum %d", keySize, config.MaxKeySize)
	}
	// Ensure key size is a power of 2 for RSA
	if keySize&(keySize-1) != 0 {
		return fmt.Errorf("key size %d must be a power of 2", keySize)
	}
	return nil
}

// ValidateValidityPeriod ensures certificate validity period is reasonable
func ValidateValidityPeriod(days int) error {
	config := DefaultSecurityConfig()
	if days <= 0 {
		return fmt.Errorf("validity period must be positive, got %d", days)
	}
	if days > config.MaxValidityDays {
		return fmt.Errorf("validity period %d days exceeds maximum %d days", days, config.MaxValidityDays)
	}
	return nil
}

// ValidateDN performs comprehensive DN validation
func ValidateDN(dn string) error {
	if dn == "" {
		return fmt.Errorf("DN cannot be empty")
	}

	// Check for required CN
	if !strings.Contains(dn, "CN=") {
		return fmt.Errorf("DN must contain Common Name (CN)")
	}

	// Parse DN components
	components := parseDNComponents(dn)
	config := DefaultSecurityConfig()

	for component, value := range components {
		// Check if component is allowed
		allowed := false
		for _, allowedComp := range config.AllowedDNComponents {
			if component == allowedComp {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("DN component %s is not allowed", component)
		}

		// Validate component value
		if err := validateDNComponentValue(component, value); err != nil {
			return fmt.Errorf("invalid %s value: %w", component, err)
		}
	}

	return nil
}

// ValidateIPAddress validates IP address format
func ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// ValidateDNSName validates DNS name format
func ValidateDNSName(name string) error {
	if name == "" {
		return fmt.Errorf("DNS name cannot be empty")
	}

	// Basic DNS name validation
	if len(name) > 253 {
		return fmt.Errorf("DNS name too long: %s", name)
	}

	// Check for valid characters and format
	dnsRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	if !dnsRegex.MatchString(name) {
		return fmt.Errorf("invalid DNS name format: %s", name)
	}

	return nil
}

// SecureCompare performs constant-time comparison for sensitive data
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GenerateSecurePassword generates a cryptographically secure password
func GenerateSecurePassword(length int) (string, error) {
	if length < DefaultSecurityConfig().MinPasswordLength {
		return "", fmt.Errorf("password length %d is below minimum %d", length, DefaultSecurityConfig().MinPasswordLength)
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)
	charsetLen := len(charset)

	for i := range password {
		// Generate cryptographically secure random index
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		password[i] = charset[int(randomBytes[0])%charsetLen]
	}

	return string(password), nil
}

// ValidateCertificate performs comprehensive certificate validation
func ValidateCertificate(cert *x509.Certificate) error {
	now := time.Now()

	// Check certificate validity period
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (valid from %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (expired on %s)", cert.NotAfter)
	}

	// Check key usage
	config := DefaultSecurityConfig()
	for _, requiredUsage := range config.RequiredKeyUsage {
		if cert.KeyUsage&requiredUsage == 0 {
			return fmt.Errorf("certificate missing required key usage: %s", keyUsageToString(requiredUsage))
		}
	}

	// Check public key strength
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := ValidateKeySize(pub.N.BitLen()); err != nil {
			return fmt.Errorf("certificate has weak RSA key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}

	return nil
}

// Helper functions

func parseDNComponents(dn string) map[string]string {
	components := make(map[string]string)
	
	// Handle escaped commas
	placeholder := "##ESCAPED_COMMA##"
	dn = strings.ReplaceAll(dn, "\\,", placeholder)
	
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(strings.ToUpper(kv[0]))
			value := strings.TrimSpace(kv[1])
			value = strings.ReplaceAll(value, placeholder, ",")
			components[key] = value
		}
	}
	
	return components
}

func validateDNComponentValue(component, value string) error {
	if value == "" {
		return fmt.Errorf("component value cannot be empty")
	}

	switch component {
	case "C":
		// Country code should be 2 characters
		if len(value) != 2 {
			return fmt.Errorf("country code must be 2 characters, got %s", value)
		}
	case "CN":
		// Common name validation
		if len(value) > 64 {
			return fmt.Errorf("common name too long (max 64 characters)")
		}
	case "O", "OU":
		// Organization validation
		if len(value) > 64 {
			return fmt.Errorf("organization name too long (max 64 characters)")
		}
	}

	// Check for invalid characters (basic validation)
	invalidChars := []string{"\n", "\r", "\x00"}
	for _, char := range invalidChars {
		if strings.Contains(value, char) {
			return fmt.Errorf("contains invalid character")
		}
	}

	return nil
}

func keyUsageToString(usage x509.KeyUsage) string {
	switch usage {
	case x509.KeyUsageDigitalSignature:
		return "DigitalSignature"
	case x509.KeyUsageKeyEncipherment:
		return "KeyEncipherment"
	case x509.KeyUsageCertSign:
		return "CertSign"
	default:
		return fmt.Sprintf("Unknown(%d)", usage)
	}
}
