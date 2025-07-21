package cert

import (
	"crypto/rand"
	"fmt"
)

// PasswordManager handles password generation and storage
type PasswordManager struct {
	length int
}

// NewPasswordManager creates a new password manager
func NewPasswordManager(length int) *PasswordManager {
	if length < 12 {
		length = 12 // Minimum secure length
	}
	return &PasswordManager{
		length: length,
	}
}

// GeneratePassword creates a cryptographically secure random password
func (pm *PasswordManager) GeneratePassword() (string, error) {
	// Character set similar to original Java tool (letters and digits)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	password := make([]byte, pm.length)
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

// CertificatePasswords holds passwords for certificates
type CertificatePasswords struct {
	RootCAPassword         string
	IntermediateCAPassword string
	NodePasswords          map[string]NodePasswordInfo // node name -> passwords
	ClientPasswords        map[string]string           // client name -> password
}

// NodePasswordInfo holds both transport and HTTP passwords for a node
type NodePasswordInfo struct {
	TransportPassword string
	HTTPPassword      string
}

// NewCertificatePasswords creates a new password collection
func NewCertificatePasswords() *CertificatePasswords {
	return &CertificatePasswords{
		NodePasswords:   make(map[string]NodePasswordInfo),
		ClientPasswords: make(map[string]string),
	}
}

// SetNodePasswords sets both transport and HTTP passwords for a node
func (cp *CertificatePasswords) SetNodePasswords(nodeName, transportPassword, httpPassword string) {
	cp.NodePasswords[nodeName] = NodePasswordInfo{
		TransportPassword: transportPassword,
		HTTPPassword:      httpPassword,
	}
}

// SetClientPassword sets the password for a client certificate
func (cp *CertificatePasswords) SetClientPassword(clientName, password string) {
	cp.ClientPasswords[clientName] = password
}

// GetNodeTransportPassword returns the transport password for a node
func (cp *CertificatePasswords) GetNodeTransportPassword(nodeName string) string {
	if info, exists := cp.NodePasswords[nodeName]; exists {
		return info.TransportPassword
	}
	return ""
}

// GetNodeHTTPPassword returns the HTTP password for a node
func (cp *CertificatePasswords) GetNodeHTTPPassword(nodeName string) string {
	if info, exists := cp.NodePasswords[nodeName]; exists {
		return info.HTTPPassword
	}
	return ""
}

// GetClientPassword returns the password for a client certificate
func (cp *CertificatePasswords) GetClientPassword(clientName string) string {
	return cp.ClientPasswords[clientName]
}
