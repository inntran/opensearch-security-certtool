package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/inntran/opensearch-security-certtool/internal/logger"
)

// CertificateManager handles certificate operations
type CertificateManager struct {
	outputDir         string
	passwordManager   *PasswordManager
	passwords         *CertificatePasswords
	logger            *logger.Logger
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(outputDir string, passwordLength int, log *logger.Logger) *CertificateManager {
	return &CertificateManager{
		outputDir:       outputDir,
		passwordManager: NewPasswordManager(passwordLength),
		passwords:       NewCertificatePasswords(),
		logger:          log,
	}
}

// CAInfo holds CA certificate and private key information
type CAInfo struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
	Password    string
}

// GenerateCA creates a new certificate authority
func (cm *CertificateManager) GenerateCA(dn string, keySize int, validityDays int, filename string, passwordSetting string) (*CAInfo, error) {
	return cm.GenerateCAWithConfig(dn, keySize, validityDays, filename, passwordSetting, "")
}

// GenerateCAWithConfig creates a new certificate authority with CRL distribution points
func (cm *CertificateManager) GenerateCAWithConfig(dn string, keySize int, validityDays int, filename string, passwordSetting string, crlDistributionPoints string) (*CAInfo, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse distinguished name
	subject, err := parseDistinguishedName(dn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DN: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
		BasicConstraintsValid: true,
	}

	// Add CRL distribution points if specified
	if crlDistributionPoints != "" {
		template.CRLDistributionPoints = []string{crlDistributionPoints}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	// Handle password
	var password string
	if passwordSetting == "auto" {
		var err error
		password, err = cm.passwordManager.GeneratePassword()
		if err != nil {
			return nil, fmt.Errorf("failed to generate password: %w", err)
		}
		cm.logger.LogPasswordGeneration(filename + " CA")
	} else if passwordSetting != "none" && passwordSetting != "" {
		password = passwordSetting
	}

	// Encrypt private key if password is provided
	if password != "" {
		encryptedKeyPEM, err := cm.encryptPrivateKey(keyDER, password)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		keyPEM = encryptedKeyPEM
	}

	caInfo := &CAInfo{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Password:    password,
	}

	// Store password for CA
	if filename == "root-ca" {
		cm.passwords.RootCAPassword = password
	} else if filename == "signing-ca" {
		cm.passwords.IntermediateCAPassword = password
	}

	// Save to files
	if err := cm.saveCertificateAndKey(filename, certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("failed to save CA files: %w", err)
	}

	// Log certificate creation
	certPath := filepath.Join(cm.outputDir, filename+".pem")
	cm.logger.LogCertificateAction("created", filename+" CA", certPath)

	return caInfo, nil
}

// GenerateNodeCertificate creates a node certificate signed by the CA
func (cm *CertificateManager) GenerateNodeCertificate(ca *CAInfo, dn string, dnsNames []string, ipAddresses []string, validityDays int, filename string, passwordSetting string) error {
	return cm.GenerateNodeCertificateWithOID(ca, dn, dnsNames, ipAddresses, validityDays, filename, passwordSetting, "")
}

// GenerateNodeCertificateWithOID creates a node certificate with optional node OID
func (cm *CertificateManager) GenerateNodeCertificateWithOID(ca *CAInfo, dn string, dnsNames []string, ipAddresses []string, validityDays int, filename string, passwordSetting string, nodeOID string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse distinguished name
	subject, err := parseDistinguishedName(dn)
	if err != nil {
		return fmt.Errorf("failed to parse DN: %w", err)
	}

	// Parse IP addresses
	var ips []net.IP
	for _, ipStr := range ipAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}

	// Add node OID extension if specified
	if nodeOID != "" {
		if oid, err := parseOID(nodeOID); err == nil {
			// Add the node OID as a custom extension
			template.ExtraExtensions = []pkix.Extension{
				{
					Id:    oid,
					Value: []byte("node"),
				},
			}
		}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, &privateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Handle password
	var password string
	if passwordSetting == "auto" {
		var err error
		password, err = cm.passwordManager.GeneratePassword()
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
	} else if passwordSetting != "none" && passwordSetting != "" {
		password = passwordSetting
	}

	// Encrypt private key if password is provided
	var keyPEM []byte
	if password != "" {
		encryptedKeyPEM, err := cm.encryptPrivateKey(keyDER, password)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
		keyPEM = encryptedKeyPEM
	} else {
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})
	}

	// Store password for node
	if strings.HasSuffix(filename, "_http") {
		nodeName := strings.TrimSuffix(filename, "_http")
		if existing, exists := cm.passwords.NodePasswords[nodeName]; exists {
			existing.HTTPPassword = password
			cm.passwords.NodePasswords[nodeName] = existing
		} else {
			cm.passwords.SetNodePasswords(nodeName, "", password)
		}
	} else {
		if existing, exists := cm.passwords.NodePasswords[filename]; exists {
			existing.TransportPassword = password
			cm.passwords.NodePasswords[filename] = existing
		} else {
			cm.passwords.SetNodePasswords(filename, password, "")
		}
	}

	// Save to files
	if err := cm.saveCertificateAndKey(filename, certPEM, keyPEM); err != nil {
		return err
	}

	// Log certificate creation
	certPath := filepath.Join(cm.outputDir, filename+".pem")
	cm.logger.LogCertificateAction("created", filename+" node", certPath)

	return nil
}

// GenerateClientCertificate creates a client certificate signed by the CA
func (cm *CertificateManager) GenerateClientCertificate(ca *CAInfo, dn string, validityDays int, filename string, passwordSetting string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse distinguished name
	subject, err := parseDistinguishedName(dn)
	if err != nil {
		return fmt.Errorf("failed to parse DN: %w", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, &privateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Handle password
	var password string
	if passwordSetting == "auto" {
		var err error
		password, err = cm.passwordManager.GeneratePassword()
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		cm.logger.LogPasswordGeneration(filename + " client")
	} else if passwordSetting != "none" && passwordSetting != "" {
		password = passwordSetting
	}

	// Encrypt private key if password is provided
	var keyPEM []byte
	if password != "" {
		encryptedKeyPEM, err := cm.encryptPrivateKey(keyDER, password)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
		keyPEM = encryptedKeyPEM
	} else {
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})
	}

	// Store password for client
	cm.passwords.SetClientPassword(filename, password)

	// Save to files
	if err := cm.saveCertificateAndKey(filename, certPEM, keyPEM); err != nil {
		return err
	}

	// Log certificate creation
	certPath := filepath.Join(cm.outputDir, filename+".pem")
	cm.logger.LogCertificateAction("created", filename+" client", certPath)

	return nil
}

// saveCertificateAndKey saves certificate and key to separate files
func (cm *CertificateManager) saveCertificateAndKey(basename string, certPEM, keyPEM []byte) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(cm.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save certificate
	certFile := filepath.Join(cm.outputDir, basename+".pem")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Save private key
	keyFile := filepath.Join(cm.outputDir, basename+".key")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// parseDistinguishedName parses a DN string into pkix.Name
func parseDistinguishedName(dn string) (pkix.Name, error) {
	var name pkix.Name
	
	// Handle escaped commas by replacing them with a placeholder
	placeholder := "##ESCAPED_COMMA##"
	dn = strings.ReplaceAll(dn, "\\,", placeholder)
	
	// Split by commas and parse each component
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		// Split by equals sign
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return name, fmt.Errorf("invalid DN component: %s", part)
		}
		
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		
		// Restore escaped commas
		value = strings.ReplaceAll(value, placeholder, ",")
		
		switch strings.ToUpper(key) {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = append(name.Organization, value)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, value)
		case "C":
			name.Country = append(name.Country, value)
		case "L":
			name.Locality = append(name.Locality, value)
		case "ST", "S":
			name.Province = append(name.Province, value)
		case "STREET":
			name.StreetAddress = append(name.StreetAddress, value)
		case "POSTALCODE":
			name.PostalCode = append(name.PostalCode, value)
		case "DC":
			// Domain Component - add to ExtraNames
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{0, 9, 2342, 19200300, 100, 1, 25}, // DC OID
				Value: value,
			})
		default:
			return name, fmt.Errorf("unsupported DN attribute: %s", key)
		}
	}
	
	if name.CommonName == "" {
		return name, fmt.Errorf("CN (Common Name) is required in DN")
	}
	
	return name, nil
}

// encryptPrivateKey encrypts a private key with a password using PKCS#8
func (cm *CertificateManager) encryptPrivateKey(keyDER []byte, password string) ([]byte, error) {
	// Use PKCS#8 encryption similar to the Java version
	// This uses PBE-SHA1-3DES encryption
	encryptedKey, err := x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", keyDER, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	
	return pem.EncodeToMemory(encryptedKey), nil
}

// GetPasswords returns the password collection
func (cm *CertificateManager) GetPasswords() *CertificatePasswords {
	return cm.passwords
}

// LoadCAFromPEM loads a CA certificate and private key from PEM data
func LoadCAFromPEM(certPEM, keyPEM []byte) (*CAInfo, error) {
	return LoadCAFromPEMWithPassword(certPEM, keyPEM, "")
}

// LoadCAFromPEMWithPassword loads a CA certificate and private key from PEM data with optional password
func LoadCAFromPEMWithPassword(certPEM, keyPEM []byte, password string) (*CAInfo, error) {
	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	
	var privateKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	case "RSA PRIVATE KEY":
		// PKCS#1 format
		var err error
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	case "ENCRYPTED PRIVATE KEY":
		// Encrypted PKCS#8 format
		if password == "" {
			return nil, fmt.Errorf("encrypted private key requires password")
		}
		
		// Decrypt the private key
		decryptedKey, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		
		// Parse the decrypted PKCS#8 key
		key, err := x509.ParsePKCS8PrivateKey(decryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse decrypted PKCS8 private key: %w", err)
		}
		
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("decrypted private key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}
	
	return &CAInfo{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// parseOID parses an OID string like "1.2.3.4.5" into an asn1.ObjectIdentifier
func parseOID(oidStr string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(oidStr, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	
	for i, part := range parts {
		val, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid OID part %q: %w", part, err)
		}
		oid[i] = val
	}
	
	return oid, nil
}
