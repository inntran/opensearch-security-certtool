package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	outputDir       string
	passwordManager *PasswordManager
	passwords       *CertificatePasswords
	logger          *logger.Logger
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
	PrivateKey  crypto.Signer
	CertPEM     []byte
	KeyPEM      []byte
	Password    string
}

// KeyGenSettings controls whether RSA or ECDSA keys are generated.
// UseEllipticCurves mirrors the Java Search Guard TLS Tool's global
// "useEllipticCurves" setting; EllipticCurve selects the named curve
// (e.g. "P-384") when UseEllipticCurves is true.
type KeyGenSettings struct {
	UseEllipticCurves bool
	EllipticCurve     string
}

// generatePrivateKey creates a new RSA or ECDSA private key depending on settings.
// When useEC is true, the named curve is used (defaulting to P-384 if empty);
// otherwise an RSA key of the given size is generated.
func generatePrivateKey(useEC bool, curveName string, keySize int) (crypto.Signer, error) {
	if !useEC {
		privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
		}
		return privateKey, nil
	}

	curve, err := curveByName(curveName)
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC private key: %w", err)
	}
	return privateKey, nil
}

// curveByName maps a configured curve name to a stdlib crypto/elliptic curve.
// An empty name defaults to P-384, matching the Java tool's default.
func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "", "P-384":
		return elliptic.P384(), nil
	case "P-224":
		return elliptic.P224(), nil
	case "P-256":
		return elliptic.P256(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", name)
	}
}

// GenerateCA creates a new certificate authority
func (cm *CertificateManager) GenerateCA(
	dn string, keySize int, validityDays int, filename string, passwordSetting string,
) (*CAInfo, error) {
	return cm.GenerateCAWithConfig(dn, keySize, validityDays, filename, passwordSetting, "")
}

// GenerateCAWithConfig creates a new certificate authority with CRL distribution points
func (cm *CertificateManager) GenerateCAWithConfig(
	dn string, keySize int, validityDays int, filename string, passwordSetting string, crlDistributionPoints string,
) (*CAInfo, error) {
	return cm.GenerateCAWithKeySettings(
		dn, keySize, validityDays, filename, passwordSetting, crlDistributionPoints, KeyGenSettings{},
	)
}

// GenerateCAWithKeySettings creates a new certificate authority with CRL distribution points
// and explicit key generation settings (RSA vs. ECDSA).
func (cm *CertificateManager) GenerateCAWithKeySettings(
	dn string, keySize int, validityDays int, filename string, passwordSetting string,
	crlDistributionPoints string, keySettings KeyGenSettings,
) (*CAInfo, error) {
	// Generate private key
	privateKey, err := generatePrivateKey(keySettings.UseEllipticCurves, keySettings.EllipticCurve, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse distinguished name
	subject, err := parseDistinguishedName(dn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DN: %w", err)
	}

	rawSubject, err := buildOrderedRawSubject(dn)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DN: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		RawSubject:            rawSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// Add CRL distribution points if specified
	if crlDistributionPoints != "" {
		template.CRLDistributionPoints = []string{crlDistributionPoints}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
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
func (cm *CertificateManager) GenerateNodeCertificate(
	ca *CAInfo, dn string, dnsNames []string, ipAddresses []string,
	validityDays int, filename string, passwordSetting string,
) error {
	return cm.GenerateNodeCertificateWithOID(ca, dn, dnsNames, ipAddresses, validityDays, filename, passwordSetting, "")
}

// GenerateNodeCertificateWithOID creates a node certificate with optional node OID
func (cm *CertificateManager) GenerateNodeCertificateWithOID(
	ca *CAInfo, dn string, dnsNames []string, ipAddresses []string,
	validityDays int, filename string, passwordSetting string, nodeOID string,
) error {
	return cm.GenerateNodeCertificateWithKeySettings(
		ca, dn, dnsNames, ipAddresses, validityDays, filename, passwordSetting, nodeOID, KeyGenSettings{},
	)
}

// GenerateNodeCertificateWithKeySettings creates a node certificate with an optional
// node OID and explicit key generation settings (RSA vs. ECDSA).
func (cm *CertificateManager) GenerateNodeCertificateWithKeySettings(
	ca *CAInfo, dn string, dnsNames []string, ipAddresses []string,
	validityDays int, filename string, passwordSetting string, nodeOID string, keySettings KeyGenSettings,
) error {
	// Generate private key
	privateKey, err := generatePrivateKey(keySettings.UseEllipticCurves, keySettings.EllipticCurve, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse distinguished name
	subject, err := parseDistinguishedName(dn)
	if err != nil {
		return fmt.Errorf("failed to parse DN: %w", err)
	}

	rawSubject, err := buildOrderedRawSubject(dn)
	if err != nil {
		return fmt.Errorf("failed to encode DN: %w", err)
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
		RawSubject:   rawSubject,
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
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, privateKey.Public(), ca.PrivateKey)
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
func (cm *CertificateManager) GenerateClientCertificate(
	ca *CAInfo, dn string, validityDays int, filename string, passwordSetting string,
) error {
	return cm.GenerateClientCertificateWithKeySettings(ca, dn, validityDays, filename, passwordSetting, KeyGenSettings{})
}

// GenerateClientCertificateWithKeySettings creates a client certificate signed by the CA
// using explicit key generation settings (RSA vs. ECDSA).
func (cm *CertificateManager) GenerateClientCertificateWithKeySettings(
	ca *CAInfo, dn string, validityDays int, filename string, passwordSetting string, keySettings KeyGenSettings,
) error {
	// Generate private key
	privateKey, err := generatePrivateKey(keySettings.UseEllipticCurves, keySettings.EllipticCurve, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse distinguished name
	subject, err := parseDistinguishedName(dn)
	if err != nil {
		return fmt.Errorf("failed to parse DN: %w", err)
	}

	rawSubject, err := buildOrderedRawSubject(dn)
	if err != nil {
		return fmt.Errorf("failed to encode DN: %w", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		RawSubject:   rawSubject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, privateKey.Public(), ca.PrivateKey)
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
	if err := os.MkdirAll(cm.outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save certificate
	certFile := filepath.Join(cm.outputDir, basename+".pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Save private key
	keyFile := filepath.Join(cm.outputDir, basename+".key")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// dnAttributeOIDs maps DN attribute keywords to their ASN.1 object identifiers.
var dnAttributeOIDs = map[string]asn1.ObjectIdentifier{
	"CN":         {2, 5, 4, 3},
	"O":          {2, 5, 4, 10},
	"OU":         {2, 5, 4, 11},
	"C":          {2, 5, 4, 6},
	"L":          {2, 5, 4, 7},
	"ST":         {2, 5, 4, 8},
	"S":          {2, 5, 4, 8},
	"STREET":     {2, 5, 4, 9},
	"POSTALCODE": {2, 5, 4, 17},
	"DC":         {0, 9, 2342, 19200300, 100, 1, 25},
}

// parseDistinguishedName parses a DN string into pkix.Name
func parseDistinguishedName(dn string) (pkix.Name, error) {
	var name pkix.Name

	attrs, err := parseDNAttributes(dn)
	if err != nil {
		return name, err
	}

	for _, attr := range attrs {
		switch attr.key {
		case "CN":
			name.CommonName = attr.value
		case "O":
			name.Organization = append(name.Organization, attr.value)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, attr.value)
		case "C":
			name.Country = append(name.Country, attr.value)
		case "L":
			name.Locality = append(name.Locality, attr.value)
		case "ST", "S":
			name.Province = append(name.Province, attr.value)
		case "STREET":
			name.StreetAddress = append(name.StreetAddress, attr.value)
		case "POSTALCODE":
			name.PostalCode = append(name.PostalCode, attr.value)
		case "DC":
			// Domain Component - add to ExtraNames
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  dnAttributeOIDs["DC"],
				Value: attr.value,
			})
		}
	}

	if name.CommonName == "" {
		return name, fmt.Errorf("CN (Common Name) is required in DN")
	}

	return name, nil
}

// dnAttribute is a single parsed "KEY=value" component of a DN string,
// preserving the original input order.
type dnAttribute struct {
	key   string
	value string
}

// parseDNAttributes splits a DN string into ordered key/value components,
// validating that each key is a supported DN attribute.
func parseDNAttributes(dn string) ([]dnAttribute, error) {
	// Handle escaped commas by replacing them with a placeholder
	placeholder := "##ESCAPED_COMMA##"
	dn = strings.ReplaceAll(dn, "\\,", placeholder)

	var attrs []dnAttribute

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
			return nil, fmt.Errorf("invalid DN component: %s", part)
		}

		key := strings.ToUpper(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		// Restore escaped commas
		value = strings.ReplaceAll(value, placeholder, ",")

		if _, ok := dnAttributeOIDs[key]; !ok {
			return nil, fmt.Errorf("unsupported DN attribute: %s", key)
		}

		attrs = append(attrs, dnAttribute{key: key, value: value})
	}

	return attrs, nil
}

// asn1RDN mirrors the ASN.1 AttributeTypeAndValue / RDN / Name structures so
// that we can marshal a subject whose attribute order is controlled
// precisely, instead of the fixed field order pkix.Name imposes on encode.
//
// OpenSearch Security does not compare RFC2253 display strings directly: its
// DefaultPrincipalExtractor takes the certificate's X500Principal string
// (RFC2253, i.e. reverse-of-DER order), re-parses it with javax.naming's
// LdapName (which un-reverses it back to DER/logical order), and then
// reverses that list *again* before joining it into the "SSL Principal"
// used for plugins.security.nodes_dn wildcard matching. Net effect: the
// principal OpenSearch matches against nodes_dn equals the DN attributes in
// DER encoding order, unreversed.
//
// The legacy Java Search Guard tlstool DER-encodes DC-first (opposite of the
// CN-first order typically written in tlsconfig's dn: string), so that after
// the extractor's reversal the resulting principal is CN-first and matches
// CN-first nodes_dn wildcards. To stay compatible, we must therefore encode
// the DER subject in the *reverse* of the input DN string's attribute order.
type asn1AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value string `asn1:"utf8"`
}

// asn1RDNSET is a single-valued RelativeDistinguishedName. The Go asn1
// package special-cases slice type names with a "SET" suffix (mirroring
// pkix.RelativeDistinguishedNameSET) to encode as SET OF instead of the
// default SEQUENCE OF.
type asn1RDNSET []asn1AttributeTypeAndValue

// buildOrderedRawSubject parses a DN string and ASN.1-encodes it as an X.501
// Name (RDNSequence of single-valued RDNs) in the reverse of the DN string's
// attribute order, for use as x509.Certificate.RawSubject. See the
// asn1AttributeTypeAndValue doc comment for why the order must be reversed
// to match the legacy Java Search Guard tlstool and OpenSearch Security's
// nodes_dn principal matching.
func buildOrderedRawSubject(dn string) ([]byte, error) {
	attrs, err := parseDNAttributes(dn)
	if err != nil {
		return nil, err
	}

	hasCN := false
	rdnSequence := make([]asn1RDNSET, 0, len(attrs))
	for i := len(attrs) - 1; i >= 0; i-- {
		attr := attrs[i]
		if attr.key == "CN" {
			hasCN = true
		}
		rdnSequence = append(rdnSequence, asn1RDNSET{
			{Type: dnAttributeOIDs[attr.key], Value: attr.value},
		})
	}

	if !hasCN {
		return nil, fmt.Errorf("CN (Common Name) is required in DN")
	}

	return asn1.Marshal(rdnSequence)
}

// encryptPrivateKey encrypts a PKCS#8 private key with a password, producing
// a standard PKCS#8 EncryptedPrivateKeyInfo (PBES2/PBKDF2 + AES-256-CBC) PEM
// block, so the result is readable by standard PKCS#8 consumers (OpenSSL,
// Java, the OpenSearch security plugin).
func (cm *CertificateManager) encryptPrivateKey(keyDER []byte, password string) ([]byte, error) {
	encryptedDER, err := encryptPKCS8PrivateKeyInfo(keyDER, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedDER,
	}), nil
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

	var privateKey crypto.Signer
	switch keyBlock.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		privateKey, err = asSigner(key)
		if err != nil {
			return nil, err
		}
	case "RSA PRIVATE KEY":
		// PKCS#1 format
		var err error
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	case "EC PRIVATE KEY":
		// SEC1/PKCS#1-style EC format
		ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		privateKey = ecKey
	case "ENCRYPTED PRIVATE KEY":
		// Encrypted PKCS#8 format
		if password == "" {
			return nil, fmt.Errorf("encrypted private key requires password")
		}

		var decryptedKey []byte
		if _, hasDEKInfo := keyBlock.Headers["DEK-Info"]; hasDEKInfo {
			// Legacy RFC1423 PEM-header encryption (this tool's own older output)
			var err error
			decryptedKey, err = x509.DecryptPEMBlock(keyBlock, []byte(password))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
		} else {
			// Standard PKCS#8 EncryptedPrivateKeyInfo (RFC 5958/8018 PBES2)
			var err error
			decryptedKey, err = decryptPKCS8EncryptedPrivateKeyInfo(keyBlock.Bytes, []byte(password))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
		}

		// Parse the decrypted PKCS8 key
		key, err := x509.ParsePKCS8PrivateKey(decryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse decrypted PKCS8 private key: %w", err)
		}

		privateKey, err = asSigner(key)
		if err != nil {
			return nil, fmt.Errorf("decrypted %w", err)
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

// asSigner converts the result of x509.ParsePKCS8PrivateKey (which returns
// an untyped interface{}) into a crypto.Signer, accepting both RSA and
// ECDSA keys.
func asSigner(key interface{}) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("private key is not RSA or ECDSA")
	}
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
