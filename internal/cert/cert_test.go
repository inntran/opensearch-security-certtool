package cert

import (
	"bytes"
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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inntran/opensearch-security-certtool/internal/logger"
)

func TestNewCertificateManager(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)

	cm := NewCertificateManager(tempDir, 16, log)

	if cm.outputDir != tempDir {
		t.Errorf("Expected outputDir %s, got %s", tempDir, cm.outputDir)
	}
	if cm.passwordManager == nil {
		t.Error("Expected passwordManager to be initialized")
	}
	if cm.passwords == nil {
		t.Error("Expected passwords to be initialized")
	}
}

func TestGenerateCA(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	tests := []struct {
		name            string
		dn              string
		keySize         int
		validityDays    int
		filename        string
		passwordSetting string
		expectPassword  bool
		expectFiles     bool
	}{
		{
			name:            "basic_ca_with_auto_password",
			dn:              "CN=Test CA,O=Test Org,C=US",
			keySize:         2048,
			validityDays:    365,
			filename:        "test-ca",
			passwordSetting: "auto",
			expectPassword:  true,
			expectFiles:     true,
		},
		{
			name:            "ca_with_fixed_password",
			dn:              "CN=Test CA 2,O=Test Org,C=US",
			keySize:         2048,
			validityDays:    365,
			filename:        "test-ca-2",
			passwordSetting: "mypassword123",
			expectPassword:  true,
			expectFiles:     true,
		},
		{
			name:            "ca_without_password",
			dn:              "CN=Test CA 3,O=Test Org,C=US",
			keySize:         2048,
			validityDays:    365,
			filename:        "test-ca-3",
			passwordSetting: "none",
			expectPassword:  false,
			expectFiles:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caInfo, err := cm.GenerateCA(tt.dn, tt.keySize, tt.validityDays, tt.filename, tt.passwordSetting)
			if err != nil {
				t.Fatalf("GenerateCA() error = %v", err)
			}

			if caInfo == nil {
				t.Fatal("Expected CA info to be returned")
			}

			// Check certificate properties
			if caInfo.Certificate.Subject.CommonName != "Test CA" && caInfo.Certificate.Subject.CommonName != "Test CA 2" && caInfo.Certificate.Subject.CommonName != "Test CA 3" {
				t.Errorf("Unexpected Common Name: %s", caInfo.Certificate.Subject.CommonName)
			}

			if !caInfo.Certificate.IsCA {
				t.Error("Expected certificate to be marked as CA")
			}

			// Check password handling
			if tt.expectPassword && caInfo.Password == "" {
				t.Error("Expected password to be set")
			}
			if !tt.expectPassword && caInfo.Password != "" {
				t.Error("Expected no password")
			}

			// Check files exist
			if tt.expectFiles {
				certFile := filepath.Join(tempDir, tt.filename+".pem")
				keyFile := filepath.Join(tempDir, tt.filename+".key")

				if _, err := os.Stat(certFile); os.IsNotExist(err) {
					t.Errorf("Certificate file not created: %s", certFile)
				}
				if _, err := os.Stat(keyFile); os.IsNotExist(err) {
					t.Errorf("Key file not created: %s", keyFile)
				}
			}
		})
	}
}

func TestGenerateCAEncryptedKeyIsStandardPKCS8(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	caInfo, err := cm.GenerateCA("CN=Test CA,O=Test Org,C=US", 2048, 365, "test-ca", "mypassword123")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	keyBlock, _ := pem.Decode(caInfo.KeyPEM)
	if keyBlock == nil {
		t.Fatal("Failed to decode key PEM")
	}

	if keyBlock.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("Expected PEM type ENCRYPTED PRIVATE KEY, got %s", keyBlock.Type)
	}

	if _, hasDEKInfo := keyBlock.Headers["DEK-Info"]; hasDEKInfo {
		t.Error("Encrypted key must not use legacy RFC1423 PEM headers (DEK-Info); expected standard PKCS8 ASN.1 encoding")
	}

	// The PEM body must be a valid ASN.1 EncryptedPrivateKeyInfo structure,
	// decryptable via the standard PBES2 path (as produced by OpenSSL/Java).
	decryptedDER, err := decryptPKCS8EncryptedPrivateKeyInfo(keyBlock.Bytes, []byte("mypassword123"))
	if err != nil {
		t.Fatalf("Failed to decrypt generated key as standard PKCS8: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decryptedDER); err != nil {
		t.Fatalf("Decrypted key is not valid PKCS8: %v", err)
	}
}

func TestGenerateCAWithCRLDistributionPoints(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	crlURL := "https://example.com/revoked.crl"
	caInfo, err := cm.GenerateCAWithConfig(
		"CN=Test CA,O=Test Org,C=US",
		2048,
		365,
		"test-ca-crl",
		"auto",
		crlURL,
	)

	if err != nil {
		t.Fatalf("GenerateCAWithConfig() error = %v", err)
	}

	if len(caInfo.Certificate.CRLDistributionPoints) == 0 {
		t.Error("Expected CRL distribution points to be set")
	}

	if caInfo.Certificate.CRLDistributionPoints[0] != crlURL {
		t.Errorf("Expected CRL URL %s, got %s", crlURL, caInfo.Certificate.CRLDistributionPoints[0])
	}
}

func TestGenerateNodeCertificate(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	// First create a CA
	caInfo, err := cm.GenerateCA("CN=Test CA,O=Test Org,C=US", 2048, 365, "test-ca", "none")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	tests := []struct {
		name         string
		dn           string
		dnsNames     []string
		ipAddresses  []string
		validityDays int
		filename     string
		password     string
	}{
		{
			name:         "node_with_dns_and_ip",
			dn:           "CN=node1.example.com,O=Test Org,C=US",
			dnsNames:     []string{"node1.example.com", "localhost"},
			ipAddresses:  []string{"127.0.0.1", "10.0.0.1"},
			validityDays: 365,
			filename:     "node1",
			password:     "auto",
		},
		{
			name:         "node_dns_only",
			dn:           "CN=node2.example.com,O=Test Org,C=US",
			dnsNames:     []string{"node2.example.com"},
			ipAddresses:  []string{},
			validityDays: 365,
			filename:     "node2",
			password:     "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cm.GenerateNodeCertificate(
				caInfo,
				tt.dn,
				tt.dnsNames,
				tt.ipAddresses,
				tt.validityDays,
				tt.filename,
				tt.password,
			)

			if err != nil {
				t.Fatalf("GenerateNodeCertificate() error = %v", err)
			}

			// Check files exist
			certFile := filepath.Join(tempDir, tt.filename+".pem")
			keyFile := filepath.Join(tempDir, tt.filename+".key")

			if _, err := os.Stat(certFile); os.IsNotExist(err) {
				t.Errorf("Certificate file not created: %s", certFile)
			}
			if _, err := os.Stat(keyFile); os.IsNotExist(err) {
				t.Errorf("Key file not created: %s", keyFile)
			}

			// Read and verify certificate
			certData, err := os.ReadFile(certFile)
			if err != nil {
				t.Fatalf("Failed to read certificate file: %v", err)
			}

			block, _ := pem.Decode(certData)
			if block == nil {
				t.Fatal("Failed to decode certificate PEM")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			// Verify DNS names
			for _, dnsName := range tt.dnsNames {
				found := false
				for _, certDNS := range cert.DNSNames {
					if certDNS == dnsName {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("DNS name %s not found in certificate", dnsName)
				}
			}

			// Verify IP addresses
			for _, ipStr := range tt.ipAddresses {
				found := false
				for _, certIP := range cert.IPAddresses {
					if certIP.String() == ipStr {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("IP address %s not found in certificate", ipStr)
				}
			}
		})
	}
}

func TestGenerateNodeCertificateWithOID(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	// Create a CA first
	caInfo, err := cm.GenerateCA("CN=Test CA,O=Test Org,C=US", 2048, 365, "test-ca", "none")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	nodeOID := "1.2.3.4.5.5"
	err = cm.GenerateNodeCertificateWithOID(
		caInfo,
		"CN=node-with-oid.example.com,O=Test Org,C=US",
		[]string{"node-with-oid.example.com"},
		[]string{"127.0.0.1"},
		365,
		"node-with-oid",
		"none",
		nodeOID,
	)

	if err != nil {
		t.Fatalf("GenerateNodeCertificateWithOID() error = %v", err)
	}

	// Verify certificate was created
	certFile := filepath.Join(tempDir, "node-with-oid.pem")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Error("Certificate file not created")
	}
}

func TestGenerateClientCertificate(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	// Create a CA first
	caInfo, err := cm.GenerateCA("CN=Test CA,O=Test Org,C=US", 2048, 365, "test-ca", "none")
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	err = cm.GenerateClientCertificate(
		caInfo,
		"CN=admin,O=Test Org,C=US",
		365,
		"admin",
		"auto",
	)

	if err != nil {
		t.Fatalf("GenerateClientCertificate() error = %v", err)
	}

	// Check files exist
	certFile := filepath.Join(tempDir, "admin.pem")
	keyFile := filepath.Join(tempDir, "admin.key")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Error("Certificate file not created")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("Key file not created")
	}

	// Read and verify certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify it's a client certificate
	found := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			found = true
			break
		}
	}
	if !found {
		t.Error("Certificate missing ClientAuth extended key usage")
	}

	// Check password was stored
	password := cm.passwords.GetClientPassword("admin")
	if password == "" {
		t.Error("Expected client password to be stored")
	}
}

// subjectAttrOIDs returns the OIDs of a certificate's subject RDNs in the
// order they were encoded, as dotted strings, by decoding RawSubject
// directly rather than going through pkix.Name (which reorders fields).
func subjectAttrOIDs(t *testing.T, cert *x509.Certificate) []string {
	t.Helper()

	var rdnSeq pkix.RDNSequence
	rest, err := asn1.Unmarshal(cert.RawSubject, &rdnSeq)
	if err != nil {
		t.Fatalf("failed to unmarshal RawSubject: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes after RawSubject: %d", len(rest))
	}

	var oids []string
	for _, rdn := range rdnSeq {
		for _, atv := range rdn {
			oids = append(oids, atv.Type.String())
		}
	}
	return oids
}

const (
	oidCN = "2.5.4.3"
	oidDC = "0.9.2342.19200300.100.1.25"
)

// openSearchPrincipal reproduces OpenSearch Security's
// DefaultPrincipalExtractor: it takes the certificate's DER RDN sequence
// (logical/encoding order) and reverses it, joining with commas. This is
// the string plugins.security.nodes_dn wildcards are actually matched
// against, which is why our DER encoding order must be the reverse of the
// DN string's attribute order (see the asn1AttributeTypeAndValue doc
// comment in cert.go).
func openSearchPrincipal(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	var rdnSeq pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &rdnSeq); err != nil {
		t.Fatalf("failed to unmarshal RawSubject: %v", err)
	}

	parts := make([]string, 0, len(rdnSeq))
	for _, rdn := range rdnSeq {
		for _, atv := range rdn {
			name := atv.Type.String()
			switch name {
			case oidCN:
				name = "CN"
			case oidDC:
				name = "DC"
			case "2.5.4.10":
				name = "O"
			case "2.5.4.11":
				name = "OU"
			case "2.5.4.6":
				name = "C"
			}
			parts = append(parts, fmt.Sprintf("%s=%s", name, atv.Value))
		}
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ",")
}

func TestGenerateCAOpenSearchPrincipalMatchesDNOrder(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	dn := "CN=node.example.com,OU=Example,O=Example Org,DC=opensearch,DC=example,DC=com"
	caInfo, err := cm.GenerateCA(dn, 2048, 365, "root-ca", "none")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	want := "CN=node.example.com,OU=Example,O=Example Org,DC=opensearch,DC=example,DC=com"
	if got := openSearchPrincipal(t, caInfo.Certificate); got != want {
		t.Fatalf("OpenSearch principal = %q, want %q", got, want)
	}
}

func TestGenerateNodeCertificateOpenSearchPrincipalMatchesDNOrder(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	caDN := "CN=Test CA,OU=Example,O=Example Org,DC=opensearch,DC=example,DC=com"
	caInfo, err := cm.GenerateCA(caDN, 2048, 365, "root-ca", "none")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	dn := "CN=node-001.example.com,OU=Example,O=Example Org,DC=opensearch,DC=example,DC=com"
	if err := cm.GenerateNodeCertificate(
		caInfo, dn, []string{"node-001.example.com"}, nil, 365, "node-001", "none",
	); err != nil {
		t.Fatalf("GenerateNodeCertificate() error = %v", err)
	}

	certData, err := os.ReadFile(filepath.Join(tempDir, "node-001.pem"))
	if err != nil {
		t.Fatalf("failed to read node cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("failed to decode node cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse node cert: %v", err)
	}

	if got := openSearchPrincipal(t, cert); got != dn {
		t.Fatalf("OpenSearch principal = %q, want %q", got, dn)
	}

	if !bytes.Equal(cert.RawIssuer, caInfo.Certificate.RawSubject) {
		t.Fatalf("expected node cert issuer bytes to match CA subject bytes exactly")
	}
	if got := openSearchPrincipal(t, caInfo.Certificate); got != caDN {
		t.Fatalf("issuer (CA) OpenSearch principal = %q, want %q", got, caDN)
	}
}

func TestGenerateClientCertificateOpenSearchPrincipalMatchesDNOrder(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	caInfo, err := cm.GenerateCA("CN=Test CA,O=Test Org,C=US", 2048, 365, "root-ca", "none")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	dn := "CN=admin,OU=Example,O=Example Org,DC=opensearch,DC=example,DC=com"
	if err := cm.GenerateClientCertificate(caInfo, dn, 365, "admin", "none"); err != nil {
		t.Fatalf("GenerateClientCertificate() error = %v", err)
	}

	certData, err := os.ReadFile(filepath.Join(tempDir, "admin.pem"))
	if err != nil {
		t.Fatalf("failed to read client cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("failed to decode client cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse client cert: %v", err)
	}

	if got := openSearchPrincipal(t, cert); got != dn {
		t.Fatalf("OpenSearch principal = %q, want %q", got, dn)
	}
}

func TestGenerateNodeCertificateOpenSearchPrincipalWithoutDC(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	caInfo, err := cm.GenerateCA("CN=Test CA,O=Test Org,C=US", 2048, 365, "root-ca", "none")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	dn := "CN=node.example.com,OU=Example,O=Example Org,C=US"
	if err := cm.GenerateNodeCertificate(
		caInfo, dn, []string{"node.example.com"}, nil, 365, "node", "none",
	); err != nil {
		t.Fatalf("GenerateNodeCertificate() error = %v", err)
	}

	certData, err := os.ReadFile(filepath.Join(tempDir, "node.pem"))
	if err != nil {
		t.Fatalf("failed to read node cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("failed to decode node cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse node cert: %v", err)
	}

	if got := openSearchPrincipal(t, cert); got != dn {
		t.Fatalf("OpenSearch principal = %q, want %q", got, dn)
	}

	// DER order must be the exact reverse of the DN string.
	wantOIDs := []string{"2.5.4.6", "2.5.4.10", "2.5.4.11", oidCN} // C, O, OU, CN
	oids := subjectAttrOIDs(t, cert)
	if len(oids) != len(wantOIDs) {
		t.Fatalf("expected %d subject attrs, got %d: %v", len(wantOIDs), len(oids), oids)
	}
	for i, want := range wantOIDs {
		if oids[i] != want {
			t.Fatalf("attr %d: expected OID %s, got %s (full order: %v)", i, want, oids[i], oids)
		}
	}
}

func TestGenerateNodeCertificateOpenSearchPrincipalWithEscapedComma(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	caInfo, err := cm.GenerateCA("CN=Test CA,O=Test Org,C=US", 2048, 365, "root-ca", "none")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	dn := `CN=node.example.com,O=My\, Org,DC=example,DC=com`
	if err := cm.GenerateNodeCertificate(
		caInfo, dn, []string{"node.example.com"}, nil, 365, "node", "none",
	); err != nil {
		t.Fatalf("GenerateNodeCertificate() error = %v", err)
	}

	certData, err := os.ReadFile(filepath.Join(tempDir, "node.pem"))
	if err != nil {
		t.Fatalf("failed to read node cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("failed to decode node cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse node cert: %v", err)
	}

	if cert.Subject.Organization[0] != "My, Org" {
		t.Fatalf("expected escaped comma to be restored in O, got %q", cert.Subject.Organization)
	}

	wantDN := `CN=node.example.com,O=My, Org,DC=example,DC=com`
	if got := openSearchPrincipal(t, cert); got != wantDN {
		t.Fatalf("OpenSearch principal = %q, want %q", got, wantDN)
	}

	// DER order must be the exact reverse of the DN string: DC, DC, O, CN.
	wantOIDs := []string{oidDC, oidDC, "2.5.4.10", oidCN}
	oids := subjectAttrOIDs(t, cert)
	if len(oids) != len(wantOIDs) {
		t.Fatalf("expected %d subject attrs, got %d: %v", len(wantOIDs), len(oids), oids)
	}
	for i, want := range wantOIDs {
		if oids[i] != want {
			t.Fatalf("attr %d: expected OID %s, got %s (full order: %v)", i, want, oids[i], oids)
		}
	}
}

func TestParseDistinguishedName(t *testing.T) {
	tests := []struct {
		name      string
		dn        string
		expectCN  string
		expectOrg []string
		expectErr bool
	}{
		{
			name:      "basic_dn",
			dn:        "CN=test.example.com,O=Test Org,C=US",
			expectCN:  "test.example.com",
			expectOrg: []string{"Test Org"},
			expectErr: false,
		},
		{
			name:      "dn_with_escaped_comma",
			dn:        "CN=test.example.com,O=Test\\, Inc.,C=US",
			expectCN:  "test.example.com",
			expectOrg: []string{"Test, Inc."},
			expectErr: false,
		},
		{
			name:      "dn_with_multiple_ou",
			dn:        "CN=test.example.com,OU=IT,OU=Security,O=Test Org,C=US",
			expectCN:  "test.example.com",
			expectOrg: []string{"Test Org"},
			expectErr: false,
		},
		{
			name:      "empty_dn",
			dn:        "",
			expectErr: true,
		},
		{
			name:      "no_cn",
			dn:        "O=Test Org,C=US",
			expectErr: true,
		},
		{
			name:      "invalid_format",
			dn:        "invalid-dn-format",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := parseDistinguishedName(tt.dn)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if name.CommonName != tt.expectCN {
				t.Errorf("Expected CN %s, got %s", tt.expectCN, name.CommonName)
			}

			if len(tt.expectOrg) > 0 {
				if len(name.Organization) == 0 {
					t.Error("Expected organization but got none")
				} else if name.Organization[0] != tt.expectOrg[0] {
					t.Errorf("Expected org %s, got %s", tt.expectOrg[0], name.Organization[0])
				}
			}
		})
	}
}

const testPBES2EncryptedKeyPEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ3z7u/j32qcJ701ln
a3exJgICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEP8lbfLJBqQPDW7s
XVgZCh4EggTQiskVc/HAS4oj+KSsYcxZWfTKrFfJxx8SVsubIRZA+wXFcscQP3Sr
e7peOGXMz+QeT5bJY0aKFcDvvs7fvDnMNF3ZnPj3RdEuuk8pG7sj/1Ogy6US0Slt
8p4+fx64fLP7ZBObD48JPOh/bOYEmZVoKsQfCe2/j1h5M1zA8AKR1Plt9PpR0zsD
ul8mMLFzcpGfDBqL5mhJCBONKkp43DAbYX8xIdnntuG0q3a4hMKz15WKh94wW9/k
xOhwF3dbSDf1Rrzv15tTXxoUZSI/JaX48tmvqh4DZpPL49TXzmNpCRMGlHtkNDTQ
YlusvvXeRIpBqJfq+bBj7uucddO/B0onsGiXWXvylDXSgTXvNI+aNQNRJqybByvT
tBz0GvFXPq54MPh6O6ZN21f4HzW5bMAIu/PYjPmZnT5wxx1TOIU5hmy/cH699h63
ettvOpjQYV+pWLwR+MRIIFRMqMRkEMTP2q05w6GsTZQrcZ3l24Fy6y1uGamgDceq
XcvejVSPkD6RC3ryZVKdHwtfFFuU25QG0ak6RnqpXpMg5iZCeBuDgH5/R42ik8+s
InzTPNTadG7wX9u7mg7OCXPVST7IKREv19gV31hq3rrWKDpR044mv8zPLQak5wkl
NdwYZ/2kWXdN0lDuXn2Wg91tZxde08j4/4xILxq2pa66HR5GgZe5OLYj+ihyguvc
wEDXylt1RNP55Jv1nro7c6qvo5e/U31z7CdB4rOyGEHzAcLaEQpUEsGtjZHaFaie
GCTAackIyxfdYgzZ/a1vLyMAQJo+p1YmChXM2yb+J7z7pPQ7CxPJMCW48vtVLGJe
x3eDuWEipXYySC+sgnr9WridY1TBUbRzblA2eHU3YKJKoyw27iNAQ6VHNQBeFLPJ
NKTnK+nGJnZXsE6byfUPvsI2TsZj1ui+4aQBX6ceoUlNETZSJ6JbnzyTyHqJSWFQ
xlkRrp4m47YqtkpUhKcxA5tmyr51jUJBEzdzw4SxMRmfa79F34fb42kkQ7TrEKgt
78pwdZ/KS70aKLeu9FEhecGhHhwWIGm/HhEVXVnutOfjG2dVZrAcsUZ+iIvMwyoa
Hh7v4OPpeGSH7pFSFTLUhaU69EvRgBpOU8GyPU1Mn2xoVGsvyI99x4E4b7IYPC4O
m5dD09tl6K/4/9gCSKOKqURj5DWs3zLrnTGVoiSH65jEjh7HNrH8JI4T47g4zc+C
NdfVzzNtvy5DuJ5qWOC+/yWv7qFKYSo0uT0CXD5kef3sS8NZSywupawzcHrOq1u7
kDxxajgCDjIAVLY1L79MvOWufYSMzgxbkaNsCGbOPagxGetgZXRFW4oCbuisX6qL
HsguAjUkhGUeThDQKzOIlqZ2T/HT+aE6MIh5oC/s309gXvWus/cUMIjmsxSLEtZt
YOSeVk022oyFd2bMwZcgKscqrr0ipt+EKNk+ijHmo4dCrKhpAHmoM0QUjCR5tj72
ywyoohFOpMp/oY4ixj8uCxMlgl/kFEdtnQFUuRWI4Tlv0otmYd3ynwhGgGvGNlqV
PhSGuwH3Z/vgOkB6NMThH18VlOFhIwbc8llwlNUEJbKU9EKVzAdPTHD0rByim2Xw
Glqx3Upbgy67OT/Txiz7A0cqPwnNfmMUX5Uvjef+qIyJmuHvXqIEUBU=
-----END ENCRYPTED PRIVATE KEY-----
`

// testLegacyPKCS12PBEEncryptedKeyPEM is a real key produced by
// `openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES`, encrypted with password
// "testpassword123". This is the legacy scheme Java's SunJCE provider uses
// for PKCS#8 keys (pbeWithSHA1And3-KeyTripleDES-CBC) instead of PBES2 -
// this tool intentionally does not decrypt it, but should explain why and
// how to convert it.
const testLegacyPKCS12PBEEncryptedKeyPEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6jAcBgoqhkiG9w0BDAEDMA4ECGuVcwPHc8SzAgIIAASCBMg61Gs3hB4Tvei6
LtOGj1VVb3+akyB79fK+BcBSOLRjxWHipfblyOcza/xUtuzO0/pMQZ5328qz3VI6
e/V9+srXJgsC1aZSlw8fXE1/Jk//4a+Y3HmgAglFx1cZ1fBOcrNqAOxTBmljh3aC
ivkjF5qIg+bID6FHpcZ9hgzhfIp2akLuPyw2iJnFoq3KQNetoLup3OXcyrVB+NFq
EfUWREFZr56zih3apBZbnhV9WViqRD1IFxU0Fv7UL08II4UAiEvv+Emmy11sGfeM
59Qj6DZFklh/whh6XPZETxUaa9EXzD5PmQzGPlTPsOa1ypvWfdj1uXJJA6lHmjhv
oikrWEcpe0ROaHA+7eeTLs9qL7G4cqOoqQkC49diVksYEis/OdRxdYpXpFF5m3S4
zqtR5gUWvlhCe8Ac4V5tLgGmf+5Qz4qzLibL+PyR9S5/UAzpr/huEA6GZ+v69CmP
r2gAXzQtpVNE7lgt9AtOiJ/mwA/J5oCXr4+JO+ptEs2ciJ1tPpGEomm3RbhYsmvF
LUWqs2S7GOxsJpbGTgeUyXI5VdGkAhLDO/tTdT2YOTQuctImPusZoN6yzcWWXLqV
RPxNlgnhkEK6UsJCTl3tjQpPT2D0wAI07Ta2dRmw4tHqohcb4/YAJEJw2njQU/00
RpvRSXMR/LhqUMcTW90IdGaVhRtHQZNMshPPAxiw5hcqLFI9hX/sMlPzl6aR/rVk
75RTlCqcnecS7eGG6859A75/OOjlfKWYih23gSTyOU9XI8JM8D6QthyXTV8i7nik
ypcXoWt3XO/EVBORwr+EPcbBoTn6SqXMrhCgxIx0k2EmFcnXax8qvOsEkZOqYpsP
v3Faho83t7Rvd8hOqbMuxvkx/12MYAxH5wWGH3+QZymyoAJyNdMUNTH/l3jpGBVk
qTHqtBzOkE31LUadpzw7FGl8LvMu1B+HmSiaJ5ECDUDPhh7cjBAqA7WJozWMEU9v
JizKiQr2jJWALtaCgRkxZfaW5AuLEhgIQzNiW8asdnDgZmEczuLglgFIMJtOEJjE
xDzEQ7G9bAS49OjFebbQSd2yLxFP4WhExVCdzjfmbttTS5hBvsZxQ8uFVZOqh43E
QIATjTqvj7mSyTX1IjcOeQDJNaQN9IZ/qZ3v/OrB4WKTgVIdTomQJwqipnjYFnVB
iPJsHdbrvQC0fvaZeLPLDAa6uvUUAmcDslPSqjl87QEV5hi+8lKpbcY5s5xwkqhU
1SAVFNhzhaizNWxyNYfhBbZISi6wx43d/FJeVRhLoDsgUXY4mHSSnljPuNeW6E+d
YYRL59LJGgHBNop4ekoxUu0JSGGXe2kLe8i72ZIvmxj0MfsXaN5KzIRkujCY1Rx0
qG3hj0XmLHjnJa2qZRjJF0Y2S0xDnW59LsMxcH//l0H0ferLUORo41l1ySB2pBtB
14SDRjLP+NpIlwg/mdgBaSc0hqYEdyRoZ7OBhShZNTGAuUKsbQd3GB9LOGrtoOQI
i2z1ucwdlGJ0wVwrvNpkQJwkdD/YyOtQNMQvIOH1pF2dRdonlgWiUmFJ43FwBFAW
vFqmi5WErcnY97n43Sz1GvMcZBGrZVZZ+jBouXACRLcCtcigd8QCZCKhlv22ynSa
/cpPyTIRn3RNf+MDi98=
-----END ENCRYPTED PRIVATE KEY-----
`

// TestLoadCAFromPEM_LegacyPKCS12PBE verifies that loading a key encrypted
// with the legacy pbeWithSHA1And3-KeyTripleDES-CBC scheme (unsupported by
// this tool, and distinct from PBES2) fails with actionable guidance
// pointing the user at an openssl conversion command, rather than a
// generic decrypt failure.
func TestLoadCAFromPEM_LegacyPKCS12PBE(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	_, err = LoadCAFromPEMWithPassword(certPEM, []byte(testLegacyPKCS12PBEEncryptedKeyPEM), "testpassword123")
	if err == nil {
		t.Fatal("Expected error loading legacy PKCS12-PBE encrypted key, got none")
	}

	msg := err.Error()
	if !strings.Contains(msg, "pbeWithSHA1And3-KeyTripleDES-CBC") && !strings.Contains(msg, "not supported") {
		t.Errorf("Expected error to explain the unsupported legacy scheme, got: %v", err)
	}
	if !strings.Contains(msg, "openssl pkcs8") {
		t.Errorf("Expected error to include an openssl conversion command, got: %v", err)
	}
}

// testLegacyKeyConvertedToPBES2PEM is testLegacyPKCS12PBEEncryptedKeyPEM
// after running the two commands documented in pbes2ConversionHelp (and by
// scripts/convert-legacy-ca-key.sh):
//
//	openssl pkcs8 -in old-key.pem -out decrypted-key.pem
//	openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in decrypted-key.pem -out new-key.pem
//
// re-encrypted with password "newpassword456". This proves the documented
// conversion path actually produces a key this tool can load.
const testLegacyKeyConvertedToPBES2PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQhI+FxfRire1gsndp
UUp8NgICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEDL20GAT6LxeJiKo
/HpXkeMEggTQ6rulyfVHWo3eJNNajhygs9ACBg8I+BEehoZnuIOPSqEUnJxbxv0q
zwlRKwaTvokUWdfhNlmIV41KfWOkAhYNq1SXhnNgzR+3iO6YWZQMvtxJrPN3NTB3
G8+0t5H5I+li+ILls8YPMYFWUZWTAd4dg/4Bm+dHtrHp2Dl+WWwHW9gUo+Bs4COB
BE9sI0JOsRtDsvXh04QTTDq4PT/K7L08Btlun5smsQFSJrlhjwl0ZjcA6HvCooXE
XrqwdrBVQArbOtxBdE6fttRJEaEHs8LSHGCFXg4+NPEpeucaIBPFo5vKCnNB6lCH
rjusQKNy6Kt+v0OR1hbAN3AbGcKPgFJ5zEkddoJxAw4UtZ3DVMoCPvrXJhvPKzks
IHx8N2GJr+TAAI2DAQd2ci7CIRxlMlLECrTY4Rd4Q9gPQ2X1yQ3PLyzG9W9VUnUO
sM4/2nUiXPuZ0YltX7IDOjAqFiBpZkPldId7Y3A9cczFQt2kfKoRSLzhUe0tzsr3
6Ep3IbUgFi1YlI8g8X9WKT/1MFmlF98h7wGrGDVsGnhmL9dPZE+BveikDNsOsNdz
bPhxuKwWbBMr7rvIIChBp6XrS7/cH+o+uBEp/wsfvWhVdlXIsMJhg9UrCfOnl9s1
meiCGwYfPDIqXRK+uFH6OclAyrgCgfqaHb8xEx48jjc0M9Bkc71joXejVXEyTSlG
A/YYUZzdowYVGhQgTLZoJuTDM6bHKYAa0E3W9xVBOUduzjcy9UyFiiG0CdBxfkUG
UKd2KgtCBbfixctvx5SW6w20jnRg2rasJpiVddrN+TFYXU2gcoKLuQAPhSm2JPEO
OlqLwH+7X7LrY4mr8wo/MNMZOqFWskow1Cu3oUHrVcGGP3XFqswunK6FBUlm6Bti
vTqBFl5xdnFZG5xtRCaqJm4ZqM5WnNk6C8S4+bykMx6Ah/9kPFNGm5NMBZSuTnJV
B+GhmsNHamgbz8icTB0DJq9ODOmQtvlPLwdy3s4uWhKKsJ6jtR2wiTni28cK6kSw
3heaEbruTXY3w+477F/RP3dmpH0ubkN2kFk2ymLtIt8ybdiIu8IaeD5jcsAXtR34
VZKc+dTbv81MfMChmRhyF6ydVmnNWKlIPj0BC59mg5ux/7zHTA7Spl/2nY2tXGAi
RB/34hpp4+8GJ1gcFyivK+eQNSRJhTiznlmJyX+nFIrE9B2MvBkQ87vRIf2xLpNu
uzDPrNNfGV680DlPyvkMDeBbe5UdcVljGOhAn27y5BYJjRMThEl6gu5sw0WnP+7h
ZCw6V3cmRlvDZgyxKYkt+oUDFKL7qP5MBlIq8K1GHNYk31J2+qN/pQBI0o2sXSqY
OQC6ge6nSFbTa4JA9pkxQqgHKXCLT/UKqI9lezfQdzJJ2uOmMfNsAgbi083bGBGx
4gHAvopFJfzQXMSK6xgudayyquQgn6c7m7C/IPg1H3Q8mOVmMqr8YIejy7MXFmAc
dBZsyJNY6gW9svx5jOLPZfeMa4WDRQuus/NfY8i2oPzhp049PuDUEZYcuBsyfvhZ
TP+LnOJD/gEXK5ZyWQc8kvLus/hmSbqjs+jBr9sT53c1eIoSOvcU8OKrxa+bnHr/
JPVUKTLB4ZXf6gykFw5IBVNaPwJxEwey/MEyty0kDeaNe9hPvr3vRHE=
-----END ENCRYPTED PRIVATE KEY-----
`

// TestLoadCAFromPEM_LegacyKeyAfterConversion verifies that after following
// the documented conversion (see pbes2ConversionHelp /
// scripts/convert-legacy-ca-key.sh), the resulting key loads successfully.
func TestLoadCAFromPEM_LegacyKeyAfterConversion(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	caInfo, err := LoadCAFromPEMWithPassword(certPEM, []byte(testLegacyKeyConvertedToPBES2PEM), "newpassword456")
	if err != nil {
		t.Fatalf("Failed to load converted key: %v", err)
	}
	if caInfo.PrivateKey == nil {
		t.Fatal("Expected private key to be loaded")
	}
}

// TestLoadCAFromPEM_PBES2 verifies decryption of a standard PKCS#8
// ENCRYPTED PRIVATE KEY using PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC,
// the format produced by `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256`.
// This is distinct from this tool's own legacy RFC1423 PEM-header encryption.
func TestLoadCAFromPEM_PBES2(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	caInfo, err := LoadCAFromPEMWithPassword(certPEM, []byte(testPBES2EncryptedKeyPEM), "testpassword123")
	if err != nil {
		t.Fatalf("Failed to load PBES2-encrypted CA key: %v", err)
	}
	if caInfo.PrivateKey == nil {
		t.Fatal("Expected private key to be loaded")
	}

	// Wrong password must fail
	if _, err := LoadCAFromPEMWithPassword(certPEM, []byte(testPBES2EncryptedKeyPEM), "wrongpassword"); err == nil {
		t.Error("Expected error for wrong password, got none")
	}
}

func TestLoadCAFromPEM(t *testing.T) {
	// Create a test CA certificate and key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	tests := []struct {
		name      string
		certPEM   []byte
		keyPEM    []byte
		password  string
		expectErr bool
	}{
		{
			name:      "valid_unencrypted_key",
			certPEM:   certPEM,
			keyPEM:    keyPEM,
			password:  "",
			expectErr: false,
		},
		{
			name:      "invalid_cert_pem",
			certPEM:   []byte("invalid pem"),
			keyPEM:    keyPEM,
			password:  "",
			expectErr: true,
		},
		{
			name:      "invalid_key_pem",
			certPEM:   certPEM,
			keyPEM:    []byte("invalid pem"),
			password:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caInfo, err := LoadCAFromPEMWithPassword(tt.certPEM, tt.keyPEM, tt.password)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if caInfo.Certificate.Subject.CommonName != "Test CA" {
				t.Errorf("Expected CN 'Test CA', got %s", caInfo.Certificate.Subject.CommonName)
			}

			if !caInfo.Certificate.IsCA {
				t.Error("Expected certificate to be marked as CA")
			}
		})
	}
}

func TestGenerateCAWithKeySettingsEllipticCurve(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	caInfo, err := cm.GenerateCAWithKeySettings(
		"CN=EC Test CA,O=Test Org,C=US",
		2048,
		365,
		"ec-test-ca",
		"none",
		"",
		KeyGenSettings{UseEllipticCurves: true, EllipticCurve: "P-384"},
	)
	if err != nil {
		t.Fatalf("GenerateCAWithKeySettings() error = %v", err)
	}

	ecKey, ok := caInfo.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected ECDSA private key, got %T", caInfo.PrivateKey)
	}
	if ecKey.Curve != elliptic.P384() {
		t.Errorf("Expected P-384 curve, got %s", ecKey.Curve.Params().Name)
	}

	// Verify the certificate itself reports an EC public key on P-384
	block, _ := pem.Decode(caInfo.CertPEM)
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	pub, ok := parsedCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected certificate public key to be ECDSA, got %T", parsedCert.PublicKey)
	}
	if pub.Curve != elliptic.P384() {
		t.Errorf("Expected certificate public key curve P-384, got %s", pub.Curve.Params().Name)
	}
}

func TestGenerateCAWithKeySettingsDefaultsToRSA(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	// Zero-value KeyGenSettings (UseEllipticCurves: false) must preserve
	// existing RSA behavior for backward compatibility.
	caInfo, err := cm.GenerateCAWithKeySettings(
		"CN=RSA Test CA,O=Test Org,C=US",
		2048,
		365,
		"rsa-test-ca",
		"none",
		"",
		KeyGenSettings{},
	)
	if err != nil {
		t.Fatalf("GenerateCAWithKeySettings() error = %v", err)
	}

	if _, ok := caInfo.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("Expected RSA private key when UseEllipticCurves is false, got %T", caInfo.PrivateKey)
	}
}

func TestGenerateCAEncryptedECKeyRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	password := "super-secret-passw0rd"
	caInfo, err := cm.GenerateCAWithKeySettings(
		"CN=EC Encrypted CA,O=Test Org,C=US",
		2048,
		365,
		"ec-encrypted-ca",
		password,
		"",
		KeyGenSettings{UseEllipticCurves: true, EllipticCurve: "P-384"},
	)
	if err != nil {
		t.Fatalf("GenerateCAWithKeySettings() error = %v", err)
	}
	if caInfo.Password != password {
		t.Fatalf("Expected password %q, got %q", password, caInfo.Password)
	}

	// Confirm the key was actually encrypted
	block, _ := pem.Decode(caInfo.KeyPEM)
	if block == nil {
		t.Fatal("Failed to decode key PEM")
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("Expected ENCRYPTED PRIVATE KEY block, got %s", block.Type)
	}

	// Round-trip: load the CA back using the password and verify it's
	// still a usable ECDSA key that can sign a certificate.
	loadedCA, err := LoadCAFromPEMWithPassword(caInfo.CertPEM, caInfo.KeyPEM, password)
	if err != nil {
		t.Fatalf("LoadCAFromPEMWithPassword() error = %v", err)
	}

	loadedECKey, ok := loadedCA.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected loaded private key to be ECDSA, got %T", loadedCA.PrivateKey)
	}
	if loadedECKey.Curve != elliptic.P384() {
		t.Errorf("Expected loaded key curve P-384, got %s", loadedECKey.Curve.Params().Name)
	}

	// Use the loaded CA to sign a node certificate, proving the key is functional.
	err = cm.GenerateNodeCertificateWithKeySettings(
		loadedCA,
		"CN=ec-node.example.com,O=Test Org,C=US",
		[]string{"ec-node.example.com"},
		[]string{"127.0.0.1"},
		365,
		"ec-node-from-loaded-ca",
		"none",
		"",
		KeyGenSettings{UseEllipticCurves: true, EllipticCurve: "P-384"},
	)
	if err != nil {
		t.Fatalf("GenerateNodeCertificateWithKeySettings() with loaded EC CA error = %v", err)
	}
}

func TestGenerateNodeAndClientCertificatesWithEllipticCurves(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New(false)
	cm := NewCertificateManager(tempDir, 16, log)

	caInfo, err := cm.GenerateCAWithKeySettings(
		"CN=EC Test CA,O=Test Org,C=US",
		2048,
		365,
		"ec-ca-for-leaf",
		"none",
		"",
		KeyGenSettings{UseEllipticCurves: true, EllipticCurve: "P-384"},
	)
	if err != nil {
		t.Fatalf("Failed to create EC CA: %v", err)
	}

	keySettings := KeyGenSettings{UseEllipticCurves: true, EllipticCurve: "P-384"}

	if err := cm.GenerateNodeCertificateWithKeySettings(
		caInfo, "CN=ec-node.example.com,O=Test Org,C=US",
		[]string{"ec-node.example.com"}, []string{"127.0.0.1"},
		365, "ec-node", "none", "", keySettings,
	); err != nil {
		t.Fatalf("GenerateNodeCertificateWithKeySettings() error = %v", err)
	}

	nodeKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "ec-node.key"))
	if err != nil {
		t.Fatalf("Failed to read node key file: %v", err)
	}
	block, _ := pem.Decode(nodeKeyPEM)
	if block == nil {
		t.Fatal("Failed to decode node key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse node private key: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("Expected node private key to be ECDSA, got %T", key)
	}

	if err := cm.GenerateClientCertificateWithKeySettings(
		caInfo, "CN=ec-client,O=Test Org,C=US", 365, "ec-client", "none", keySettings,
	); err != nil {
		t.Fatalf("GenerateClientCertificateWithKeySettings() error = %v", err)
	}

	clientKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "ec-client.key"))
	if err != nil {
		t.Fatalf("Failed to read client key file: %v", err)
	}
	block, _ = pem.Decode(clientKeyPEM)
	if block == nil {
		t.Fatal("Failed to decode client key PEM")
	}
	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse client private key: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("Expected client private key to be ECDSA, got %T", key)
	}
}

func TestCurveByName(t *testing.T) {
	tests := []struct {
		name      string
		curveName string
		expected  elliptic.Curve
		expectErr bool
	}{
		{name: "empty_defaults_to_p384", curveName: "", expected: elliptic.P384()},
		{name: "p224", curveName: "P-224", expected: elliptic.P224()},
		{name: "p256", curveName: "P-256", expected: elliptic.P256()},
		{name: "p384", curveName: "P-384", expected: elliptic.P384()},
		{name: "p521", curveName: "P-521", expected: elliptic.P521()},
		{name: "unsupported", curveName: "secp256k1", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curve, err := curveByName(tt.curveName)
			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if curve != tt.expected {
				t.Errorf("Expected curve %s, got %s", tt.expected.Params().Name, curve.Params().Name)
			}
		})
	}
}

func TestParseOID(t *testing.T) {
	tests := []struct {
		name      string
		oidStr    string
		expected  []int
		expectErr bool
	}{
		{
			name:      "valid_oid",
			oidStr:    "1.2.3.4.5",
			expected:  []int{1, 2, 3, 4, 5},
			expectErr: false,
		},
		{
			name:      "single_component",
			oidStr:    "1",
			expected:  []int{1},
			expectErr: false,
		},
		{
			name:      "invalid_non_numeric",
			oidStr:    "1.2.abc.4",
			expectErr: true,
		},
		{
			name:      "empty_string",
			oidStr:    "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid, err := parseOID(tt.oidStr)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(oid) != len(tt.expected) {
				t.Errorf("Expected %d components, got %d", len(tt.expected), len(oid))
				return
			}

			for i, expected := range tt.expected {
				if oid[i] != expected {
					t.Errorf("Expected component %d to be %d, got %d", i, expected, oid[i])
				}
			}
		})
	}
}
