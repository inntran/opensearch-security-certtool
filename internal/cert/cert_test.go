package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
