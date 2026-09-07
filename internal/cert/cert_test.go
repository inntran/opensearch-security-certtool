package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
