package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestValidateKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{"valid_2048", 2048, false},
		{"valid_4096", 4096, false},
		{"invalid_1024", 1024, true},
		{"invalid_3000", 3000, true}, // Not power of 2
		{"invalid_too_large", 16384, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeySize(tt.keySize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeySize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateValidityPeriod(t *testing.T) {
	tests := []struct {
		name    string
		days    int
		wantErr bool
	}{
		{"valid_365", 365, false},
		{"valid_3650", 3650, false},
		{"invalid_zero", 0, true},
		{"invalid_negative", -1, true},
		{"invalid_too_long", 10000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValidityPeriod(tt.days)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateValidityPeriod() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDN(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{
			name:    "valid_basic_dn",
			dn:      "CN=test.example.com,O=Test Org,C=US",
			wantErr: false,
		},
		{
			name:    "valid_dn_with_escaped_comma",
			dn:      "CN=test.example.com,O=Test\\, Inc.,C=US",
			wantErr: false,
		},
		{
			name:    "valid_dn_with_dc",
			dn:      "CN=test.example.com,DC=example,DC=com",
			wantErr: false,
		},
		{
			name:    "invalid_empty_dn",
			dn:      "",
			wantErr: true,
		},
		{
			name:    "invalid_no_cn",
			dn:      "O=Test Org,C=US",
			wantErr: true,
		},
		{
			name:    "invalid_country_code",
			dn:      "CN=test.example.com,C=USA", // Should be 2 chars
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDN(tt.dn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDN() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid_ipv4", "192.168.1.1", false},
		{"valid_ipv6", "2001:db8::1", false},
		{"valid_localhost", "127.0.0.1", false},
		{"invalid_empty", "", true},
		{"invalid_format", "192.168.1", true},
		{"invalid_text", "not-an-ip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPAddress(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPAddress() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDNSName(t *testing.T) {
	tests := []struct {
		name     string
		dnsName  string
		wantErr  bool
	}{
		{"valid_simple", "example.com", false},
		{"valid_subdomain", "test.example.com", false},
		{"valid_multiple_levels", "api.v1.test.example.com", false},
		{"invalid_empty", "", true},
		{"invalid_too_long", string(make([]byte, 254)), true},
		{"invalid_with_underscore", "test_invalid.com", true},
		{"invalid_start_with_dash", "-invalid.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSName(tt.dnsName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDNSName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateSecurePassword(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{"valid_12", 12, false},
		{"valid_16", 16, false},
		{"valid_32", 32, false},
		{"invalid_too_short", 8, true},
		{"invalid_zero", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := GenerateSecurePassword(tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSecurePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(password) != tt.length {
					t.Errorf("GenerateSecurePassword() length = %d, want %d", len(password), tt.length)
				}

				// Check that password contains different character types
				hasLower := false
				hasUpper := false
				hasDigit := false

				for _, char := range password {
					switch {
					case char >= 'a' && char <= 'z':
						hasLower = true
					case char >= 'A' && char <= 'Z':
						hasUpper = true
					case char >= '0' && char <= '9':
						hasDigit = true
					}
				}

				if !hasLower || !hasUpper || !hasDigit {
					t.Errorf("GenerateSecurePassword() should contain lowercase, uppercase, and digits")
				}
			}
		})
	}
}

func TestValidateCertificate(t *testing.T) {
	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse test certificate: %v", err)
	}

	tests := []struct {
		name    string
		cert    *x509.Certificate
		wantErr bool
	}{
		{
			name:    "valid_certificate",
			cert:    cert,
			wantErr: false,
		},
		{
			name: "expired_certificate",
			cert: func() *x509.Certificate {
				expired := *cert
				expired.NotAfter = time.Now().Add(-1 * time.Hour)
				return &expired
			}(),
			wantErr: true,
		},
		{
			name: "not_yet_valid_certificate",
			cert: func() *x509.Certificate {
				future := *cert
				future.NotBefore = time.Now().Add(1 * time.Hour)
				return &future
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCertificate(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{"equal_bytes", []byte("hello"), []byte("hello"), true},
		{"different_bytes", []byte("hello"), []byte("world"), false},
		{"empty_bytes", []byte{}, []byte{}, true},
		{"different_lengths", []byte("hello"), []byte("hi"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecureCompare(tt.a, tt.b); got != tt.want {
				t.Errorf("SecureCompare() = %v, want %v", got, tt.want)
			}
		})
	}
}
