package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestEncryptPKCS8PrivateKeyInfoRoundTrip(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	password := []byte("testpassword123")

	encryptedDER, err := encryptPKCS8PrivateKeyInfo(keyDER, password)
	if err != nil {
		t.Fatalf("encryptPKCS8PrivateKeyInfo failed: %v", err)
	}

	decryptedDER, err := decryptPKCS8EncryptedPrivateKeyInfo(encryptedDER, password)
	if err != nil {
		t.Fatalf("failed to decrypt round-tripped key: %v", err)
	}

	if _, err := x509.ParsePKCS8PrivateKey(decryptedDER); err != nil {
		t.Fatalf("decrypted key is not valid PKCS8: %v", err)
	}

	if _, err := decryptPKCS8EncryptedPrivateKeyInfo(encryptedDER, []byte("wrongpassword")); err == nil {
		t.Error("Expected error for wrong password, got none")
	}
}
