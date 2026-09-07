package cert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// PKCS#5/PKCS#8 OIDs relevant to decrypting an EncryptedPrivateKeyInfo
// (RFC 8018 PBES2/PBKDF2, RFC 8018 Appendix B encryption schemes).
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// pkcs8EncryptedPrivateKeyInfo mirrors the ASN.1 EncryptedPrivateKeyInfo structure
// (RFC 5958): SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }
type pkcs8EncryptedPrivateKeyInfo struct {
	Algo          algorithmIdentifier
	EncryptedData []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                 `asn1:"optional"`
	PRF            algorithmIdentifier `asn1:"optional"`
}

// decryptPKCS8EncryptedPrivateKeyInfo decrypts DER-encoded PKCS#8
// EncryptedPrivateKeyInfo content (RFC 5958). Only PBES2 (RFC 8018) is
// supported: PBKDF2 key derivation with HMAC-SHA1 or HMAC-SHA256, followed
// by AES-CBC or 3DES-CBC decryption. Returns the decrypted PKCS#8
// PrivateKeyInfo DER bytes.
func decryptPKCS8EncryptedPrivateKeyInfo(der []byte, password []byte) ([]byte, error) {
	var info pkcs8EncryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("failed to parse EncryptedPrivateKeyInfo: %w", err)
	}

	if !info.Algo.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported private key encryption algorithm: %s", info.Algo.Algorithm)
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("failed to parse PBES2 parameters: %w", err)
	}

	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported PBES2 key derivation function: %s", params.KeyDerivationFunc.Algorithm)
	}

	var kdfParams pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdfParams); err != nil {
		return nil, fmt.Errorf("failed to parse PBKDF2 parameters: %w", err)
	}

	var newHash func() hash.Hash
	switch {
	case kdfParams.PRF.Algorithm == nil || kdfParams.PRF.Algorithm.Equal(oidHMACWithSHA1):
		newHash = sha1.New
	case kdfParams.PRF.Algorithm.Equal(oidHMACWithSHA256):
		newHash = sha256.New
	default:
		return nil, fmt.Errorf("unsupported PBKDF2 PRF: %s", kdfParams.PRF.Algorithm)
	}

	keyLen, blockCipher, err := cipherForScheme(params.EncryptionScheme.Algorithm)
	if err != nil {
		return nil, err
	}

	iv, err := ivForScheme(params.EncryptionScheme.Algorithm, params.EncryptionScheme.Parameters)
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key(password, kdfParams.Salt, kdfParams.IterationCount, keyLen, newHash)

	block, err := blockCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cipher: %w", err)
	}

	if len(info.EncryptedData)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("encrypted data is not a multiple of the block size")
	}

	decrypted := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, info.EncryptedData)

	return unpadPKCS7(decrypted, block.BlockSize())
}

// cipherForScheme returns the required key length and a constructor for the
// block cipher named by the PBES2 encryptionScheme OID.
func cipherForScheme(oid asn1.ObjectIdentifier) (keyLen int, newCipher func([]byte) (cipher.Block, error), err error) {
	switch {
	case oid.Equal(oidAES256CBC):
		return 32, func(k []byte) (cipher.Block, error) { return aes.NewCipher(k) }, nil
	case oid.Equal(oidAES192CBC):
		return 24, func(k []byte) (cipher.Block, error) { return aes.NewCipher(k) }, nil
	case oid.Equal(oidAES128CBC):
		return 16, func(k []byte) (cipher.Block, error) { return aes.NewCipher(k) }, nil
	case oid.Equal(oidDESEDE3CBC):
		return 24, func(k []byte) (cipher.Block, error) { return des.NewTripleDESCipher(k) }, nil
	default:
		return 0, nil, fmt.Errorf("unsupported PBES2 encryption scheme: %s", oid)
	}
}

// ivForScheme extracts the IV (the encryptionScheme parameters, an OCTET STRING) for CBC modes.
func ivForScheme(oid asn1.ObjectIdentifier, params asn1.RawValue) ([]byte, error) {
	var iv []byte
	if _, err := asn1.Unmarshal(params.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("failed to parse IV for encryption scheme %s: %w", oid, err)
	}
	return iv, nil
}

// unpadPKCS7 removes PKCS#7 padding, validating it. An invalid pad usually
// indicates a wrong password.
func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding (likely incorrect password)")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("invalid padding (likely incorrect password)")
		}
	}
	return data[:len(data)-padLen], nil
}
