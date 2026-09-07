package cert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"  // #nosec G502 -- decrypting legacy PBES2 keys that use 3DES-CBC, not producing new ciphertext
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- decrypting legacy PBES2 keys that use PBKDF2-HMAC-SHA1, not producing new signatures
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// pbes2EncryptIterationCount is the PBKDF2 iteration count used when
// encrypting new keys. It matches common OpenSSL/Java defaults for PBES2.
const pbes2EncryptIterationCount = 2048

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

	// oidPBEWithSHA1And3KeyTripleDESCBC is the legacy PKCS#12 PBE scheme
	// (RFC 7292) that Java's SunJCE provider uses by default for PKCS#8
	// private keys, instead of PBES2. Not supported for decryption here
	// (SHA-1 + 3DES), but recognized so we can point the user at a fix.
	oidPBEWithSHA1And3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
)

// pbes2ConversionHelp is appended to the error when a key uses the legacy
// PKCS#12 PBE scheme, explaining how to convert it to standard PBES2 with
// openssl (or the bundled scripts/convert-legacy-ca-key.sh helper).
const pbes2ConversionHelp = `this key is encrypted with the legacy PKCS#12 scheme ` +
	`pbeWithSHA1And3-KeyTripleDES-CBC (SHA-1 + 3DES), commonly produced by Java's ` +
	`SunJCE provider (e.g. the Java Search Guard TLS Tool). This is not supported; ` +
	`convert it to standard PKCS#8 PBES2 first:

  openssl pkcs8 -in old-key.pem -out decrypted-key.pem
  openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in decrypted-key.pem -out new-key.pem
  shred -u decrypted-key.pem

Or run scripts/convert-legacy-ca-key.sh old-key.pem new-key.pem`

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
		if info.Algo.Algorithm.Equal(oidPBEWithSHA1And3KeyTripleDESCBC) {
			return nil, fmt.Errorf("%s", pbes2ConversionHelp)
		}
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

// encryptPKCS8PrivateKeyInfo encrypts DER-encoded PKCS#8 PrivateKeyInfo
// content into a standard PKCS#8 EncryptedPrivateKeyInfo (RFC 5958),
// using PBES2 (RFC 8018) with PBKDF2-HMAC-SHA256 key derivation and
// AES-256-CBC encryption. This matches the format produced by OpenSSL and
// Java tooling, so keys generated here can be read by other standard
// PKCS#8 consumers (e.g. the OpenSearch security plugin).
func encryptPKCS8PrivateKeyInfo(der []byte, password []byte) ([]byte, error) {
	const keyLen = 32 // AES-256

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	key := pbkdf2.Key(password, salt, pbes2EncryptIterationCount, keyLen, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cipher: %w", err)
	}

	padded := padPKCS7(der, block.BlockSize())
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)

	ivParam, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal IV: %w", err)
	}

	kdfParams, err := asn1.Marshal(pbkdf2Params{
		Salt:           salt,
		IterationCount: pbes2EncryptIterationCount,
		KeyLength:      keyLen,
		PRF:            algorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.RawValue{FullBytes: rawNull}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PBKDF2 parameters: %w", err)
	}

	pbes2ParamsDER, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParams},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivParam},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PBES2 parameters: %w", err)
	}

	info := pkcs8EncryptedPrivateKeyInfo{
		Algo: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: pbes2ParamsDER},
		},
		EncryptedData: encrypted,
	}

	out, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EncryptedPrivateKeyInfo: %w", err)
	}

	return out, nil
}

// rawNull is the DER encoding of ASN.1 NULL, used as the (unused)
// parameters field of the HMAC-SHA256 AlgorithmIdentifier.
var rawNull = []byte{0x05, 0x00}

// padPKCS7 applies PKCS#7 padding.
func padPKCS7(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padByte := byte(padLen) // #nosec G115 -- padLen is always in [1, blockSize], well within byte range
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = padByte
	}
	return padded
}

// cipherForScheme returns the required key length and a constructor for the
// block cipher named by the PBES2 encryptionScheme OID.
func cipherForScheme(oid asn1.ObjectIdentifier) (keyLen int, newCipher func([]byte) (cipher.Block, error), err error) {
	switch {
	case oid.Equal(oidAES256CBC):
		return 32, aes.NewCipher, nil
	case oid.Equal(oidAES192CBC):
		return 24, aes.NewCipher, nil
	case oid.Equal(oidAES128CBC):
		return 16, aes.NewCipher, nil
	case oid.Equal(oidDESEDE3CBC):
		return 24, newTripleDESCipher, nil
	default:
		return 0, nil, fmt.Errorf("unsupported PBES2 encryption scheme: %s", oid)
	}
}

// newTripleDESCipher decrypts legacy PBES2 keys encrypted with 3DES-CBC
// (RFC 8018 Appendix B.2.2). 3DES is weak by modern standards but must be
// supported here to read keys produced by older tooling.
func newTripleDESCipher(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key) // #nosec G405 -- decrypting legacy keys, not producing new ciphertext
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
