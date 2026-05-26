package auroracrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"golang.org/x/crypto/chacha20poly1305"
)

func SealForSuite(suite uint64, key, nonce, aad, plaintext []byte) ([]byte, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid1024AESGCM:
		return AES256GCMSeal(key, nonce, aad, plaintext)
	case registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20, registry.SuiteHybrid1024ChaCha20, registry.SuiteLabClassical:
		return ChaCha20Poly1305Seal(key, nonce, aad, plaintext)
	default:
		return nil, fmt.Errorf("crypto: unsupported AEAD suite 0x%x", suite)
	}
}

func OpenForSuite(suite uint64, key, nonce, aad, ciphertextAndTag []byte) ([]byte, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid1024AESGCM:
		return AES256GCMOpen(key, nonce, aad, ciphertextAndTag)
	case registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20, registry.SuiteHybrid1024ChaCha20, registry.SuiteLabClassical:
		return ChaCha20Poly1305Open(key, nonce, aad, ciphertextAndTag)
	default:
		return nil, fmt.Errorf("crypto: unsupported AEAD suite 0x%x", suite)
	}
}

func AES256GCMSeal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	a, err := aes256gcm(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("crypto: AES-GCM nonce length %d, want %d", len(nonce), a.NonceSize())
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

func AES256GCMOpen(key, nonce, aad, ciphertextAndTag []byte) ([]byte, error) {
	a, err := aes256gcm(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("crypto: AES-GCM nonce length %d, want %d", len(nonce), a.NonceSize())
	}
	return a.Open(nil, nonce, ciphertextAndTag, aad)
}

func ChaCha20Poly1305Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("crypto: ChaCha20-Poly1305 nonce length %d, want %d", len(nonce), a.NonceSize())
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

func ChaCha20Poly1305Open(key, nonce, aad, ciphertextAndTag []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("crypto: ChaCha20-Poly1305 nonce length %d, want %d", len(nonce), a.NonceSize())
	}
	return a.Open(nil, nonce, ciphertextAndTag, aad)
}

func aes256gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: AES-256 key length %d, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func XORNonce96(staticIV []byte, n uint64) ([]byte, error) {
	if len(staticIV) != 12 {
		return nil, fmt.Errorf("crypto: static IV length %d, want 12", len(staticIV))
	}
	out := make([]byte, 12)
	copy(out, staticIV)
	for i := 0; i < 8; i++ {
		out[11-i] ^= byte(n >> (8 * i))
	}
	return out, nil
}
