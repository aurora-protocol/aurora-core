package auroracrypto

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestMLKEMCiphertextSizeForSuite covers the suite-to-ciphertext-size mapping
// and the unsupported-suite error.
func TestMLKEMCiphertextSizeForSuite(t *testing.T) {
	want := map[uint64]int{
		registry.SuiteHybrid768AESGCM:  mlkem.CiphertextSize768,
		registry.SuiteHybrid1024AESGCM: mlkem.CiphertextSize1024,
	}
	for suite, w := range want {
		got, err := MLKEMCiphertextSizeForSuite(suite)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		if got != w {
			t.Fatalf("suite 0x%x: %d, want %d", suite, got, w)
		}
	}
	if _, err := MLKEMCiphertextSizeForSuite(registry.SuiteLabClassical); err == nil {
		t.Fatal("lab suite returned a ciphertext size")
	}
}

// TestValidateMLKEMCiphertextForSuite covers the length check against a real
// ciphertext, wrong-length rejection, and the unsupported-suite error.
func TestValidateMLKEMCiphertextForSuite(t *testing.T) {
	suite := registry.SuiteHybrid768AESGCM
	key, err := GenerateMLKEMForSuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	_, ciphertext, err := EncapsulateMLKEMForSuite(suite, key.EncapsulationKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMLKEMCiphertextForSuite(suite, ciphertext); err != nil {
		t.Fatalf("valid ciphertext rejected: %v", err)
	}
	if err := ValidateMLKEMCiphertextForSuite(suite, []byte{1}); err == nil {
		t.Fatal("wrong-length ciphertext accepted")
	}
	if err := ValidateMLKEMCiphertextForSuite(registry.SuiteLabClassical, ciphertext); err == nil {
		t.Fatal("lab suite accepted a ciphertext")
	}
}

// TestValidateMLKEMEncapsulationKeyForSuite covers the valid key, the suite
// mismatch (768 key presented to 1024), malformed input, and unsupported suite.
func TestValidateMLKEMEncapsulationKeyForSuite(t *testing.T) {
	suite := registry.SuiteHybrid768AESGCM
	key, err := GenerateMLKEMForSuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pub := key.EncapsulationKeyBytes()

	if err := ValidateMLKEMEncapsulationKeyForSuite(suite, pub); err != nil {
		t.Fatalf("valid encapsulation key rejected: %v", err)
	}
	if err := ValidateMLKEMEncapsulationKeyForSuite(registry.SuiteHybrid1024AESGCM, pub); err == nil {
		t.Fatal("768 key accepted under the 1024 suite")
	}
	if err := ValidateMLKEMEncapsulationKeyForSuite(suite, []byte{1}); err == nil {
		t.Fatal("malformed encapsulation key accepted")
	}
	if err := ValidateMLKEMEncapsulationKeyForSuite(registry.SuiteLabClassical, pub); err == nil {
		t.Fatal("lab suite accepted an encapsulation key")
	}
}

// TestNewMLKEM768DecapsulationKey covers the 64-byte seed constructor success and
// the wrong-length-seed rejection.
func TestNewMLKEM768DecapsulationKey(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 64)
	k, err := NewMLKEM768DecapsulationKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if k == nil {
		t.Fatal("nil key for valid seed")
	}
	if _, err := NewMLKEM768DecapsulationKey([]byte{1, 2, 3}); err == nil {
		t.Fatal("wrong-length seed accepted")
	}
}
