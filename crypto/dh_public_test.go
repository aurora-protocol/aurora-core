package auroracrypto

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestECDHCurveNameForSuite covers the suite-to-curve-name mapping and the
// unsupported-suite error (lab + unknown).
func TestECDHCurveNameForSuite(t *testing.T) {
	cases := []struct {
		suite uint64
		want  string
	}{
		{registry.SuiteHybrid768AESGCM, ECDHCurveX25519},
		{registry.SuiteHybrid768P256AESGCM, ECDHCurveP256},
		{registry.SuiteHybrid1024AESGCM, ECDHCurveP384},
		{registry.SuiteHybrid768ChaCha20, ECDHCurveX25519},
		{registry.SuiteHybrid768P256ChaCha20, ECDHCurveP256},
		{registry.SuiteHybrid1024ChaCha20, ECDHCurveP384},
	}
	for _, tc := range cases {
		got, err := ECDHCurveNameForSuite(tc.suite)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", tc.suite, err)
		}
		if got != tc.want {
			t.Fatalf("suite 0x%x: %s, want %s", tc.suite, got, tc.want)
		}
	}
	if _, err := ECDHCurveNameForSuite(registry.SuiteLabClassical); err == nil {
		t.Fatal("lab suite unexpectedly mapped to an ECDH curve")
	}
}

// TestNewECDHPublicKeyForSuite covers valid construction from a generated key,
// rejection of malformed public keys, and the unsupported-suite error.
func TestNewECDHPublicKeyForSuite(t *testing.T) {
	suite := registry.SuiteHybrid768P256AESGCM
	key, err := GenerateECDHForSuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pub := key.PublicKeyBytes()

	parsed, err := NewECDHPublicKeyForSuite(suite, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Bytes(), pub) {
		t.Fatal("parsed public key bytes differ from source")
	}
	if _, err := NewECDHPublicKeyForSuite(suite, []byte{1, 2, 3}); err == nil {
		t.Fatal("malformed public key accepted")
	}
	if _, err := NewECDHPublicKeyForSuite(registry.SuiteLabClassical, pub); err == nil {
		t.Fatal("lab suite accepted a public key")
	}
}