package auroracrypto

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestECDHForSuiteRoundTripsAllPrototypeCurves(t *testing.T) {
	cases := []struct {
		suite         uint64
		wantCurveName string
		wantPublicLen int
	}{
		{registry.SuiteHybrid768AESGCM, ECDHCurveX25519, 32},
		{registry.SuiteHybrid768P256AESGCM, ECDHCurveP256, 65},
		{registry.SuiteHybrid1024AESGCM, ECDHCurveP384, 97},
		{registry.SuiteHybrid768ChaCha20, ECDHCurveX25519, 32},
		{registry.SuiteHybrid768P256ChaCha20, ECDHCurveP256, 65},
		{registry.SuiteHybrid1024ChaCha20, ECDHCurveP384, 97},
	}
	for _, tc := range cases {
		alice, err := GenerateECDHForSuite(tc.suite)
		if err != nil {
			t.Fatal(err)
		}
		bob, err := GenerateECDHForSuite(tc.suite)
		if err != nil {
			t.Fatal(err)
		}
		if alice.CurveName() != tc.wantCurveName || bob.CurveName() != tc.wantCurveName {
			t.Fatalf("suite 0x%x curve mismatch: %s/%s", tc.suite, alice.CurveName(), bob.CurveName())
		}
		if len(alice.PublicKeyBytes()) != tc.wantPublicLen {
			t.Fatalf("suite 0x%x public key len = %d, want %d", tc.suite, len(alice.PublicKeyBytes()), tc.wantPublicLen)
		}
		aliceSecret, err := alice.SharedSecret(bob.PublicKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		bobSecret, err := bob.SharedSecret(alice.PublicKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		if len(aliceSecret) == 0 || !bytes.Equal(aliceSecret, bobSecret) {
			t.Fatalf("suite 0x%x ECDH secrets did not match", tc.suite)
		}
		restored, err := NewECDHPrivateKeyForSuite(tc.suite, alice.PrivateKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		restoredSecret, err := restored.SharedSecret(bob.PublicKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(restoredSecret, aliceSecret) {
			t.Fatalf("suite 0x%x restored private key changed ECDH secret", tc.suite)
		}
	}
}

func TestECDHRejectsWrongSuiteAndMalformedPublicKey(t *testing.T) {
	if _, err := GenerateECDHForSuite(registry.SuiteLabClassical); err == nil {
		t.Fatalf("lab suite unexpectedly mapped to production ECDH")
	}
	key, err := GenerateECDHForSuite(registry.SuiteHybrid768P256AESGCM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.SharedSecret([]byte{1, 2, 3}); err == nil {
		t.Fatalf("malformed peer public key accepted")
	}
}
