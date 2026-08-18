package auroracrypto

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestSuiteAEADOpenRoundTripsAndRejectsTamper covers Open via the Seal/Open
// round-trip and the authentication-failure path for every AEAD family.
func TestSuiteAEADOpenRoundTripsAndRejectsTamper(t *testing.T) {
	suites := []uint64{
		registry.SuiteHybrid768AESGCM,
		registry.SuiteHybrid768ChaCha20,
		registry.SuiteLabClassical,
	}
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 12)
	aad := []byte("aad")
	plaintext := []byte("secret message")
	for _, suite := range suites {
		a, err := NewSuiteAEAD(suite, key)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		ct, err := a.Seal(nonce, aad, plaintext)
		if err != nil {
			t.Fatalf("suite 0x%x seal: %v", suite, err)
		}
		got, err := a.Open(nonce, aad, ct)
		if err != nil {
			t.Fatalf("suite 0x%x open: %v", suite, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("suite 0x%x: round-trip mismatch", suite)
		}
		// tamper -> authentication failure
		bad := append([]byte(nil), ct...)
		bad[0] ^= 0xff
		if _, err := a.Open(nonce, aad, bad); err == nil {
			t.Fatalf("suite 0x%x: tampered ciphertext accepted", suite)
		}
	}
}

// TestSuiteAEADOpenToValidatesNonceAndNilGuard covers the OpenTo nonce-length
// check and the nil-receiver guard.
func TestSuiteAEADOpenToValidatesNonceAndNilGuard(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 12)
	a, err := NewSuiteAEAD(registry.SuiteHybrid768AESGCM, key)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := a.Seal(nonce, nil, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.OpenTo(nil, nonce[:11], nil, ct); err == nil {
		t.Fatal("wrong-length nonce accepted")
	}
	var nilAEAD *SuiteAEAD
	if _, err := nilAEAD.Open(nonce, nil, ct); err == nil {
		t.Fatal("nil AEAD accepted")
	}
}

// TestSuiteAEADOpenToReusesDestinationStorage covers the documented in-place
// decryption path: pass ciphertextAndTag[:0] as dst to reuse its storage.
func TestSuiteAEADOpenToReusesDestinationStorage(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 12)
	a, err := NewSuiteAEAD(registry.SuiteHybrid768AESGCM, key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("reuse me")
	ct, err := a.Seal(nonce, nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.OpenTo(ct[:0], nonce, nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("reuse round-trip mismatch: %x", got)
	}
}

// TestOpenForSuiteRoundTripsAndRejectsUnsupportedSuite covers the suite-level
// seal/open pair and the unsupported-suite error.
func TestOpenForSuiteRoundTripsAndRejectsUnsupportedSuite(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 12)
	aad := []byte("a")
	plaintext := []byte("msg")
	ct, err := SealForSuite(registry.SuiteHybrid1024AESGCM, key, nonce, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenForSuite(registry.SuiteHybrid1024AESGCM, key, nonce, aad, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round-trip mismatch")
	}
	if _, err := OpenForSuite(0xdead, key, nonce, aad, ct); err == nil {
		t.Fatal("unsupported suite opened")
	}
}
