package auroracrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestHMACForSuiteMatchesExpectedHashFamily verifies each suite family routes to
// the expected HMAC hash and produces the matching digest, plus the
// unsupported-suite error.
func TestHMACForSuiteMatchesExpectedHashFamily(t *testing.T) {
	key := []byte("hmac-key")
	msg := []byte("message")
	cases := []struct {
		suite uint64
		newH  func() hash.Hash
	}{
		{registry.SuiteHybrid768AESGCM, sha512.New384},
		{registry.SuiteHybrid1024AESGCM, sha512.New},
		{registry.SuiteLabClassical, sha256.New},
	}
	for _, tc := range cases {
		got, err := HMACForSuite(tc.suite, key, msg)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", tc.suite, err)
		}
		mac := hmac.New(tc.newH, key)
		mac.Write(msg)
		if want := mac.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("suite 0x%x: %x, want %x", tc.suite, got, want)
		}
	}

	// All 768 variants share SHA-384 -> 48-byte tag.
	for _, suite := range []uint64{
		registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM,
		registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20,
	} {
		got, err := HMACForSuite(suite, key, msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 48 {
			t.Fatalf("suite 0x%x: mac len %d, want 48", suite, len(got))
		}
	}

	if _, err := HMACForSuite(0xdead, key, msg); err == nil {
		t.Fatal("unsupported suite produced a MAC")
	}
}
