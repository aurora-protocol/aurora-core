package auroracrypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

// manualExpandLabel reproduces the info construction (uint16 length, opaque8
// "aurora "+label, opaque8 context) used by hkdfExpandLabel and expands it, so
// the suite dispatch can be cross-checked against an independently-built oracle.
func manualExpandLabel(t *testing.T, newHash func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	fullLabel := []byte("aurora " + label)
	e := wire.NewEncoder()
	e.WriteUint16(uint16(length))
	e.WriteOpaque8(fullLabel)
	e.WriteOpaque8(context)
	info, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	out, err := hkdf.Expand(newHash, secret, string(info), length)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustExtract(t *testing.T, h func() hash.Hash, secret, salt []byte) []byte {
	t.Helper()
	out, err := hkdf.Extract(h, secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHKDFExtractSHA256MatchesStdlib pins the SHA-256 extract to crypto/hkdf.
func TestHKDFExtractSHA256MatchesStdlib(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	got, err := HKDFExtractSHA256(secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("HKDFExtractSHA256 = %x, want %x", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("HKDFExtractSHA256 length = %d, want 32", len(got))
	}
}

// TestHKDFExtractForSuiteDispatch verifies each suite family routes to the
// expected hash and that unsupported suites are rejected.
func TestHKDFExtractForSuiteDispatch(t *testing.T) {
	secret := []byte("ikm")
	salt := []byte("salt")
	cases := []struct {
		suite uint64
		want  []byte
	}{
		{registry.SuiteHybrid768AESGCM, mustExtract(t, sha512.New384, secret, salt)},
		{registry.SuiteHybrid1024AESGCM, mustExtract(t, sha512.New, secret, salt)},
		{registry.SuiteLabClassical, mustExtract(t, sha256.New, secret, salt)},
	}
	for _, tc := range cases {
		got, err := HKDFExtractForSuite(tc.suite, secret, salt)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", tc.suite, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("suite 0x%x: %x, want %x", tc.suite, got, tc.want)
		}
	}
	if _, err := HKDFExtractForSuite(0xdead, secret, salt); err == nil {
		t.Fatal("unsupported suite extracted a PRK")
	}
}

// TestHKDFExpandLabelSHA256MatchesManualOracle pins the SHA-256 expand-label to
// an independently-built info buffer and asserts the length is honored.
func TestHKDFExpandLabelSHA256MatchesManualOracle(t *testing.T) {
	secret := []byte("prk")
	got, err := HKDFExpandLabelSHA256(secret, "derived", []byte("ctx"), 40)
	if err != nil {
		t.Fatal(err)
	}
	want := manualExpandLabel(t, sha256.New, secret, "derived", []byte("ctx"), 40)
	if !bytes.Equal(got, want) {
		t.Fatalf("HKDFExpandLabelSHA256 = %x, want %x", got, want)
	}
	if len(got) != 40 {
		t.Fatalf("HKDFExpandLabelSHA256 length = %d, want 40", len(got))
	}
}

// TestHKDFExpandLabelForSuiteDispatch verifies suite routing to the SHA-384 /
// SHA-512 / SHA-256 expand-label implementations.
func TestHKDFExpandLabelForSuiteDispatch(t *testing.T) {
	secret := []byte("prk")
	label := "traffic"
	ctx := []byte("rover")

	// 768 suites route to SHA-384.
	got, err := HKDFExpandLabelForSuite(registry.SuiteHybrid768AESGCM, secret, label, ctx, 48)
	if err != nil {
		t.Fatal(err)
	}
	want, err := HKDFExpandLabelSHA384(secret, label, ctx, 48)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("768 suite did not route to SHA-384 expand-label")
	}

	// 1024 suites route to SHA-512 (manual oracle).
	got, err = HKDFExpandLabelForSuite(registry.SuiteHybrid1024AESGCM, secret, label, ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	if want := manualExpandLabel(t, sha512.New, secret, label, ctx, 64); !bytes.Equal(got, want) {
		t.Fatal("1024 suite did not route to SHA-512 expand-label")
	}

	// Lab routes to SHA-256.
	got, err = HKDFExpandLabelForSuite(registry.SuiteLabClassical, secret, label, ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	if want, err := HKDFExpandLabelSHA256(secret, label, ctx, 32); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(got, want) {
		t.Fatal("lab suite did not route to SHA-256 expand-label")
	}
}

// TestHKDFExpandLabelRejectsOversizedLabelContextAndUnsupportedSuite covers the
// label/context length guards and the unsupported-suite error. "aurora " (7
// bytes) + label(248) = 255 is allowed; label(249) = 256 is rejected.
func TestHKDFExpandLabelRejectsOversizedLabelContextAndUnsupportedSuite(t *testing.T) {
	secret := []byte("prk")
	if _, err := HKDFExpandLabelSHA256(secret, strings.Repeat("x", 249), nil, 16); err == nil {
		t.Fatal("oversized label accepted")
	}
	if _, err := HKDFExpandLabelSHA256(secret, strings.Repeat("x", 248), nil, 16); err != nil {
		t.Fatalf("248-char label (255 total) should be allowed: %v", err)
	}
	if _, err := HKDFExpandLabelSHA256(secret, "ok", bytes.Repeat([]byte{1}, 256), 16); err == nil {
		t.Fatal("oversized context accepted")
	}
	if _, err := HKDFExpandLabelForSuite(0xdead, secret, "ok", nil, 16); err == nil {
		t.Fatal("unsupported suite accepted")
	}
}
