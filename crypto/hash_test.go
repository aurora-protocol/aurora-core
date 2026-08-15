package auroracrypto

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestPreHashLabelMatchesPreHashOfLabelPlusParts pins the label helper to the
// underlying PreHash of the label bytes followed by the parts.
func TestPreHashLabelMatchesPreHashOfLabelPlusParts(t *testing.T) {
	label := "session transcript"
	parts := [][]byte{[]byte("alpha"), []byte("beta"), bytes.Repeat([]byte{0x9e}, 40)}
	got := PreHashLabel(label, parts...)
	want := PreHash(append([][]byte{[]byte(label)}, parts...)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("PreHashLabel = %x, want %x", got, want)
	}
	if len(got) != 48 {
		t.Fatalf("PreHashLabel length = %d, want 48 (SHA-384)", len(got))
	}
}

// TestSHA256MatchesStdlib verifies the convenience hasher against crypto/sha256.
func TestSHA256MatchesStdlib(t *testing.T) {
	cases := [][]byte{nil, []byte("abc"), bytes.Repeat([]byte{0x41}, 250)}
	for _, in := range cases {
		got := SHA256(in)
		want := sha256.Sum256(in)
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("SHA256(%q) = %x, want %x", in, got, want)
		}
	}
}

// TestTruncate128 covers both branches: the >=16-byte slice (first 16 bytes in
// freshly-owned storage) and the <16-byte slice (zero-padded to 16).
func TestTruncate128(t *testing.T) {
	// >= 16 bytes: first 16 bytes, owned (not aliasing the input).
	long := bytes.Repeat([]byte{0x01}, 32)
	got := Truncate128(long)
	if want := long[:16]; !bytes.Equal(got, want) {
		t.Fatalf("Truncate128(long) = %x, want %x", got, want)
	}
	if len(got) != 16 {
		t.Fatalf("Truncate128 length = %d, want 16", len(got))
	}
	long[0] = 0xff
	if got[0] == 0xff {
		t.Fatal("Truncate128 result aliases input storage")
	}

	// < 16 bytes: zero-padded to 16 with the input copied to the front.
	short := []byte{0xaa, 0xbb, 0xcc}
	got = Truncate128(short)
	want := append(append([]byte{}, short...), make([]byte, 13)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Truncate128(short) = %x, want %x", got, want)
	}

	// empty input: 16 zero bytes.
	if got := Truncate128(nil); !bytes.Equal(got, make([]byte, 16)) {
		t.Fatalf("Truncate128(nil) = %x, want 16 zero bytes", got)
	}
}

// TestSuiteHashLengthMatchesSuiteHashOutput cross-checks the length predictor
// against the actual digest length for every suite, plus explicit per-family
// lengths and the unsupported-suite error.
func TestSuiteHashLengthMatchesSuiteHashOutput(t *testing.T) {
	for _, suite := range appendTestSuites {
		n, err := SuiteHashLength(suite)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		digest, err := SuiteHash(suite, []byte("probe"))
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		if n != len(digest) {
			t.Fatalf("suite 0x%x: SuiteHashLength=%d, len(SuiteHash)=%d", suite, n, len(digest))
		}
	}
	wantLen := map[uint64]int{
		registry.SuiteHybrid768AESGCM:  48,
		registry.SuiteHybrid1024AESGCM: 64,
		registry.SuiteLabClassical:      32,
	}
	for suite, want := range wantLen {
		got, err := SuiteHashLength(suite)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		if got != want {
			t.Fatalf("suite 0x%x: SuiteHashLength=%d, want %d", suite, got, want)
		}
	}
	if _, err := SuiteHashLength(0xdead); err == nil {
		t.Fatal("unsupported suite returned a length")
	}
}

// TestAEADKeyLengthAllSuitesAndUnsupported verifies every production suite uses a
// 32-byte AEAD key and that unsupported suites are rejected.
func TestAEADKeyLengthAllSuitesAndUnsupported(t *testing.T) {
	for _, suite := range appendTestSuites {
		n, err := AEADKeyLength(suite)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		if n != 32 {
			t.Fatalf("suite 0x%x: AEADKeyLength=%d, want 32", suite, n)
		}
	}
	if _, err := AEADKeyLength(0xdead); err == nil {
		t.Fatal("unsupported suite returned a key length")
	}
}