package main

// Adversarial white-box coverage for the count-0 parse-error guards of
// parseProvisioningWalletState (cmd/aurorac/wallet_state.go:37). The pure parse
// function validates, in order: time (:38), size (:41), format varint (:46),
// source-digest (:54, provisioning format only), unknown format (:61), entry
// count (:65), per-entry read/expiry (:73), canonical ordering (:77), and
// trailing-bytes/!EOF (:85). Existing tests only exercise the happy path
// (Encode round-trip) and one MIS-CONSTRUCTED non-canonical case
// (TestProvisioningWalletStateRejectsNonCanonicalEntries at :45 writes
// provisioningWalletStateFormat WITHOUT the source digest, so the parser
// misaligns on the 32-byte digest read and trips :65, never reaching :77) — so
// all nine error bodies below are COUNT 0 on main.
//
// Coverage targets (baseline measured on main; all bodies COUNT 0):
//   - wallet_state.go:38.36,40.3 0  — invalid time ("requires a valid time")
//   - wallet_state.go:41.77,43.3 0  — invalid size ("size is invalid")
//   - wallet_state.go:46.25,48.3 0  — format varint read err ("malformed wallet state")
//   - wallet_state.go:54.26,57.4 0  — source-digest read err ("malformed wallet state source digest")
//   - wallet_state.go:61.10,62.68 0 — unsupported format ("unsupported wallet state format")
//   - wallet_state.go:65.74,67.3 0  — entry count invalid ("entry count is invalid")
//   - wallet_state.go:73.62,76.4 0  — entry read err / expiry==0 ("malformed wallet state entry")
//   - wallet_state.go:77.59,80.4 0  — non-canonical ordering ("entries are not canonical")
//   - wallet_state.go:85.42,87.3 0  — trailing bytes / !EOF ("malformed wallet state")
//
// Each subtest builds a buffer with wire.NewEncoder (the same encoder
// parseProvisioningWalletState's Encode() uses) and perturbs exactly one field so
// the target guard is the FIRST to fail — every buffer uses
// legacyProvisioningWalletStateFormat (1, no source-digest) except the :54
// subtest which deliberately uses provisioningWalletStateFormat (2) with a
// too-short digest. Error strings are asserted per subtest so a mis-built buffer
// that trips the wrong guard fails the test (self-validating); the per-line
// coverage flip is the rigorous proof.
//
// parseProvisioningWalletState is unexported, so this is an in-package
// (package main) test. No filesystem, no store, no goroutines. One TestXxx with
// nine t.Run subtests; references wire.NewEncoder + in-package constants + stdlib
// bytes/strings/testing/time -> no U1000 surface.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/wire"
)

// validWalletTime is a non-zero, non-negative time that passes the :38 guard.
func validWalletTime() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

// walletKey returns a fixed-length (48-byte) spent-hint key filled with b.
func walletKey(b byte) []byte { return bytes.Repeat([]byte{b}, provisioningWalletSpentHintKeyBytes) }

// legacyWalletHeader writes the legacy-format header (format=1, no digest) and
// the given entry count. Used by every subtest that needs to reach past :61.
func legacyWalletHeader(count uint64) []byte {
	encoder := wire.NewEncoder()
	encoder.WriteVarint(legacyProvisioningWalletStateFormat)
	encoder.WriteVarint(count)
	encoded, err := encoder.Bytes()
	if err != nil {
		panic(err)
	}
	return encoded
}

// appendWalletEntry appends one fixed-width entry (48-byte key + 8-byte expiry)
// to encoded. Mirrors Encode()'s per-entry writes.
func appendWalletEntry(encoded []byte, key []byte, expiry uint64) []byte {
	encoder := wire.NewEncoder()
	encoder.WriteOpaqueFixed(key, provisioningWalletSpentHintKeyBytes)
	encoder.WriteUint64(expiry)
	entry, err := encoder.Bytes()
	if err != nil {
		panic(err)
	}
	return append(encoded, entry...)
}

func TestParseProvisioningWalletStateRejectsMalformedInput(t *testing.T) {
	now := validWalletTime()

	// :38 — a zero time fails the very first check before encoded is read.
	t.Run("invalid time", func(t *testing.T) {
		if _, err := parseProvisioningWalletState([]byte{0x01}, time.Time{}); err == nil || !strings.Contains(err.Error(), "requires a valid time") {
			t.Fatalf("err = %v, want non-nil containing \"requires a valid time\" (:38)", err)
		}
	})

	// :41 — a valid time but empty encoded fails the size check.
	t.Run("invalid size", func(t *testing.T) {
		if _, err := parseProvisioningWalletState(nil, now); err == nil || !strings.Contains(err.Error(), "size is invalid") {
			t.Fatalf("err = %v, want non-nil containing \"size is invalid\" (:41)", err)
		}
	})

	// :46 — a single 0x80 byte is an incomplete varint (continuation bit set,
	// no following byte), so ReadVarint errors before the format switch.
	t.Run("format varint read err", func(t *testing.T) {
		if _, err := parseProvisioningWalletState([]byte{0x80}, now); err == nil || !strings.Contains(err.Error(), "malformed wallet state") {
			t.Fatalf("err = %v, want non-nil containing \"malformed wallet state\" (:46)", err)
		}
	})

	// :54 — provisioning format (2) but only one byte follows, so the 32-byte
	// source-digest read errors.
	t.Run("source digest read err", func(t *testing.T) {
		encoder := wire.NewEncoder()
		encoder.WriteVarint(provisioningWalletStateFormat)
		encoded, err := encoder.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, 0x01) // 1 byte < 32-byte digest
		if _, err := parseProvisioningWalletState(encoded, now); err == nil || !strings.Contains(err.Error(), "source digest") {
			t.Fatalf("err = %v, want non-nil containing \"source digest\" (:54)", err)
		}
	})

	// :61 — an unknown format varint falls through the switch's default.
	t.Run("unsupported format", func(t *testing.T) {
		encoder := wire.NewEncoder()
		encoder.WriteVarint(999) // neither legacy(1) nor provisioning(2)
		encoded, err := encoder.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseProvisioningWalletState(encoded, now); err == nil || !strings.Contains(err.Error(), "unsupported wallet state format") {
			t.Fatalf("err = %v, want non-nil containing \"unsupported wallet state format\" (:61)", err)
		}
	})

	// :65 — legacy format with a count exceeding the maximum (65536).
	t.Run("entry count invalid", func(t *testing.T) {
		encoder := wire.NewEncoder()
		encoder.WriteVarint(legacyProvisioningWalletStateFormat)
		encoder.WriteVarint(maximumProvisioningWalletStateEntries + 1)
		encoded, err := encoder.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseProvisioningWalletState(encoded, now); err == nil || !strings.Contains(err.Error(), "entry count is invalid") {
			t.Fatalf("err = %v, want non-nil containing \"entry count is invalid\" (:65)", err)
		}
	})

	// :73 — one well-formed key followed by a zero expiry (expiry==0 is rejected
	// before the canonical-order check).
	t.Run("entry expiry zero", func(t *testing.T) {
		encoded := appendWalletEntry(legacyWalletHeader(1), walletKey(0x01), 0)
		if _, err := parseProvisioningWalletState(encoded, now); err == nil || !strings.Contains(err.Error(), "malformed wallet state entry") {
			t.Fatalf("err = %v, want non-nil containing \"malformed wallet state entry\" (:73)", err)
		}
	})

	// :77 — two entries in non-canonical order: key 0xFF... precedes key 0x11...
	// (bytes.Compare(previous, key) >= 0). Uses legacy format so no digest is
	// read; this is the case the existing :45 test failed to reach (it used
	// provisioning format without a digest and misaligned on the digest read).
	t.Run("non canonical entries", func(t *testing.T) {
		encoded := legacyWalletHeader(2)
		encoded = appendWalletEntry(encoded, walletKey(0xFF), uint64(now.Add(time.Hour).Unix()))
		encoded = appendWalletEntry(encoded, walletKey(0x11), uint64(now.Add(time.Hour).Unix()))
		if _, err := parseProvisioningWalletState(encoded, now); err == nil || !strings.Contains(err.Error(), "not canonical") {
			t.Fatalf("err = %v, want non-nil containing \"not canonical\" (:77)", err)
		}
	})

	// :85 — one fully-valid entry followed by a trailing byte, so the reader is
	// not at EOF after the loop.
	t.Run("trailing bytes", func(t *testing.T) {
		encoded := appendWalletEntry(legacyWalletHeader(1), walletKey(0x01), uint64(now.Add(time.Hour).Unix()))
		encoded = append(encoded, 0xFF) // one trailing byte -> !EOF
		if _, err := parseProvisioningWalletState(encoded, now); err == nil || !strings.Contains(err.Error(), "malformed wallet state") {
			t.Fatalf("err = %v, want non-nil containing \"malformed wallet state\" (:85)", err)
		}
	})
}
