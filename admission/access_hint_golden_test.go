package admission

import (
	"encoding/hex"
	"testing"
)

// TestComputeAccessHintGoldenValue locks the exact 16-byte Truncate128 output
// of ComputeAccessHint for a fixed input. Any change to the HMAC construction
// (label bytes, field ordering, uint64 encoding, sum handling) must preserve
// these bytes exactly. Captured from the canonical implementation before the
// allocation-reduction optimization; the optimized path is byte-identical and
// this test is the regression guard proving it.
func TestComputeAccessHintGoldenValue(t *testing.T) {
	cred := validHintCredential()
	bindingContext := rep(0x70, 48)
	clientNonce := rep(0x71, 32)

	got, err := ComputeAccessHint(cred, bindingContext, clientNonce)
	if err != nil {
		t.Fatalf("ComputeAccessHint: %v", err)
	}
	const wantHex = "af6dff23afa97296a43d95505c0db23a"
	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("ComputeAccessHint golden value changed:\n got %s\nwant %s", gotHex, wantHex)
	}
	if len(got) != 16 {
		t.Fatalf("ComputeAccessHint length = %d, want 16", len(got))
	}
}

// TestComputeSpentHintKeyGoldenValue locks the exact 48-byte PreHash
// (SHA-384) output of ComputeSpentHintKey for a fixed credential. This guards
// the spent-key preimage encoding against accidental reordering or label drift.
func TestComputeSpentHintKeyGoldenValue(t *testing.T) {
	cred := validHintCredential()

	got, err := ComputeSpentHintKey(cred)
	if err != nil {
		t.Fatalf("ComputeSpentHintKey: %v", err)
	}
	const wantHex = "cee3fdf66bb685993b6378a521ff0d776da5a47e0e28f315d568e60d7a8d3fe011caf19bfaefb3d65877498f89e414a4"
	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("ComputeSpentHintKey golden value changed:\n got %s\nwant %s", gotHex, wantHex)
	}
	if len(got) != 48 {
		t.Fatalf("ComputeSpentHintKey length = %d, want 48", len(got))
	}
}