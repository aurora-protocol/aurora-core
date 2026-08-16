package protocol

// Adversarial coverage for the Critical==true branch of Extension.EncodeTo
// (protocol/types.go line 17/18).
//
// Every existing test encodes extensions with Critical == false, so the
// branch that writes the critical flag byte 0x01 is never exercised. It is
// live, reachable production code: EncodeExtensions calls EncodeTo for each
// extension, and ValidateExtensions treats critical extensions specially
// (rejecting unknown ones), so a Critical==true extension is a real wire shape,
// not a dead defensive branch.
//
// This file encodes a critical extension, asserts the flag byte is 0x01
// (against a non-critical anchor that writes 0x00), and round-trips the whole
// extension through DecodeExtension to confirm the type, flag, and body all
// survive the codec. The single residual count-0 in types.go is this branch;
// covering it takes types.go to 100% and EncodeTo to 100%.
//
// No dead-by-design. No new package-level helpers → nothing for staticcheck
// U1000. No crypto, no context, no goroutines, no real network or filesystem.

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/wire"
)

func TestExtensionEncodeCriticalFlag(t *testing.T) {
	const extType = 0x07
	body := []byte{0xAA, 0xBB, 0xCC}

	// Critical extension: the flag byte after the type varint must be 0x01.
	enc := wire.NewEncoder()
	(Extension{ExtensionType: extType, Critical: true, Body: body}).EncodeTo(enc)
	got, err := enc.Bytes()
	if err != nil {
		t.Fatalf("encode critical: %v", err)
	}
	// Layout: varint(type) | flag | opaque24(body). type 0x07 is a 1-byte
	// varint, so the flag sits at index 1.
	if len(got) < 2 {
		t.Fatalf("critical encoding too short: % x", got)
	}
	if got[1] != 0x01 {
		t.Fatalf("critical flag byte = %x, want 0x01 (full=% x)", got[1], got)
	}
	// Round-trip: DecodeExtension must recover the type, Critical == true,
	// and the body.
	decoded := DecodeExtension(wire.NewReader(got))
	if decoded.ExtensionType != extType {
		t.Fatalf("decoded ExtensionType = %#x, want %#x", decoded.ExtensionType, extType)
	}
	if !decoded.Critical {
		t.Fatalf("decoded Critical = false, want true")
	}
	if !bytes.Equal(decoded.Body, body) {
		t.Fatalf("decoded Body = %x, want %x", decoded.Body, body)
	}

	// Anchor: a non-critical extension with the same type and body writes 0x00
	// for the flag, proving the 0x01 above is the Critical==true branch and not
	// an artifact of the body or type.
	enc2 := wire.NewEncoder()
	(Extension{ExtensionType: extType, Critical: false, Body: body}).EncodeTo(enc2)
	got2, err := enc2.Bytes()
	if err != nil {
		t.Fatalf("encode non-critical: %v", err)
	}
	if len(got2) < 2 || got2[1] != 0x00 {
		t.Fatalf("non-critical flag byte = % x, want 0x00 (full=% x)", got2[1], got2)
	}
}
