package handshake

// Adversarial coverage for handshake/control.go. Every branch exercised here
// is genuinely reachable: the Seal*/Open* capsules do not pre-validate the
// caller-supplied plain, the control AAD/nonce helpers surface ctx errors, and
// the decode* helpers reject truncated or trailing wire bytes. None of these
// paths are dead-by-design.

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// overlongOpaque is longer than the 65535-byte WriteOpaque16 limit, so encoding
// a field carrying it fails. Used to drive the Seal* Encode-error branches for
// capsule types that have no AdmissionProof (Cover/Route Capsule2).
const overlongOpaque = 70000

// TestSealCapsulesRejectMalformedPlaintextEncoding covers the four
// `if err != nil { return nil, err }` branches that follow protocol.Encode in
// each Seal* function. Each capsule is fed a structurally-invalid plain whose
// fixed-length field (AdmissionProof.TokenNonce for Capsule1, ServerFinished
// length for Capsule2) trips WriteOpaqueFixed/WriteOpaque16 inside Encode.
func TestSealCapsulesRejectMalformedPlaintextEncoding(t *testing.T) {
	ctx := controlTestContext()

	t.Run("CoverCapsule1/AdmissionProof", func(t *testing.T) {
		c := sampleControlCapsule1()
		c.AdmissionProof.TokenNonce = repeatedByte(0x05, 31) // want 32
		if _, err := SealCoverCapsule1(ctx, c); err == nil {
			t.Fatal("SealCoverCapsule1 accepted malformed admission proof encoding")
		}
	})

	t.Run("CoverCapsule2/ServerFinishedOverlong", func(t *testing.T) {
		c := protocol.CoverCapsule2Plain{
			PolicyAccept:   samplePolicyAcceptForControl(),
			ServerFinished: bytes.Repeat([]byte("x"), overlongOpaque),
		}
		if _, err := SealCoverCapsule2(ctx, c); err == nil {
			t.Fatal("SealCoverCapsule2 accepted overlong ServerFinished")
		}
	})

	t.Run("RouteCapsule1/AdmissionProof", func(t *testing.T) {
		c := validRouteCapsule1Plain(ctx)
		c.AdmissionProof.TokenNonce = repeatedByte(0x05, 31) // want 32
		if _, err := SealRouteCapsule1(ctx, c); err == nil {
			t.Fatal("SealRouteCapsule1 accepted malformed admission proof encoding")
		}
	})

	t.Run("RouteCapsule2/ServerFinishedOverlong", func(t *testing.T) {
		c := protocol.RouteCapsule2Plain{
			PolicyAccept:   samplePolicyAcceptForControl(),
			ServerFinished: bytes.Repeat([]byte("x"), overlongOpaque),
		}
		if _, err := SealRouteCapsule2(ctx, c); err == nil {
			t.Fatal("SealRouteCapsule2 accepted overlong ServerFinished")
		}
	})
}

// TestControlCapsuleRejectsUnsupportedSelectedVersion covers the controlAAD
// version-mismatch branch and its propagation through sealControl/openControl.
// The capsule's own Encode succeeds (version is not a capsule field), so the
// error surfaces only when controlAAD inspects ctx.SelectedVersion.
func TestControlCapsuleRejectsUnsupportedSelectedVersion(t *testing.T) {
	ctx := controlTestContext()
	ctx.SelectedVersion = registry.Version20 + 1

	// sealControl path: Encode OK, then controlAAD(ctx) errors.
	if _, err := SealCoverCapsule1(ctx, sampleControlCapsule1()); err == nil {
		t.Fatal("SealCoverCapsule1 accepted unsupported selected version")
	}
	// openControl path: controlAAD errors before any AEAD open.
	if _, err := OpenCoverCapsule1(ctx, []byte{0xff}); err == nil {
		t.Fatal("OpenCoverCapsule1 accepted unsupported selected version")
	} else {
		assertControlFailureKind(t, err, failure.BadAEADTag)
	}
}

// TestControlCapsuleRejectsMalformedHSIVLength covers the XORNonce96 error
// branches in sealControl (client HS IV) and openControl (server HS IV). The
// selected version is valid so controlAAD succeeds and execution reaches the
// nonce derivation.
func TestControlCapsuleRejectsMalformedHSIVLength(t *testing.T) {
	sealCtx := controlTestContext()
	sealCtx.ClientHSIV = repeatedByte(0x42, 11) // want 12
	if _, err := SealCoverCapsule1(sealCtx, sampleControlCapsule1()); err == nil {
		t.Fatal("SealCoverCapsule1 accepted malformed client HS IV length")
	}

	openCtx := controlTestContext()
	openCtx.ServerHSIV = repeatedByte(0x44, 11) // want 12
	if _, err := OpenCoverCapsule2(openCtx, []byte{0xff}); err == nil {
		t.Fatal("OpenCoverCapsule2 accepted malformed server HS IV length")
	} else {
		assertControlFailureKind(t, err, failure.BadAEADTag)
	}
}

// TestOpenRouteCapsule2RejectsCoverCapsule2AEAD covers the OpenRouteCapsule2
// openControl error branch (the only Open* AEAD-open path not already covered
// by the round-trip tests). A CoverCapsule2 is sealed (AAD message type
// MsgCoverCapsule2) and opened as a RouteCapsule2 (AAD message type
// MsgRouteCapsule2); the AAD mismatch fails the AEAD tag.
func TestOpenRouteCapsule2RejectsCoverCapsule2AEAD(t *testing.T) {
	ctx := controlTestContext()
	sealed2, err := SealCoverCapsule2(ctx, protocol.CoverCapsule2Plain{
		PolicyAccept:   samplePolicyAcceptForControl(),
		ServerFinished: repeatedByte(0x71, 48),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRouteCapsule2(ctx, sealed2); err == nil {
		t.Fatal("OpenRouteCapsule2 opened a CoverCapsule2 (wrong AAD message type)")
	} else {
		assertControlFailureKind(t, err, failure.BadAEADTag)
	}
}

// TestOpenCapsulesRejectMalformedPlaintext covers the three remaining
// Open* decode-error propagation branches plus the three uncovered decode*
// r.Err() branches. A truncated plaintext is AEAD-sealed under the correct
// key/AAD so openControl succeeds; the capsule decoder then hits a reader error
// and the Open* wrapper converts it into MalformedCapsule.
func TestOpenCapsulesRejectMalformedPlaintext(t *testing.T) {
	ctx := controlTestContext()
	truncated := []byte{0x01} // decodes MsgType varint, then EOF on RouteInstanceID

	t.Run("RouteCapsule1", func(t *testing.T) {
		sealed, err := sealControl(ctx, registry.MsgRouteCapsule1, ControlDirectionClientToHop, ctx.ClientHSKey, ctx.ClientHSIV, truncated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRouteCapsule1(ctx, sealed); err == nil {
			t.Fatal("OpenRouteCapsule1 accepted malformed plaintext")
		} else {
			assertControlFailureKind(t, err, failure.MalformedCapsule)
		}
	})

	t.Run("RouteCapsule2", func(t *testing.T) {
		sealed, err := sealControl(ctx, registry.MsgRouteCapsule2, ControlDirectionHopToClient, ctx.ServerHSKey, ctx.ServerHSIV, truncated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRouteCapsule2(ctx, sealed); err == nil {
			t.Fatal("OpenRouteCapsule2 accepted malformed plaintext")
		} else {
			assertControlFailureKind(t, err, failure.MalformedCapsule)
		}
	})

	t.Run("CoverCapsule2", func(t *testing.T) {
		sealed, err := sealControl(ctx, registry.MsgCoverCapsule2, ControlDirectionHopToClient, ctx.ServerHSKey, ctx.ServerHSIV, truncated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCoverCapsule2(ctx, sealed); err == nil {
			t.Fatal("OpenCoverCapsule2 accepted malformed plaintext")
		} else {
			assertControlFailureKind(t, err, failure.MalformedCapsule)
		}
	})
}

// TestDecodeCapsulePlainRejectsTrailingBytes covers the four decode* trailing
// branches. Each decoder is fed a complete valid encoding followed by one
// surplus byte; all reads succeed but the reader is not at EOF, so the
// `if !r.EOF()` branch fires.
func TestDecodeCapsulePlainRejectsTrailingBytes(t *testing.T) {
	c1 := sampleControlCapsule1()
	c1.MsgType = registry.MsgCoverCapsule1
	c1.RouteInstanceID = 0
	enc1, err := protocol.Encode(c1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCoverCapsule1Plain(append(enc1, 0xff)); err == nil {
		t.Fatal("decodeCoverCapsule1Plain accepted trailing bytes")
	}

	r1 := validRouteCapsule1Plain(controlTestContext())
	encR1, err := protocol.Encode(r1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRouteCapsule1Plain(append(encR1, 0xff)); err == nil {
		t.Fatal("decodeRouteCapsule1Plain accepted trailing bytes")
	}

	ctx := controlTestContext()
	r2 := protocol.RouteCapsule2Plain{
		PolicyAccept:   samplePolicyAcceptForControl(),
		ServerFinished: repeatedByte(0x95, 48),
	}
	r2.MsgType = registry.MsgRouteCapsule2
	r2.RouteInstanceID = ctx.RouteInstanceID
	r2.HopIndex = ctx.HopIndex
	encR2, err := protocol.Encode(r2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRouteCapsule2Plain(append(encR2, 0xff)); err == nil {
		t.Fatal("decodeRouteCapsule2Plain accepted trailing bytes")
	}

	c2 := protocol.CoverCapsule2Plain{
		PolicyAccept:   samplePolicyAcceptForControl(),
		ServerFinished: repeatedByte(0x71, 48),
	}
	c2.MsgType = registry.MsgCoverCapsule2
	c2.RouteInstanceID = ctx.RouteInstanceID
	encC2, err := protocol.Encode(c2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCoverCapsule2Plain(append(encC2, 0xff)); err == nil {
		t.Fatal("decodeCoverCapsule2Plain accepted trailing bytes")
	}
}

// TestOpenRouteCapsulesRejectPlaintextHeaderMismatch covers the RouteCapsule1
// and RouteCapsule2 plaintext-header mismatch branches. A structurally-valid
// capsule whose RouteInstanceID or HopIndex differs from ctx is sealed under
// ctx's AAD (which binds ctx's values); openControl succeeds, the decoder
// succeeds, and the explicit header-equality check rejects the mismatch.
func TestOpenRouteCapsulesRejectPlaintextHeaderMismatch(t *testing.T) {
	ctx := controlTestContext()
	ctx.HopIndex = 1

	// RouteCapsule1: plaintext RouteInstanceID != ctx.RouteInstanceID.
	r1 := validRouteCapsule1Plain(ctx)
	r1.RouteInstanceID = ctx.RouteInstanceID + 1
	encR1, err := protocol.Encode(r1)
	if err != nil {
		t.Fatal(err)
	}
	sealedR1, err := sealControl(ctx, registry.MsgRouteCapsule1, ControlDirectionClientToHop, ctx.ClientHSKey, ctx.ClientHSIV, encR1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRouteCapsule1(ctx, sealedR1); err == nil {
		t.Fatal("OpenRouteCapsule1 accepted mismatched plaintext RouteInstanceID")
	} else {
		assertControlFailureKind(t, err, failure.MalformedCapsule)
	}

	// RouteCapsule2: plaintext HopIndex != ctx.HopIndex.
	r2 := protocol.RouteCapsule2Plain{
		PolicyAccept:   samplePolicyAcceptForControl(),
		ServerFinished: repeatedByte(0x95, 48),
	}
	r2.MsgType = registry.MsgRouteCapsule2
	r2.RouteInstanceID = ctx.RouteInstanceID
	r2.HopIndex = ctx.HopIndex + 1
	encR2, err := protocol.Encode(r2)
	if err != nil {
		t.Fatal(err)
	}
	sealedR2, err := sealControl(ctx, registry.MsgRouteCapsule2, ControlDirectionHopToClient, ctx.ServerHSKey, ctx.ServerHSIV, encR2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRouteCapsule2(ctx, sealedR2); err == nil {
		t.Fatal("OpenRouteCapsule2 accepted mismatched plaintext HopIndex")
	} else {
		assertControlFailureKind(t, err, failure.MalformedCapsule)
	}
}

// validRouteCapsule1Plain builds a structurally-valid RouteCapsule1Plain whose
// header (MsgType/RouteInstanceID/HopIndex) matches ctx, for use in tests that
// need a clean baseline before malforming one field.
func validRouteCapsule1Plain(ctx ControlCapsuleContext) protocol.RouteCapsule1Plain {
	base := sampleControlCapsule1()
	r := protocol.RouteCapsule1Plain{
		AdmissionProof: base.AdmissionProof,
		ReplayProof:    base.ReplayProof,
		PolicyOffer:    base.PolicyOffer,
		ClientFinished: repeatedByte(0x93, 48),
	}
	r.MsgType = registry.MsgRouteCapsule1
	r.RouteInstanceID = ctx.RouteInstanceID
	r.HopIndex = ctx.HopIndex
	return r
}
