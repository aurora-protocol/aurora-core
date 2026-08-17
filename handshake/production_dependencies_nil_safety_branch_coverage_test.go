package handshake

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards on the ML-DSA-65 transcript signer in
// handshake/production_dependencies.go. Each guard exists so a caller that
// passes a nil private key — or holds a nil *mldsa65TranscriptSigner — does not
// panic or proceed into the crypto path: the function returns at its very first
// statement, before any field is dereferenced (s.public.SignatureScheme,
// s.public.PublicKey) or any crypto operation runs (private.MarshalBinary,
// UnmarshalBinary, Public()). The existing handshake tests only ever drive a
// populated ML-DSA-65 signer along the live handshake path (the ECDSA-P256
// sibling constructors/receivers are already covered), so the ML-DSA-65 nil
// guards stayed count-0 even though each is plainly reachable.
//
//   - :240 NewMLDSA65TranscriptSigner(private *mldsa65.PrivateKey)
//     private == nil -> (nil, "handshake: ML-DSA-65 transcript private key is
//     invalid") (the private==nil guard fires before MarshalBinary / the
//     owned-private parse / Public() extraction; no crypto actually runs)
//   - :267 (*mldsa65TranscriptSigner).PublicKey()
//     s == nil -> protocol.PublicKeyRecord{} (the zero record, distinct from a
//     populated signer whose PublicKey slice is non-nil)
//
// These are nil-ARGUMENT / nil-RECEIVER first-statement guards. Neither takes a
// context (PublicKey takes none; the constructor takes only the private key), so
// there is no SA1012 surface. No network, no goroutine — the nil guard returns
// before any crypto runs. The test is in-package (package handshake) because
// mldsa65TranscriptSigner is unexported (NewMLDSA65TranscriptSigner is exported
// but its nil path is exercised here alongside the unexported receiver).
//
// This test file adds only TestXxx entry points and uses existing
// exported/unexported in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestNewMLDSA65TranscriptSignerNilArgumentGuard(t *testing.T) {
	// 240: NewMLDSA65TranscriptSigner(nil) returns the invalid-key error and a
	// nil signer. The private==nil guard fires before MarshalBinary, so no
	// crypto operation runs.
	signer, err := NewMLDSA65TranscriptSigner(nil)
	if err == nil {
		t.Fatal("NewMLDSA65TranscriptSigner(nil) err = nil, want non-nil (:240 should reject)")
	} else if !strings.Contains(err.Error(), "ML-DSA-65 transcript private key is invalid") {
		t.Fatalf("NewMLDSA65TranscriptSigner(nil) err = %q, want substring \"ML-DSA-65 transcript private key is invalid\" (:240)", err.Error())
	}
	if signer != nil {
		t.Fatalf("NewMLDSA65TranscriptSigner(nil) signer = %v, want nil (:240)", signer)
	}
}

func TestMLDSA65TranscriptSignerNilReceiverGuard(t *testing.T) {
	// 267: a nil *mldsa65TranscriptSigner returns the zero PublicKeyRecord at
	// the first statement, rather than dereferencing s.public. A populated
	// signer would return a record whose PublicKey slice is non-nil, so a
	// nil PublicKey slice distinguishes the zero record from a real one.
	var s *mldsa65TranscriptSigner
	record := s.PublicKey()
	if record.PublicKey != nil {
		t.Fatalf("nil.PublicKey() = %+v, want zero protocol.PublicKeyRecord{} (nil PublicKey slice) (:267)", record)
	}
}
