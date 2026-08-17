package handshake

// Adversarial white-box coverage for the four count-0 guards in the two
// transcript-signer SignTranscript methods in handshake/production_dependencies.go:
//
//	func (s *ecdsaP256TranscriptSigner) SignTranscript(ctx context.Context, transcript []byte) ([]byte, error) {
//	    if ctx == nil { ... }                              // 221 — already covered (nil-context)
//	    if err := ctx.Err(); err != nil { return nil, err } // 224 — count-0 (cancelled ctx)
//	    if s == nil || s.private == nil {                  // 227 — count-0 (nil receiver)
//	        return nil, fmt.Errorf("handshake: P-256 transcript signer is missing")
//	    }
//	    return ecdsa.SignASN1(rand.Reader, s.private, transcript) // crypto, never reached by this test
//	}
//
//	func (s *mldsa65TranscriptSigner) SignTranscript(ctx context.Context, transcript []byte) ([]byte, error) {
//	    if ctx == nil { ... }                              // 278 — already covered (nil-context)
//	    if err := ctx.Err(); err != nil { return nil, err } // 281 — count-0 (cancelled ctx)
//	    if s == nil || s.private == nil {                  // 284 — count-0 (nil receiver)
//	        return nil, fmt.Errorf("handshake: ML-DSA-65 transcript signer is missing")
//	    }
//	    ...
//	    if err := mldsa65.SignTo(...); err != nil { ... }  // 288 — crypto error-propagation, dead-by-design, NOT covered
//	}
//
// The nil-context guards (:221/:278) were covered by an earlier PR; these four
// remained count-0 because the existing signer tests always pass a live context
// to a fully-constructed signer and let it sign, so neither the cancelled-context
// return (:224/:281) nor the nil-receiver return (:227/:284) ran — even though each
// is plainly reachable.
//
// All four are driven on a nil *signer (the types are unexported, so the test is
// in-package) with no crypto executed: the two ctx.Err guards fire before the
// nil-receiver check, and the two nil-receiver guards fire before the crypto call.
// The cancelled contexts come from context.WithCancel+cancel (never a nil-context
// literal, so no SA1012 surface), mirroring the cancelled-context guard covered for
// server.productionFirstHopLimiter.acquire. No network, no goroutine, no crypto.
//
//   - 224/281 (ctx.Err): a nil signer + a cancelled context. :221/:278 (ctx==nil)
//     pass because the context is non-nil; :224/:281 fire because ctx.Err() is
//     non-nil, returning context.Canceled before the nil-receiver check is reached.
//   - 227/284 (nil receiver): a nil signer + a live context. :221/:278 pass,
//     :224/:281 pass (ctx.Err() is nil), then :227/:284 fire because s==nil (the
//     || short-circuits before s.private is read), returning the "missing" sentinel
//     before the crypto path. The different error string (the "missing" sentinel vs
//     context.Canceled) proves each guard ran rather than the other.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEcdsaP256TranscriptSignerRejectsCancelledContext(t *testing.T) {
	// 224: a cancelled context makes ctx.Err() non-nil, so SignTranscript returns
	// context.Canceled before the nil-receiver check at 227. The receiver is nil
	// (the 227 guard would also fire on a nil receiver, but 224 fires first for a
	// cancelled context), so this proves the ctx.Err branch ran.
	var s *ecdsaP256TranscriptSigner
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.SignTranscript(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SignTranscript(cancelled ctx) err = %v, want errors.Is context.Canceled (:224 should propagate the cancelled context)", err)
	}
}

func TestEcdsaP256TranscriptSignerRejectsNilReceiver(t *testing.T) {
	// 227: a nil signer with a live context passes 221 (ctx != nil) and 224
	// (ctx.Err() == nil), then the `s == nil || s.private == nil` guard fires. The
	// || short-circuits on s==nil, so s.private is never read and the call cannot
	// panic; it returns the "missing" sentinel before reaching ecdsa.SignASN1.
	var s *ecdsaP256TranscriptSigner
	_, err := s.SignTranscript(context.Background(), nil)
	if err == nil {
		t.Fatal("nil.SignTranscript(live ctx) err = nil, want non-nil (:227 should return the missing sentinel)")
	}
	if !strings.Contains(err.Error(), "P-256 transcript signer is missing") {
		t.Fatalf("nil.SignTranscript(live ctx) err = %q, want it to contain \"P-256 transcript signer is missing\" (:227)", err.Error())
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("nil.SignTranscript(live ctx) err = %v, must NOT be context.Canceled (the context is live; :224 did not fire)", err)
	}
}

func TestMldsa65TranscriptSignerRejectsCancelledContext(t *testing.T) {
	// 281: the ML-DSA-65 analogue of 224 — a cancelled context returns
	// context.Canceled before the nil-receiver check at 284.
	var s *mldsa65TranscriptSigner
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.SignTranscript(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SignTranscript(cancelled ctx) err = %v, want errors.Is context.Canceled (:281 should propagate the cancelled context)", err)
	}
}

func TestMldsa65TranscriptSignerRejectsNilReceiver(t *testing.T) {
	// 284: the ML-DSA-65 analogue of 227 — a nil signer with a live context returns
	// the "missing" sentinel before reaching mldsa65.SignTo. The contrast with the
	// 281 case (different error string) proves 284 ran rather than 281.
	var s *mldsa65TranscriptSigner
	_, err := s.SignTranscript(context.Background(), nil)
	if err == nil {
		t.Fatal("nil.SignTranscript(live ctx) err = nil, want non-nil (:284 should return the missing sentinel)")
	}
	if !strings.Contains(err.Error(), "ML-DSA-65 transcript signer is missing") {
		t.Fatalf("nil.SignTranscript(live ctx) err = %q, want it to contain \"ML-DSA-65 transcript signer is missing\" (:284)", err.Error())
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("nil.SignTranscript(live ctx) err = %v, must NOT be context.Canceled (the context is live; :281 did not fire)", err)
	}
}
