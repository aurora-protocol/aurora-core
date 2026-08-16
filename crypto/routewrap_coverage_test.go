package auroracrypto

// Adversarial coverage for the route-prelude wrap helpers in crypto/routewrap.go.
// The happy wrap/derive/seal/open paths are already exercised end-to-end by the
// route package (route/route_test.go, route/route_coverage_test.go build real
// prelude wraps and round-trip them), so the wrap-context/key-iv/AAD/seal/open
// success returns (lines 44, 64, 76, 96, 112) are already covered. The residual
// count-0 blocks are the error-return branches the happy route tests never drive:
// the unsupported-suite guard, the wire-encoder failures, and the composed
// propagation returns.
//
// This file covers them with crafted RouteWrapInput values, perturbing exactly one
// condition per case so the branch under test is the one that fires. Each
// rejection asserts exactly one error substring so the failure is attributable
// to the perturbed field alone.
//
// Uncovered blocks (measured count 0 before this file):
//   - RoutePreludeWrapContext (24): unsupported suite 25, encoder error 41.
//   - RoutePreludeWrapKeyIV (47): context propagation 49, HKDF-extract 53,
//     HKDF-expand key 57, HKDF-expand iv 61.
//   - RouteWrapAAD (67): encoder error 73.
//   - SealRoutePrelude (79): KeyIV propagation 81, AAD error 85, nonce error 89,
//     seal error 93.
//   - OpenRoutePrelude (99): KeyIV propagation 101, AAD error 105, nonce error 109.
//
// Dead-by-design (documented, not covered):
//   - RoutePreludeWrapKeyIV HKDF branches 53/57/61. HKDFExtractSHA384 wraps
//     hkdf.Extract (x/crypto/hkdf), which returns no error, so 53 never fires.
//     hkdfExpandLabel errors only on a label or context longer than 255 bytes or an
//     encoder error; the labels are the fixed strings "key"/"iv" (well under 255)
//     and the context is a PreHash digest (SHA-384, 48 bytes, well under 255), so
//     the encoder writes (WriteUint16/WriteOpaque8) never fail and 57/61 never
//     fire for any constructible input.
//   - SealRoutePrelude AAD error 85, nonce error 89, seal error 93. SealRoutePrelude
//     reaches these only after RoutePreludeWrapKeyIV succeeds, which requires
//     in.WrapSuiteID == WrapSuiteRouteV1 (else the suite guard at line 25 fires and
//     KeyIV returns at 49 before SealRoutePrelude reaches 81). With a valid suite
//     RouteWrapAAD writes a small varint and a PreHash of a valid 48-byte context,
//     so it cannot error (85). The iv is always 12 bytes (HKDFExpandLabelSHA384
//     ... length 12), so XORNonce96 never errors (89). The key is always 32 bytes
//     and the nonce always 12, so AES256GCMSeal never errors (93).
//   - OpenRoutePrelude AAD error 105, nonce error 109. Same reasoning as
//     SealRoutePrelude 85/89: a valid suite + valid 48-byte context keep
//     RouteWrapAAD and XORNonce96 from erroring.
//
// Not duplicated: the wrap-context / key-iv / AAD / seal / open happy returns are
// already covered by the route package's end-to-end tests and are not re-asserted
// here except for a single SealRoutePrelude->OpenRoutePrelude round-trip that
// anchors the valid baseline used by the error cases.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The new helper routewrapCovValidInput is referenced by >=2
// tests, so it is not U1000. No context.Context, no goroutines, no deprecated APIs.

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// routewrapCovValidInput returns a RouteWrapInput that passes every guard in
// routewrap.go: WrapSuiteRouteV1, a small in-range route instance id, and the
// 16-byte fixed-opaque fields (HintIssuerID, RelayBucketID, HintSelector,
// WrapNonce) at their required lengths. Each error-case test clones it and
// perturbs exactly one field. Referenced by >=2 tests, so not U1000.
func routewrapCovValidInput() RouteWrapInput {
	return RouteWrapInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: bytes.Repeat([]byte{0x11}, 48),
		NextRelayDescriptorHash:        bytes.Repeat([]byte{0x22}, 48),
		HintIssuerID:                   bytes.Repeat([]byte{0x33}, 16),
		RelayBucketID:                  bytes.Repeat([]byte{0x44}, 16),
		HintEpochID:                    1,
		HintSelector:                   bytes.Repeat([]byte{0x55}, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      bytes.Repeat([]byte{0x66}, 16),
		HintSecret:                     bytes.Repeat([]byte{0x77}, 32),
	}
}

func TestRoutePreludeWrapContextDecidesPerCondition(t *testing.T) {
	t.Run("unsupported suite", func(t *testing.T) {
		in := routewrapCovValidInput()
		in.WrapSuiteID = 0xBAD
		_, err := RoutePreludeWrapContext(in)
		if err == nil || !strings.Contains(err.Error(), "unsupported route wrap suite") {
			t.Fatalf("err = %v, want %q", err, "unsupported route wrap suite")
		}
	})
	t.Run("route instance id out of range", func(t *testing.T) {
		// A valid suite passes the line-25 guard; the out-of-range route instance
		// id then fails WriteVarint, so e.Bytes() surfaces it at line 41.
		in := routewrapCovValidInput()
		in.RouteInstanceID = math.MaxUint64
		_, err := RoutePreludeWrapContext(in)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("valid context", func(t *testing.T) {
		ctx, err := RoutePreludeWrapContext(routewrapCovValidInput())
		if err != nil {
			t.Fatalf("valid input: %v", err)
		}
		if len(ctx) == 0 {
			t.Fatalf("wrap context is empty")
		}
	})
}

func TestRoutePreludeWrapKeyIVDecidesPerCondition(t *testing.T) {
	t.Run("propagates unsupported suite", func(t *testing.T) {
		// RoutePreludeWrapContext rejects the bad suite (line 25) and
		// RoutePreludeWrapKeyIV propagates it at line 49 before HKDF runs.
		in := routewrapCovValidInput()
		in.WrapSuiteID = 0xBAD
		_, _, _, err := RoutePreludeWrapKeyIV(in)
		if err == nil || !strings.Contains(err.Error(), "unsupported route wrap suite") {
			t.Fatalf("err = %v, want %q", err, "unsupported route wrap suite")
		}
	})
	t.Run("valid key and iv", func(t *testing.T) {
		ctx, key, iv, err := RoutePreludeWrapKeyIV(routewrapCovValidInput())
		if err != nil {
			t.Fatalf("valid input: %v", err)
		}
		if len(ctx) == 0 || len(key) != 32 || len(iv) != 12 {
			t.Fatalf("derive lengths: ctx=%d key=%d iv=%d, want ctx>0 key=32 iv=12", len(ctx), len(key), len(iv))
		}
	})
}

func TestRouteWrapAADDecidesPerCondition(t *testing.T) {
	// A real 48-byte wrap context for the happy case (RouteWrapAAD hashes it
	// regardless of length, but the round-trip anchor uses the genuine digest).
	ctx, err := RoutePreludeWrapContext(routewrapCovValidInput())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("wrap suite id out of range", func(t *testing.T) {
		// WriteVarint(0xffff...) is the first failing write (line 70), before
		// WritePreHash(context) runs, so the context value is irrelevant.
		_, err := RouteWrapAAD(math.MaxUint64, ctx)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("valid aad", func(t *testing.T) {
		aad, err := RouteWrapAAD(registry.WrapSuiteRouteV1, ctx)
		if err != nil {
			t.Fatalf("valid input: %v", err)
		}
		if len(aad) == 0 {
			t.Fatalf("aad is empty")
		}
	})
}

func TestSealRoutePreludeAndOpenRoundTripDecidesPerCondition(t *testing.T) {
	plaintext := []byte("aurora route prelude")
	t.Run("seal propagates unsupported suite", func(t *testing.T) {
		// RoutePreludeWrapKeyIV rejects the bad suite and SealRoutePrelude
		// propagates it at line 81 before AAD/nonce/seal run.
		in := routewrapCovValidInput()
		in.WrapSuiteID = 0xBAD
		_, _, _, _, _, err := SealRoutePrelude(in, plaintext)
		if err == nil || !strings.Contains(err.Error(), "unsupported route wrap suite") {
			t.Fatalf("err = %v, want %q", err, "unsupported route wrap suite")
		}
	})
	t.Run("open propagates unsupported suite", func(t *testing.T) {
		in := routewrapCovValidInput()
		in.WrapSuiteID = 0xBAD
		_, err := OpenRoutePrelude(in, plaintext)
		if err == nil || !strings.Contains(err.Error(), "unsupported route wrap suite") {
			t.Fatalf("err = %v, want %q", err, "unsupported route wrap suite")
		}
	})
	t.Run("seal open round trip", func(t *testing.T) {
		// Anchor the valid baseline: a genuine seal/open round trip proves the
		// inputs used by the error cases are otherwise valid.
		in := routewrapCovValidInput()
		_, key, iv, aad, sealed, err := SealRoutePrelude(in, plaintext)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if len(key) != 32 || len(iv) != 12 || len(aad) == 0 || len(sealed) <= 16 {
			t.Fatalf("seal outputs: key=%d iv=%d aad=%d sealed=%d", len(key), len(iv), len(aad), len(sealed))
		}
		got, err := OpenRoutePrelude(in, sealed)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if string(got) != string(plaintext) {
			t.Fatalf("round trip = %q, want %q", got, plaintext)
		}
	})
}
