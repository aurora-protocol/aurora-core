package route

import (
	"bytes"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/registry"
)

func rb(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestRouteHopBindingChangesWithPreviousTranscript(t *testing.T) {
	in := HopBindingInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopFullTranscriptHash:  rb(0x10, 48),
		PreviousHopRelayDescriptorHash: rb(0x11, 48),
		NextRelayDescriptorHash:        rb(0x12, 48),
		RoutePreludeWrapContext:        rb(0x13, 48),
		ClientNonceForThisHop:          rb(0x14, 32),
	}
	first, err := RouteHopBinding(in)
	if err != nil {
		t.Fatal(err)
	}
	in.PreviousHopFullTranscriptHash = rb(0x99, 48)
	second, err := RouteHopBinding(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatalf("route_hop_binding did not bind previous-hop transcript")
	}
}

func TestRoutePreludeWrapRoundTripRejectsMismatchedVisibleEnvelope(t *testing.T) {
	env := EnvelopeInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: rb(0x41, 48),
		NextRelayDescriptorHash:        rb(0x42, 48),
		HintIssuerID:                   rb(0x34, 16),
		RelayBucketID:                  rb(0x35, 16),
		HintEpochID:                    7,
		HintSelector:                   rb(0x31, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      rb(0x32, 16),
		HintSecret:                     rb(0x33, 32),
	}
	private := PrivatePrelude{
		RouteInstanceID:                env.RouteInstanceID,
		HopIndex:                       env.HopIndex,
		PreviousHopRelayDescriptorHash: env.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        env.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        rb(0, 48),
		PreviousHopFullTranscriptHash:  rb(0x44, 48),
		ClientNonceForThisHop:          rb(0x45, 32),
		HintIssuerID:                   env.HintIssuerID,
		RelayBucketID:                  env.RelayBucketID,
		HintEpochID:                    env.HintEpochID,
		HintSelector:                   env.HintSelector,
		AccessHint:                     rb(0x46, 16),
		OfferedSuites:                  []uint64{registry.SuiteHybrid768AESGCM},
		RequestedRouteModeID:           registry.RouteSplit2,
		CoverShapeHintID:               registry.ShapeNormal,
	}
	envelope, err := SealPrivatePrelude(env, private)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenPrivatePrelude(env, envelope)
	if err != nil {
		t.Fatal(err)
	}
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.RoutePreludeWrapContext, context) {
		t.Fatalf("private prelude did not carry wrap context")
	}
	if opened.MsgType != registry.MsgRoutePrelude0 || opened.Version != registry.Version20 {
		t.Fatalf("private prelude header was not canonical: %+v", opened)
	}
	env.NextRelayDescriptorHash = rb(0x99, 48)
	if _, err := OpenPrivatePrelude(env, envelope); err == nil {
		t.Fatalf("expected visible-envelope mismatch to fail")
	}
}
