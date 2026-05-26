package route

import (
	"bytes"
	"errors"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
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

func TestPreviousHopFullTranscriptHashBindsSuiteAndTranscript(t *testing.T) {
	transcript := rb(0x20, 48)
	got, err := PreviousHopFullTranscriptHash(registry.SuiteHybrid768AESGCM, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 48 {
		t.Fatalf("previous-hop full transcript hash length = %d", len(got))
	}
	changedSuite, err := PreviousHopFullTranscriptHash(registry.SuiteHybrid1024AESGCM, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, changedSuite) {
		t.Fatalf("previous-hop full transcript hash did not bind selected suite")
	}
	changedTranscript, err := PreviousHopFullTranscriptHash(registry.SuiteHybrid768AESGCM, rb(0x21, 48))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, changedTranscript) {
		t.Fatalf("previous-hop full transcript hash did not bind application transcript")
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
		ClientClassicalEphPub:          routeTestClassicalShare(t, registry.SuiteHybrid768AESGCM),
		ClientMLKEMEncapsulationKey:    routeTestKEMShare(t),
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

func TestOpenPrivatePreludeClassifiesMalformedHybridShares(t *testing.T) {
	env := routeTestEnvelope()
	for name, mutate := range map[string]func(*PrivatePrelude){
		"client classical": func(p *PrivatePrelude) {
			p.ClientClassicalEphPub = []byte{0x01}
		},
		"client mlkem": func(p *PrivatePrelude) {
			p.ClientMLKEMEncapsulationKey = []byte{0x02}
		},
	} {
		t.Run(name, func(t *testing.T) {
			private := routeTestPrivatePrelude(t, env)
			mutate(&private)
			envelope, err := SealPrivatePrelude(env, private)
			if err != nil {
				t.Fatal(err)
			}
			_, err = OpenPrivatePrelude(env, envelope)
			if err == nil {
				t.Fatalf("malformed route hybrid share was accepted")
			}
			var failureErr *failure.Error
			if !errors.As(err, &failureErr) || failureErr.Kind != failure.MalformedHybridShare {
				t.Fatalf("route malformed share error = %T %[1]v, want %v", err, failure.MalformedHybridShare)
			}
			if got := failure.Classify(failureErr.Kind); got.Action != failure.CoverOrigin {
				t.Fatalf("route malformed share classification = %+v", got)
			}
		})
	}
}

func TestOpenPrivatePreludeRejectsMalformedPrivateHeader(t *testing.T) {
	env := routeTestEnvelope()
	for name, mutate := range map[string]func(*PrivatePrelude){
		"wrong message type": func(p *PrivatePrelude) {
			p.MsgType = registry.MsgCoverPrelude0
		},
		"wrong version": func(p *PrivatePrelude) {
			p.Version = registry.Version20 + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			private := routeTestPrivatePrelude(t, env)
			context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
			if err != nil {
				t.Fatal(err)
			}
			private.RoutePreludeWrapContext = context
			private.RouteInstanceID = env.RouteInstanceID
			private.HopIndex = env.HopIndex
			private.PreviousHopRelayDescriptorHash = env.PreviousHopRelayDescriptorHash
			private.NextRelayDescriptorHash = env.NextRelayDescriptorHash
			private.HintIssuerID = env.HintIssuerID
			private.RelayBucketID = env.RelayBucketID
			private.HintEpochID = env.HintEpochID
			private.HintSelector = env.HintSelector
			mutate(&private)
			envelope := sealRouteTestPrivatePrelude(t, env, private)
			if _, err := OpenPrivatePrelude(env, envelope); err == nil {
				t.Fatalf("malformed private prelude header was accepted")
			}
		})
	}
}

func routeTestEnvelope() EnvelopeInput {
	return EnvelopeInput{
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
}

func sealRouteTestPrivatePrelude(t *testing.T, env EnvelopeInput, private PrivatePrelude) protocol.RoutePreludeEnvelope {
	t.Helper()
	encoded, err := protocol.Encode(private)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, sealed, err := auroracrypto.SealRoutePrelude(env.routeWrapInput(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.RoutePreludeEnvelope{
		RouteInstanceID:                env.RouteInstanceID,
		HopIndex:                       env.HopIndex,
		PreviousHopRelayDescriptorHash: append([]byte(nil), env.PreviousHopRelayDescriptorHash...),
		NextRelayDescriptorHash:        append([]byte(nil), env.NextRelayDescriptorHash...),
		HintIssuerID:                   append([]byte(nil), env.HintIssuerID...),
		RelayBucketID:                  append([]byte(nil), env.RelayBucketID...),
		HintEpochID:                    env.HintEpochID,
		HintSelector:                   append([]byte(nil), env.HintSelector...),
		WrapSuiteID:                    env.WrapSuiteID,
		WrapNonce:                      append([]byte(nil), env.WrapNonce...),
		SealedRoutePrelude0:            sealed,
	}
}

func routeTestPrivatePrelude(t *testing.T, env EnvelopeInput) PrivatePrelude {
	t.Helper()
	return PrivatePrelude{
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
		ClientClassicalEphPub:          routeTestClassicalShare(t, registry.SuiteHybrid768AESGCM),
		ClientMLKEMEncapsulationKey:    routeTestKEMShare(t),
		RequestedRouteModeID:           registry.RouteSplit2,
		CoverShapeHintID:               registry.ShapeNormal,
	}
}

func routeTestClassicalShare(t *testing.T, suite uint64) []byte {
	t.Helper()
	key, err := auroracrypto.GenerateECDHForSuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKeyBytes()
}

func routeTestKEMShare(t *testing.T) []byte {
	t.Helper()
	key, err := auroracrypto.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	return key.EncapsulationKeyBytes()
}
