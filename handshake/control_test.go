package handshake

import (
	"bytes"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestCoverCapsuleControlAEADRoundTripUsesDirectionalKeys(t *testing.T) {
	ctx := controlTestContext()
	capsule1 := sampleControlCapsule1()
	sealed1, err := SealCoverCapsule1(ctx, capsule1)
	if err != nil {
		t.Fatal(err)
	}
	opened1, err := OpenCoverCapsule1(ctx, sealed1)
	if err != nil {
		t.Fatal(err)
	}
	if opened1.MsgType != registry.MsgCoverCapsule1 || opened1.RouteInstanceID != ctx.RouteInstanceID {
		t.Fatalf("opened CoverCapsule1 header = msg 0x%x route %d", opened1.MsgType, opened1.RouteInstanceID)
	}
	if !bytes.Equal(opened1.AdmissionProof.TokenNonce, capsule1.AdmissionProof.TokenNonce) {
		t.Fatalf("CoverCapsule1 payload changed after open")
	}

	capsule2 := protocol.CoverCapsule2Plain{
		PolicyAccept: protocol.PolicyAccept{
			SelectedVersion:           registry.Version20,
			SelectedSuite:             registry.SuiteHybrid768AESGCM,
			SelectedMethod:            registry.MethodWebH2Stream,
			SelectedPolicy:            registry.PolicyAdversarialDPI,
			SelectedRouteModeID:       registry.RouteSplit2,
			SelectedShape:             registry.ShapeNormal,
			SelectedTunnelPersonality: registry.PersonalityProxyFlow,
		},
		ServerFinished: repeatedByte(0x71, 48),
	}
	sealed2, err := SealCoverCapsule2(ctx, capsule2)
	if err != nil {
		t.Fatal(err)
	}
	opened2, err := OpenCoverCapsule2(ctx, sealed2)
	if err != nil {
		t.Fatal(err)
	}
	if opened2.MsgType != registry.MsgCoverCapsule2 || opened2.RouteInstanceID != ctx.RouteInstanceID {
		t.Fatalf("opened CoverCapsule2 header = msg 0x%x route %d", opened2.MsgType, opened2.RouteInstanceID)
	}
	if _, err := OpenCoverCapsule1(ctx, sealed2); err == nil {
		t.Fatalf("CoverCapsule2 opened with CoverCapsule1 direction/AAD")
	}
}

func TestOpenCoverCapsuleRejectsPlainRouteInstanceMismatch(t *testing.T) {
	ctx := controlTestContext()
	wrong := sampleControlCapsule1()
	wrong.MsgType = registry.MsgCoverCapsule1
	wrong.RouteInstanceID = ctx.RouteInstanceID + 1
	encoded, err := protocol.Encode(wrong)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := auroracrypto.ControlAAD(auroracrypto.ControlAADInput{
		SelectedVersion:                 ctx.SelectedVersion,
		SelectedSuite:                   ctx.SelectedSuite,
		MsgType:                         registry.MsgCoverCapsule1,
		RouteInstanceID:                 ctx.RouteInstanceID,
		HopIndex:                        ctx.HopIndex,
		ControlDirection:                ControlDirectionClientToHop,
		HandshakeBindingContext:         ctx.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: ctx.PreludeTranscriptHashForThisHop,
	})
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := auroracrypto.XORNonce96(ctx.ClientHSIV, 0)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := auroracrypto.SealForSuite(ctx.SelectedSuite, ctx.ClientHSKey, nonce, aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCoverCapsule1(ctx, sealed); err == nil {
		t.Fatalf("CoverCapsule1 with mismatched plaintext route_instance_id was accepted")
	}
}

func controlTestContext() ControlCapsuleContext {
	return ControlCapsuleContext{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		RouteInstanceID:                 0x1234,
		HopIndex:                        0,
		HandshakeBindingContext:         repeatedByte(0x31, 48),
		PreludeTranscriptHashForThisHop: repeatedByte(0x32, 48),
		ClientHSKey:                     repeatedByte(0x41, 32),
		ClientHSIV:                      repeatedByte(0x42, 12),
		ServerHSKey:                     repeatedByte(0x43, 32),
		ServerHSIV:                      repeatedByte(0x44, 12),
	}
}

func sampleControlCapsule1() protocol.CoverCapsule1Plain {
	return protocol.CoverCapsule1Plain{
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              repeatedByte(0x01, 16),
			TokenKeyID:            repeatedByte(0x02, 32),
			RelayBucketID:         repeatedByte(0x03, 16),
			TokenScopeID:          repeatedByte(0x04, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            repeatedByte(0x05, 32),
			RedemptionContextHash: repeatedByte(0x06, 48),
			TokenAuthenticator:    []byte("structural-token"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       9,
			TokenRedemptionHash: repeatedByte(0x07, 48),
			ClientReplayNonce:   repeatedByte(0x08, 32),
			ReplayContextHash:   repeatedByte(0x09, 48),
			ReplayWindowID:      repeatedByte(0x0a, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyAdversarialDPI,
			RequestedPolicyID:       registry.PolicyAdversarialDPI,
			RequestedRouteModeID:    registry.RouteSplit2,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
		ClientFinished: repeatedByte(0x61, 48),
	}
}

func repeatedByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
