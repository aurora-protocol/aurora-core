package handshake

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestClientDoesNotReleaseAdmissionBeforePreludeVerification(t *testing.T) {
	s := NewClientSession()
	capsule := protocol.CoverCapsule1Plain{
		MsgType:         registry.MsgCoverCapsule1,
		RouteInstanceID: 1,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion: registry.Version20,
			ProofType:    registry.ProofLabStaticToken,
		},
	}
	if _, err := s.BuildCoverCapsule1(capsule); err == nil {
		t.Fatalf("client released admission before CoverPrelude1 verification")
	}
	if err := s.MarkDescriptorLoaded(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCoverOpened(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCoverPrelude0Sent(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCoverPrelude1Verified(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildCoverCapsule1(capsule); err != nil {
		t.Fatalf("client did not release admission after prelude verification: %v", err)
	}
}

func TestRelaySpendsAccessHintBeforePrelude1(t *testing.T) {
	cred := admission.AccessHintCredential{
		HintIssuerID:  hs(0x01, 16),
		RelayBucketID: hs(0x02, 16),
		HintEpochID:   7,
		HintSelector:  hs(0x03, 16),
		HintSecret:    hs(0x04, 32),
		MaxUses:       1,
	}
	binding := hs(0xaa, 48)
	nonce := hs(0xbb, 32)
	hint, err := admission.ComputeAccessHint(cred, binding, nonce)
	if err != nil {
		t.Fatal(err)
	}
	p0 := protocol.CoverPrelude0{
		MsgType:           registry.MsgCoverPrelude0,
		Version:           registry.Version20,
		ClientNonce:       nonce,
		HintIssuerID:      cred.HintIssuerID,
		RelayBucketID:     cred.RelayBucketID,
		HintEpochID:       cred.HintEpochID,
		HintSelector:      cred.HintSelector,
		AccessHint:        hint,
		ClientCoverRandom: hs(0xcc, 32),
	}
	cache := admission.NewMemoryReplayCache()
	relay := NewRelaySession(cache)
	p1 := protocol.CoverPrelude1{MsgType: registry.MsgCoverPrelude1, Version: registry.Version20}
	if _, err := relay.AcceptCoverPrelude0(p0, cred, binding, p1); err != nil {
		t.Fatalf("valid prelude0 rejected: %v", err)
	}
	spentKey, err := admission.ComputeSpentHintKey(cred)
	if err != nil {
		t.Fatal(err)
	}
	if !cache.Has(spentKey) {
		t.Fatalf("access hint was not spent before prelude1")
	}
	if _, err := relay.AcceptCoverPrelude0(p0, cred, binding, p1); err == nil {
		t.Fatalf("replayed access hint produced another prelude1")
	}
}

func TestWrongServerFinishedBlocksApplicationReady(t *testing.T) {
	s := NewClientSession()
	if err := s.MarkDescriptorLoaded(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCoverOpened(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCoverPrelude0Sent(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCoverPrelude1Verified(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildCoverCapsule1(protocol.CoverCapsule1Plain{MsgType: registry.MsgCoverCapsule1}); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyCoverCapsule2(protocol.CoverCapsule2Plain{
		MsgType:        registry.MsgCoverCapsule2,
		ServerFinished: hs(0xee, 48),
	}, hs(0xef, 48)); err == nil {
		t.Fatalf("wrong ServerFinished was accepted")
	}
	if s.State() == StateApplicationReady {
		t.Fatalf("application became ready after wrong ServerFinished")
	}
}

func hs(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
