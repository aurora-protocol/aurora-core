package handshake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
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
	in := signedCoverPreludeVerificationInput(t)
	if _, err := s.VerifyCoverPrelude1(in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildCoverCapsule1(capsule); err != nil {
		t.Fatalf("client did not release admission after prelude verification: %v", err)
	}
}

func TestClientVerifiesCoverPrelude1SignaturesBeforeAdmissionRelease(t *testing.T) {
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
	in := signedCoverPreludeVerificationInput(t)
	if _, err := s.VerifyCoverPrelude1(in); err != nil {
		t.Fatalf("valid CoverPrelude1 rejected: %v", err)
	}
	if _, err := s.BuildCoverCapsule1(protocol.CoverCapsule1Plain{MsgType: registry.MsgCoverCapsule1}); err != nil {
		t.Fatalf("admission remained blocked after verified CoverPrelude1: %v", err)
	}
}

func TestVerifyCoverPrelude1SignaturesRejectsTamperedPrelude(t *testing.T) {
	in := signedCoverPreludeVerificationInput(t)
	in.Prelude1.SelectedCoverProfileID = hs(0xee, 16)
	if _, err := VerifyCoverPrelude1Signatures(in); err == nil {
		t.Fatalf("tampered CoverPrelude1 signature accepted")
	}
}

func TestVerifyCoverPrelude1SignaturesRequiresDescriptorBoundHash(t *testing.T) {
	in := signedCoverPreludeVerificationInput(t)
	in.Prelude1.RelayDescriptorHash = hs(0xee, 48)
	if _, err := VerifyCoverPrelude1Signatures(in); err == nil {
		t.Fatalf("CoverPrelude1 with wrong descriptor hash accepted")
	}
}

func TestVerifyCoverPrelude1ClassifiesMalformedHybridShares(t *testing.T) {
	for name, mutate := range map[string]func(*CoverPreludeVerificationInput){
		"client classical": func(in *CoverPreludeVerificationInput) {
			in.Prelude0.ClientClassicalEphPub = []byte{0x01}
		},
		"server classical": func(in *CoverPreludeVerificationInput) {
			in.Prelude1.ServerClassicalEphPub = []byte{0x02}
		},
		"client mlkem": func(in *CoverPreludeVerificationInput) {
			in.Prelude0.ClientMLKEMEncapsulationKey = []byte{0x03}
		},
		"server mlkem": func(in *CoverPreludeVerificationInput) {
			in.Prelude1.ServerMLKEMCiphertextToClient = []byte{0x04}
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := signedCoverPreludeVerificationInput(t)
			mutate(&in)
			_, err := VerifyCoverPrelude1Signatures(in)
			if err == nil {
				t.Fatalf("malformed hybrid share was accepted")
			}
			var failureErr *FailureError
			if !errors.As(err, &failureErr) || failureErr.Kind != failure.MalformedHybridShare {
				t.Fatalf("malformed hybrid share error = %T %[1]v, want %v", err, failure.MalformedHybridShare)
			}
			if got := failure.Classify(failureErr.Kind); got.Action != failure.CoverOrigin {
				t.Fatalf("malformed hybrid share classification = %+v", got)
			}
		})
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
	if _, err := s.VerifyCoverPrelude1(signedCoverPreludeVerificationInput(t)); err != nil {
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

func signedCoverPreludeVerificationInput(t *testing.T) CoverPreludeVerificationInput {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	classicalKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      hs(0x01, 32),
		ValidFromUnix:                100,
		ValidUntilUnix:               300,
		RelayLongtermClassicalKey:    classicalKey,
		RelayLongtermPQKey:           classicalKey,
		EpochID:                      7,
		EpochAuthClassicalKey:        classicalKey,
		EpochAuthPQKey:               classicalKey,
		EpochValidFromUnix:           100,
		EpochValidUntilUnix:          300,
		ReplayEpochID:                8,
		ReplayEpochValidUntilUnix:    260,
		ReplayWindowID:               hs(0x02, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: hs(0x03, 48),
		SupportedShapeIDsCommitment:  hs(0x04, 48),
		ExitPolicyCommitment:         hs(0x05, 48),
		AbusePolicyCommitment:        hs(0x06, 48),
	}
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	clientECDH, err := auroracrypto.GenerateECDHForSuite(registry.SuiteHybrid768AESGCM)
	if err != nil {
		t.Fatal(err)
	}
	serverECDH, err := auroracrypto.GenerateECDHForSuite(registry.SuiteHybrid768AESGCM)
	if err != nil {
		t.Fatal(err)
	}
	clientKEM, err := auroracrypto.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	_, serverKEMCiphertext, err := auroracrypto.EncapsulateMLKEM768(clientKEM.EncapsulationKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	coverTemplateHash := hs(0x07, 48)
	p0 := protocol.CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{registry.SuiteHybrid768AESGCM},
		ClientNonce:                 hs(0x08, 32),
		ClientClassicalEphPub:       clientECDH.PublicKeyBytes(),
		ClientMLKEMEncapsulationKey: clientKEM.EncapsulationKeyBytes(),
		RelayDescriptorHash:         descriptorHash,
		CoverTemplateHash:           coverTemplateHash,
		RequestClassID:              3,
		HintIssuerID:                hs(0x0b, 16),
		RelayBucketID:               hs(0x0c, 16),
		HintEpochID:                 9,
		HintSelector:                hs(0x0d, 16),
		AccessHint:                  hs(0x0e, 16),
		ClientCoverRandom:           hs(0x0f, 32),
	}
	p1 := protocol.CoverPrelude1{
		MsgType:                       registry.MsgCoverPrelude1,
		Version:                       registry.Version20,
		SelectedSuite:                 registry.SuiteHybrid768AESGCM,
		RelayDescriptorHash:           descriptorHash,
		CoverTemplateHash:             coverTemplateHash,
		RelayEpochID:                  descriptor.EpochID,
		ServerNonce:                   hs(0x10, 32),
		ServerClassicalEphPub:         serverECDH.PublicKeyBytes(),
		ServerMLKEMCiphertextToClient: serverKEMCiphertext,
		SelectedCoverProfileID:        hs(0x13, 16),
		SelectedBootstrapEnvelopeID:   hs(0x14, 16),
	}
	coverStreamBinding := hs(0x15, 48)
	transcript, err := PreludeTranscriptHash(registry.SuiteHybrid768AESGCM, coverStreamBinding, p0, p1)
	if err != nil {
		t.Fatal(err)
	}
	p1.ServerPreludeSignatureClassical, err = ecdsa.SignASN1(rand.Reader, priv, transcript)
	if err != nil {
		t.Fatal(err)
	}
	return CoverPreludeVerificationInput{
		Suite:              registry.SuiteHybrid768AESGCM,
		CoverStreamBinding: coverStreamBinding,
		Prelude0:           p0,
		Prelude1:           p1,
		Descriptor:         descriptor,
	}
}
