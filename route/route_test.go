package route

import (
	"bytes"
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

func TestValidatePrivatePreludeHeaderRejectsUnknownCriticalExtension(t *testing.T) {
	private := routeTestPrivatePrelude(t, routeTestEnvelope())
	private.MsgType = registry.MsgRoutePrelude0
	private.Version = registry.Version20
	private.Extensions = []protocol.Extension{{ExtensionType: 0x4001, Critical: true, Body: []byte{0x01}}}
	if err := ValidatePrivatePreludeHeader(private); err == nil {
		t.Fatalf("unknown critical private prelude extension accepted")
	}
}

func TestOpenAndVerifyPrivatePreludeSpendsAccessHintWithRouteHopBinding(t *testing.T) {
	env := routeTestEnvelope()
	cred := routeTestAccessHintCredential(env)
	private := routeTestPrivatePrelude(t, env)
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		t.Fatal(err)
	}
	private.RoutePreludeWrapContext = context
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		t.Fatal(err)
	}
	private.AccessHint, err = admission.ComputeAccessHint(cred, binding, private.ClientNonceForThisHop)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealPrivatePrelude(env, private)
	if err != nil {
		t.Fatal(err)
	}
	cache := admission.NewMemoryReplayCache()
	opened, openedBinding, err := OpenAndVerifyPrivatePrelude(cache, env, envelope, cred, 100, 300)
	if err != nil {
		t.Fatalf("valid route prelude was rejected: %v", err)
	}
	if opened.RouteInstanceID != env.RouteInstanceID || !bytes.Equal(openedBinding, binding) {
		t.Fatalf("opened route prelude binding mismatch: %+v %x", opened, openedBinding)
	}
	spentKey, err := admission.ComputeSpentHintKey(cred)
	if err != nil {
		t.Fatal(err)
	}
	if !cache.Has(spentKey) {
		t.Fatalf("route AccessHint was not spent")
	}
	if _, _, err := OpenAndVerifyPrivatePrelude(cache, env, envelope, cred, 100, 300); err == nil {
		t.Fatalf("replayed route AccessHint was accepted")
	}
}

func TestOpenAndVerifyPrivatePreludeRejectsDuplicateWrapNonceBeforeAccessHintSpend(t *testing.T) {
	env := routeTestEnvelope()
	cred := routeTestAccessHintCredential(env)
	private := routeTestPrivatePrelude(t, env)
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		t.Fatal(err)
	}
	private.RoutePreludeWrapContext = context
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		t.Fatal(err)
	}
	private.AccessHint, err = admission.ComputeAccessHint(cred, binding, private.ClientNonceForThisHop)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealPrivatePrelude(env, private)
	if err != nil {
		t.Fatal(err)
	}
	wrapCache := NewWrapNonceReplayCache()
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), wrapCache, env, envelope, cred, 100, 300); err != nil {
		t.Fatalf("valid route prelude was rejected: %v", err)
	}
	secondAccessCache := admission.NewMemoryReplayCache()
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(secondAccessCache, wrapCache, env, envelope, cred, 100, 300); err == nil {
		t.Fatalf("duplicate route wrap nonce was accepted")
	}
	spentKey, err := admission.ComputeSpentHintKey(cred)
	if err != nil {
		t.Fatal(err)
	}
	if secondAccessCache.Has(spentKey) {
		t.Fatalf("duplicate route wrap nonce spent AccessHint before rejection")
	}
}

func TestVerifyRoutePrelude1SignaturesRejectsTampering(t *testing.T) {
	in := signedRoutePreludeVerificationInput(t)
	if _, err := VerifyRoutePrelude1Signatures(in); err != nil {
		t.Fatalf("valid ROUTE_PRELUDE1 rejected: %v", err)
	}
	in.Prelude1.SelectedShapeID = registry.ShapeStrict
	if _, err := VerifyRoutePrelude1Signatures(in); err == nil {
		t.Fatalf("tampered ROUTE_PRELUDE1 signature accepted")
	}
}

func TestVerifyRoutePrelude1RequiresCanonicalRouteHopBinding(t *testing.T) {
	in := signedRoutePreludeVerificationInputWithBinding(t, rb(0xee, 48))
	if _, err := VerifyRoutePrelude1Signatures(in); err == nil {
		t.Fatalf("ROUTE_PRELUDE1 signed over non-canonical route_hop_binding was accepted")
	}
}

func TestVerifyRoutePrelude1RejectsEpochOutsideValidityWindow(t *testing.T) {
	in := signedRoutePreludeVerificationInput(t)
	in.NowUnix = in.Descriptor.EpochValidUntilUnix + 1
	if _, err := VerifyRoutePrelude1Signatures(in); err == nil {
		t.Fatalf("ROUTE_PRELUDE1 with expired next relay epoch was accepted")
	}
}

func TestRouteClientDoesNotReleaseCapsuleBeforePreludeVerification(t *testing.T) {
	session := NewClientSession()
	capsule := protocol.RouteCapsule1Plain{
		AdmissionProof: sampleRouteAdmissionProof(),
		ReplayProof:    sampleRouteReplayProof(),
		PolicyOffer:    sampleRoutePolicyOffer(),
		ClientFinished: rb(0xc1, 48),
	}
	if _, err := session.BuildRouteCapsule1(capsule); err == nil {
		t.Fatalf("route capsule was released before ROUTE_PRELUDE1 verification")
	}
	in := signedRoutePreludeVerificationInput(t)
	transcript, err := session.VerifyRoutePrelude1(in)
	if err != nil {
		t.Fatalf("valid ROUTE_PRELUDE1 rejected: %v", err)
	}
	if len(transcript) != 48 {
		t.Fatalf("route prelude transcript length = %d, want 48", len(transcript))
	}
	built, err := session.BuildRouteCapsule1(capsule)
	if err != nil {
		t.Fatalf("route capsule remained blocked after ROUTE_PRELUDE1 verification: %v", err)
	}
	if built.MsgType != registry.MsgRouteCapsule1 || built.RouteInstanceID != in.Prelude1.RouteInstanceID || built.HopIndex != in.Prelude1.HopIndex {
		t.Fatalf("route capsule header was not bound to verified prelude: %+v", built)
	}
}

func TestRouteSessionDrainsOldInstanceDuringRotation(t *testing.T) {
	session := NewClientSession()
	session.ActivateRoute(100, 1)
	if !session.AcceptsRouteInstance(100, 10) {
		t.Fatalf("active route instance was rejected")
	}
	if err := session.RotateRoute(200, 1, 20, 5); err != nil {
		t.Fatal(err)
	}
	if !session.AcceptsRouteInstance(200, 21) {
		t.Fatalf("new route instance was rejected after rotation")
	}
	if !session.AcceptsRouteInstance(100, 24) {
		t.Fatalf("old route instance was not accepted during drain")
	}
	if session.AcceptsRouteInstance(100, 25) {
		t.Fatalf("old route instance was accepted after drain expiry")
	}
}

func TestRouteSessionRejectsOverlappingRotationWhileDraining(t *testing.T) {
	session := NewClientSession()
	session.ActivateRoute(100, 1)
	if err := session.RotateRoute(200, 1, 20, 10); err != nil {
		t.Fatal(err)
	}
	if err := session.RotateRoute(300, 1, 21, 10); err == nil {
		t.Fatalf("overlapping route rotation was accepted while old route was draining")
	}
	if !session.AcceptsRouteInstance(200, 21) || !session.AcceptsRouteInstance(100, 21) {
		t.Fatalf("rotation rejection disturbed active or draining route state")
	}
	if err := session.RotateRoute(300, 1, 30, 10); err != nil {
		t.Fatalf("rotation after drain expiry was rejected: %v", err)
	}
	if !session.AcceptsRouteInstance(300, 31) || !session.AcceptsRouteInstance(200, 31) {
		t.Fatalf("post-drain rotation state mismatch")
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

func sampleRouteAdmissionProof() protocol.AdmissionProof {
	return protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              rb(0xb1, 16),
		TokenKeyID:            rb(0xb2, 32),
		RelayBucketID:         rb(0xb3, 16),
		TokenScopeID:          rb(0xb4, 16),
		ExpiryUnix:            200,
		TokenNonce:            rb(0xb5, 32),
		RedemptionContextHash: rb(0xb6, 48),
		TokenPublicMetadata:   []byte("metadata"),
		TokenAuthenticator:    []byte("token"),
	}
}

func sampleRouteReplayProof() protocol.ReplayProof {
	return protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       9,
		TokenRedemptionHash: rb(0xb7, 48),
		ClientReplayNonce:   rb(0xb8, 32),
		ReplayContextHash:   rb(0xb9, 48),
		ReplayWindowID:      rb(0xba, 16),
	}
}

func sampleRoutePolicyOffer() protocol.PolicyOffer {
	return protocol.PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream},
		MinimumPolicyID:         registry.PolicyFastWeb,
		RequestedPolicyID:       registry.PolicyBalancedWeb,
		RequestedRouteModeID:    registry.RouteSplit2,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
	}
}

func signedRoutePreludeVerificationInput(t *testing.T) RoutePreludeVerificationInput {
	return signedRoutePreludeVerificationInputWithBinding(t, nil)
}

func signedRoutePreludeVerificationInputWithBinding(t *testing.T, bindingOverride []byte) RoutePreludeVerificationInput {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	classicalKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       mustECDSAPublicKeyBytes(t, &priv.PublicKey),
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      rb(0x91, 32),
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
		ReplayWindowID:               rb(0x92, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: rb(0x93, 48),
		SupportedShapeIDsCommitment:  rb(0x94, 48),
		ExitPolicyCommitment:         rb(0x95, 48),
		AbusePolicyCommitment:        rb(0x96, 48),
	}
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	env := routeTestEnvelope()
	env.NextRelayDescriptorHash = descriptorHash
	private := routeTestPrivatePrelude(t, env)
	clientKEM, err := auroracrypto.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	private.MsgType = registry.MsgRoutePrelude0
	private.Version = registry.Version20
	private.ClientMLKEMEncapsulationKey = clientKEM.EncapsulationKeyBytes()
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		t.Fatal(err)
	}
	private.RoutePreludeWrapContext = context
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		t.Fatal(err)
	}
	signingBinding := binding
	if bindingOverride != nil {
		signingBinding = append([]byte(nil), bindingOverride...)
	}
	serverECDH, err := auroracrypto.GenerateECDHForSuite(registry.SuiteHybrid768AESGCM)
	if err != nil {
		t.Fatal(err)
	}
	_, serverKEMCiphertext, err := auroracrypto.EncapsulateMLKEM768(clientKEM.EncapsulationKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	p1 := protocol.RoutePrelude1{
		MsgType:                        registry.MsgRoutePrelude1,
		Version:                        registry.Version20,
		RouteInstanceID:                env.RouteInstanceID,
		HopIndex:                       env.HopIndex,
		PreviousHopRelayDescriptorHash: env.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        descriptorHash,
		NextRelayEpochID:               descriptor.EpochID,
		SelectedSuite:                  registry.SuiteHybrid768AESGCM,
		ServerNonce:                    rb(0xa1, 32),
		ServerClassicalEphPub:          serverECDH.PublicKeyBytes(),
		ServerMLKEMCiphertextToClient:  serverKEMCiphertext,
		SelectedShapeID:                registry.ShapeNormal,
	}
	transcript, err := HopPreludeTranscriptHash(registry.SuiteHybrid768AESGCM, signingBinding, private, p1)
	if err != nil {
		t.Fatal(err)
	}
	p1.ServerPreludeSignatureClassical, err = ecdsa.SignASN1(rand.Reader, priv, transcript)
	if err != nil {
		t.Fatal(err)
	}
	return RoutePreludeVerificationInput{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteHopBinding: signingBinding,
		Prelude0:        private,
		Prelude1:        p1,
		Descriptor:      descriptor,
	}
}

func mustECDSAPublicKeyBytes(t testing.TB, key *ecdsa.PublicKey) []byte {
	t.Helper()
	encoded, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func routeTestAccessHintCredential(env EnvelopeInput) admission.AccessHintCredential {
	return admission.AccessHintCredential{
		HintIssuerID:  append([]byte(nil), env.HintIssuerID...),
		RelayBucketID: append([]byte(nil), env.RelayBucketID...),
		HintEpochID:   env.HintEpochID,
		HintSelector:  append([]byte(nil), env.HintSelector...),
		HintSecret:    append([]byte(nil), env.HintSecret...),
		ExpiryUnix:    200,
		MaxUses:       1,
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
