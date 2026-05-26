package ops

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestDirectoryPublisherRejectsUnsignedConsensus(t *testing.T) {
	p := DirectoryPublisher{Threshold: 1}
	if err := p.Publish(ConsensusDraft{}); err == nil {
		t.Fatalf("unsigned consensus was published")
	}
}

func TestVerifierServiceEmptyAllowlistsReject(t *testing.T) {
	s := VerifierService{
		AllowedProofTypes:     nil,
		AllowedRelayBucketIDs: nil,
	}
	if s.Allows(registry.ProofVOPRFP384SHA384, []byte{1}) {
		t.Fatalf("empty verifier allowlists must reject")
	}
}

func TestServiceAuthKeyCannotReuseAuthorityKey(t *testing.T) {
	key := []byte("same-key")
	err := ValidateServiceAuthKey(key, [][]byte{key})
	if err == nil {
		t.Fatalf("service auth key reused authority key")
	}
}

func TestSelectIssuerVerifierServiceRequiresExactlyOneMatch(t *testing.T) {
	bucket := []byte("1234567890abcdef")
	service := protocol.IssuerVerifierServiceRecord{
		ServiceID:             []byte("service-id-00001"),
		ServiceKind:           registry.VerifierServiceKindVOPRF,
		ServiceProtocolID:     registry.IssuerVerifierVOPRFMTLS13,
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{bucket},
		RequestAuthPolicyID:   9,
		ValidFromUnix:         10,
		ValidUntilUnix:        30,
		ServiceStatus:         registry.IssuerStatusActive,
	}
	if _, err := SelectIssuerVerifierService([]protocol.IssuerVerifierServiceRecord{service}, registry.ProofVOPRFP384SHA384, bucket, 20, map[uint64]bool{9: true}); err != nil {
		t.Fatalf("valid verifier service not selected: %v", err)
	}
	if _, err := SelectIssuerVerifierService([]protocol.IssuerVerifierServiceRecord{service, service}, registry.ProofVOPRFP384SHA384, bucket, 20, map[uint64]bool{9: true}); err == nil {
		t.Fatalf("ambiguous verifier service selection accepted")
	}
	if _, err := SelectIssuerVerifierService([]protocol.IssuerVerifierServiceRecord{service}, registry.ProofVOPRFP384SHA384, bucket, 20, nil); err == nil {
		t.Fatalf("unimplemented request auth policy accepted")
	}
}

func TestBuildIssuerVerifierRequestRecomputesTokenSpentKey(t *testing.T) {
	service := verifierServiceRecord()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	wantRedemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	wantSpent, err := admission.TokenSpentKey(wantRedemption)
	if err != nil {
		t.Fatal(err)
	}
	req, requestHash, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		TokenSpentCache:           admission.NewMemoryReplayCache(),
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.RequestVersion != registry.Version20 || req.ServiceID == nil || len(requestHash) != 48 {
		t.Fatalf("unexpected verifier request: req=%+v hash=%x", req, requestHash)
	}
	if !bytes.Equal(req.TokenSpentKey, wantSpent) {
		t.Fatalf("request did not recompute token_spent_key")
	}
	replay.TokenRedemptionHash = rb(0xee, 48)
	if _, _, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		TokenSpentCache:           admission.NewMemoryReplayCache(),
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
	}); err == nil {
		t.Fatalf("verifier request built from mismatched ReplayProof")
	}
}

func TestBuildIssuerVerifierRequestRecomputesAuthenticatorFields(t *testing.T) {
	service := verifierServiceRecord()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	metadataHash := rb(0x30, 48)
	metadata, wantChallenge, wantAuthenticatorHash := verifierTokenMetadataForTest(t, proof, metadataHash, []byte("issuer.example"), []byte("origin.example"))
	proof.TokenPublicMetadata = metadata
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	replay.TokenRedemptionHash = redemption
	replay.ReplayContextHash, err = admission.ReplayContextHash(redemption, replay, 77, 1, handshakeBinding, admissionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        metadataHash,
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0xee, 32),
		AuthenticatorInputHash:    rb(0xef, 48),
		TokenSpentCache:           admission.NewMemoryReplayCache(),
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.ChallengeDigest, wantChallenge) {
		t.Fatalf("request challenge digest was not recomputed")
	}
	if !bytes.Equal(req.AuthenticatorInputHash, wantAuthenticatorHash) {
		t.Fatalf("request authenticator input hash was not recomputed")
	}
}

func TestBuildIssuerVerifierRequestRejectsLocalReplayWithChangedNonce(t *testing.T) {
	service := verifierServiceRecord()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	tokenCache := admission.NewMemoryReplayCache()

	input := IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
		TokenSpentCache:           tokenCache,
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
	}
	if _, _, err := BuildIssuerVerifierRequest(input); err != nil {
		t.Fatalf("first verifier request failed: %v", err)
	}

	replay.ClientReplayNonce = rb(0x42, 32)
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	replay.ReplayContextHash, err = admission.ReplayContextHash(redemption, replay, 77, 1, handshakeBinding, admissionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	input.ReplayProof = replay
	input.BootstrapDedupCache = admission.NewMemoryReplayCache()
	if _, _, err := BuildIssuerVerifierRequest(input); err == nil {
		t.Fatalf("replayed token accepted with changed replay nonce")
	}
}

func TestBuildIssuerVerifierRequestDoesNotSpendOnMetadataMismatch(t *testing.T) {
	service := verifierServiceRecord()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	tokenCache := admission.NewMemoryReplayCache()
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	spentKey, err := admission.TokenSpentKey(redemption)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x99, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
		TokenSpentCache:           tokenCache,
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
	})
	if err == nil {
		t.Fatalf("verifier request accepted mismatched issuer metadata")
	}
	if tokenCache.Has(spentKey) {
		t.Fatalf("token was spent before verifier metadata validation completed")
	}
}

func TestBuildIssuerVerifierRequestRejectsStructurallyInvalidAdmissionProof(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*protocol.AdmissionProof)
		now    uint64
	}{
		"expired": {
			mutate: func(*protocol.AdmissionProof) {},
			now:    500,
		},
		"unsupported version": {
			mutate: func(proof *protocol.AdmissionProof) {
				proof.ProofVersion = 0
			},
			now: 100,
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := verifierServiceRecord()
			proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
			tc.mutate(&proof)
			if _, _, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
				Service:                   service,
				AdmissionProof:            proof,
				ReplayProof:               replay,
				IssuerMetadataHash:        rb(0x30, 48),
				RelayDescriptorHash:       rb(0x31, 48),
				RouteInstanceID:           77,
				HopIndex:                  1,
				ReplayEpochValidUntilUnix: 800,
				HandshakeBindingContext:   handshakeBinding,
				AdmissionContextHash:      admissionContextHash,
				ChallengeDigest:           rb(0x32, 32),
				AuthenticatorInputHash:    rb(0x33, 48),
				TokenSpentCache:           admission.NewMemoryReplayCache(),
				BootstrapDedupCache:       admission.NewMemoryReplayCache(),
				RequestNonce:              rb(0x34, 32),
				RequestTimeUnix:           tc.now,
				NowUnix:                   tc.now,
				RequestAuthImplemented:    true,
			}); err == nil {
				t.Fatalf("verifier request built from structurally invalid admission proof")
			}
		})
	}
}

func TestValidateIssuerVerifierResponseRequiresFreshMatchingAccept(t *testing.T) {
	service := verifierServiceRecord()
	serviceSigner := attachVerifierServiceSigningKey(t, &service)
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	req, requestHash, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		TokenSpentCache:           admission.NewMemoryReplayCache(),
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := protocol.IssuerVerifierResponse{
		ResponseVersion: registry.Version20,
		ServiceID:       append([]byte(nil), service.ServiceID...),
		RequestHash:     requestHash,
		Decision:        registry.VerifierDecisionAccept,
		TokenSpentKey:   append([]byte(nil), req.TokenSpentKey...),
		ValidUntilUnix:  200,
		ResponseNonce:   rb(0x40, 32),
	}
	signVerifierResponse(t, serviceSigner, &resp)
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err != nil {
		t.Fatalf("valid verifier response rejected: %v", err)
	}
	resp.RequestHash = rb(0x41, 48)
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
		t.Fatalf("mismatched request hash accepted")
	}
	resp.RequestHash = requestHash
	resp.TokenSpentKey = rb(0x42, 48)
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
		t.Fatalf("mismatched token_spent_key accepted")
	}
	resp.TokenSpentKey = req.TokenSpentKey
	resp.ValidUntilUnix = req.RequestTimeUnix + 301
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
		t.Fatalf("overlong verifier response freshness accepted")
	}
	resp.ValidUntilUnix = 200
	resp.ServiceSignature = nil
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
		t.Fatalf("unsigned verifier response accepted")
	}
	resp.ServiceSignature = []byte("signature")
	resp.Decision = registry.VerifierDecisionRejectPolicy
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
		t.Fatalf("reject decision accepted")
	}
}

func TestValidateIssuerVerifierResponseRejectsUnusableService(t *testing.T) {
	service := verifierServiceRecord()
	serviceSigner := attachVerifierServiceSigningKey(t, &service)
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	req, requestHash, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		TokenSpentCache:           admission.NewMemoryReplayCache(),
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := protocol.IssuerVerifierResponse{
		ResponseVersion: registry.Version20,
		ServiceID:       append([]byte(nil), service.ServiceID...),
		RequestHash:     requestHash,
		Decision:        registry.VerifierDecisionAccept,
		TokenSpentKey:   append([]byte(nil), req.TokenSpentKey...),
		ValidUntilUnix:  200,
		ResponseNonce:   rb(0x40, 32),
	}
	signVerifierResponse(t, serviceSigner, &resp)
	service.ServiceStatus = registry.IssuerStatusRevoked
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
		t.Fatalf("verifier response from revoked service accepted")
	}
}

func TestValidateIssuerVerifierResponseRejectsInvalidServiceSignature(t *testing.T) {
	service := verifierServiceRecord()
	attachVerifierServiceSigningKey(t, &service)
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	req, requestHash, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		TokenSpentCache:           admission.NewMemoryReplayCache(),
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := protocol.IssuerVerifierResponse{
		ResponseVersion:  registry.Version20,
		ServiceID:        append([]byte(nil), service.ServiceID...),
		RequestHash:      requestHash,
		Decision:         registry.VerifierDecisionAccept,
		TokenSpentKey:    append([]byte(nil), req.TokenSpentKey...),
		ValidUntilUnix:   200,
		ResponseNonce:    rb(0x40, 32),
		ServiceSignature: []byte("not a valid signature"),
	}
	if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
		t.Fatalf("invalid verifier service signature accepted")
	}
}

func TestVerifyIssuerVerifierServiceMapsTransportOutageToCoverNeutralFailure(t *testing.T) {
	service := verifierServiceRecord()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	err := VerifyIssuerVerifierService(IssuerVerifierServiceVerificationInput{
		Request: IssuerVerifierRequestInput{
			Service:                   service,
			AdmissionProof:            proof,
			ReplayProof:               replay,
			IssuerMetadataHash:        rb(0x30, 48),
			RelayDescriptorHash:       rb(0x31, 48),
			RouteInstanceID:           77,
			HopIndex:                  1,
			ReplayEpochValidUntilUnix: 800,
			HandshakeBindingContext:   handshakeBinding,
			AdmissionContextHash:      admissionContextHash,
			ChallengeDigest:           rb(0x32, 32),
			AuthenticatorInputHash:    rb(0x33, 48),
			TokenSpentCache:           admission.NewMemoryReplayCache(),
			BootstrapDedupCache:       admission.NewMemoryReplayCache(),
			RequestNonce:              rb(0x34, 32),
			RequestTimeUnix:           100,
			NowUnix:                   100,
			RequestAuthImplemented:    true,
		},
		Transport: outageVerifierTransport{},
	})
	var failureErr *failure.Error
	if !errors.As(err, &failureErr) || failureErr.Kind != failure.VerifierUnavailable {
		t.Fatalf("verifier transport outage error = %T %[1]v, want %v", err, failure.VerifierUnavailable)
	}
	if got := failure.Classify(failureErr.Kind); got.Action != failure.CoverOrigin {
		t.Fatalf("verifier outage action = %v, want cover-origin", got.Action)
	}
}

type outageVerifierTransport struct{}

func (outageVerifierTransport) ExchangeIssuerVerifier(protocol.IssuerVerifierServiceRecord, protocol.IssuerVerifierRequest) (protocol.IssuerVerifierResponse, error) {
	return protocol.IssuerVerifierResponse{}, errors.New("operator verifier unavailable")
}

func verifierServiceRecord() protocol.IssuerVerifierServiceRecord {
	return protocol.IssuerVerifierServiceRecord{
		ServiceID:             []byte("service-id-00001"),
		ServiceKind:           registry.VerifierServiceKindVOPRF,
		ServiceProtocolID:     registry.IssuerVerifierVOPRFMTLS13,
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{[]byte("1234567890abcdef")},
		RequestAuthPolicyID:   9,
		ValidFromUnix:         10,
		ValidUntilUnix:        900,
		ServiceStatus:         registry.IssuerStatusActive,
	}
}

func verifierProofReplay(t *testing.T) (protocol.AdmissionProof, protocol.ReplayProof, []byte, []byte) {
	t.Helper()
	admissionContextHash := rb(0x20, 48)
	handshakeBinding := rb(0x21, 48)
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofVOPRFP384SHA384,
		IssuerID:              rb(0x10, 16),
		TokenKeyID:            rb(0x11, 32),
		RelayBucketID:         []byte("1234567890abcdef"),
		TokenScopeID:          rb(0x12, 16),
		ExpiryUnix:            500,
		TokenNonce:            rb(0x13, 32),
		RedemptionContextHash: admissionContextHash,
		TokenAuthenticator:    []byte("authenticator"),
	}
	proof.TokenPublicMetadata, _, _ = verifierTokenMetadataForTest(t, proof, rb(0x30, 48), []byte("issuer.example"), []byte("origin.example"))
	redemptionHash, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	replay := protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		TokenRedemptionHash: redemptionHash,
		ClientReplayNonce:   rb(0x14, 32),
		ReplayEpochID:       22,
		ReplayWindowID:      rb(0x15, 16),
	}
	replayHash, err := admission.ReplayContextHash(redemptionHash, replay, 77, 1, handshakeBinding, admissionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	replay.ReplayContextHash = replayHash
	return proof, replay, admissionContextHash, handshakeBinding
}

func attachVerifierServiceSigningKey(t *testing.T, service *protocol.IssuerVerifierServiceRecord) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service.ServiceAuthKey = protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
	}
	return priv
}

func signVerifierResponse(t *testing.T, priv *ecdsa.PrivateKey, resp *protocol.IssuerVerifierResponse) {
	t.Helper()
	input, err := auroratrust.IssuerVerifierResponseSignatureInput(resp.RequestHash, *resp)
	if err != nil {
		t.Fatal(err)
	}
	resp.ServiceSignature, err = ecdsa.SignASN1(rand.Reader, priv, input)
	if err != nil {
		t.Fatal(err)
	}
}

func verifierTokenMetadataForTest(t *testing.T, proof protocol.AdmissionProof, issuerMetadataHash, issuerName, originInfo []byte) (metadata, challengeDigest, authenticatorHash []byte) {
	t.Helper()
	redemptionContext := sha256.Sum256(append([]byte("aurora v2.0 token redemption context"), proof.RedemptionContextHash...))
	challenge := wire.NewEncoder()
	challenge.WriteUint16(uint16(proof.ProofType))
	challenge.WriteOpaque16(issuerName)
	challenge.WriteOpaque8(redemptionContext[:])
	challenge.WriteOpaque16(originInfo)
	challengeBytes, err := challenge.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(challengeBytes)
	challengeDigest = sum[:]

	metadataEncoder := wire.NewEncoder()
	metadataEncoder.WriteUint16(uint16(proof.ProofType))
	metadataEncoder.WriteOpaqueFixed(challengeDigest, 32)
	metadataEncoder.WriteOpaqueFixed(proof.TokenKeyID, 32)
	metadataEncoder.WriteOpaque16(issuerName)
	metadataEncoder.WriteOpaque16(originInfo)
	metadataEncoder.WritePreHash(issuerMetadataHash)
	metadata, err = metadataEncoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	authenticatorInput := wire.NewEncoder()
	authenticatorInput.WriteUint16(uint16(proof.ProofType))
	authenticatorInput.WriteOpaqueFixed(proof.TokenNonce, 32)
	authenticatorInput.WriteOpaqueFixed(challengeDigest, 32)
	authenticatorInput.WriteOpaqueFixed(proof.TokenKeyID, 32)
	authenticatorInputBytes, err := authenticatorInput.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	authenticatorHash = auroratrust.AuthenticatorInputHash(authenticatorInputBytes)
	return metadata, challengeDigest, authenticatorHash
}

func rb(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
