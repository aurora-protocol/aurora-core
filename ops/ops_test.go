package ops

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		RelayEpochValidUntilUnix:  900,
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
		RelayEpochValidUntilUnix:  900,
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

func TestBuildIssuerVerifierRequestUsesRelayEpochRetention(t *testing.T) {
	service := verifierServiceRecord()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	cache := &retentionRecordingCache{}
	if _, _, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		RelayEpochValidUntilUnix:  900,
		HandshakeBindingContext:   handshakeBinding,
		AdmissionContextHash:      admissionContextHash,
		ChallengeDigest:           rb(0x32, 32),
		AuthenticatorInputHash:    rb(0x33, 48),
		TokenSpentCache:           cache,
		BootstrapDedupCache:       cache,
		RequestNonce:              rb(0x34, 32),
		RequestTimeUnix:           100,
		NowUnix:                   100,
		RequestAuthImplemented:    true,
	}); err != nil {
		t.Fatal(err)
	}
	if len(cache.deadlines) != 2 || cache.deadlines[0] != 1100 || cache.deadlines[1] != 1500 {
		t.Fatalf("retention deadlines = %v, want [1100 1500]", cache.deadlines)
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
		RelayEpochValidUntilUnix:  900,
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
		RelayEpochValidUntilUnix:  900,
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
		RelayEpochValidUntilUnix:  900,
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
				RelayEpochValidUntilUnix:  900,
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
		RelayEpochValidUntilUnix:  900,
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
		RelayEpochValidUntilUnix:  900,
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
		RelayEpochValidUntilUnix:  900,
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
			RelayEpochValidUntilUnix:  900,
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

func TestMTLSIssuerVerifierTransportExchangesSignedResponse(t *testing.T) {
	service := verifierServiceRecord()
	serviceSigner := attachVerifierServiceSigningKey(t, &service)
	server, client := startVerifierServiceTLSServer(t, &service, serviceSigner, serviceSigner)
	defer server.Close()

	err := VerifyIssuerVerifierService(IssuerVerifierServiceVerificationInput{
		Request:   verifierServiceVerificationRequest(t, service),
		Transport: MTLSIssuerVerifierTransport{Client: client},
	})
	if err != nil {
		t.Fatalf("mTLS verifier service exchange failed: %v", err)
	}
}

func TestMTLSIssuerVerifierTransportRejectsServiceAuthKeyMismatch(t *testing.T) {
	service := verifierServiceRecord()
	serviceSigner := attachVerifierServiceSigningKey(t, &service)
	mismatchedTLSKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, client := startVerifierServiceTLSServer(t, &service, mismatchedTLSKey, serviceSigner)
	defer server.Close()

	err = VerifyIssuerVerifierService(IssuerVerifierServiceVerificationInput{
		Request:   verifierServiceVerificationRequest(t, service),
		Transport: MTLSIssuerVerifierTransport{Client: client},
	})
	var failureErr *failure.Error
	if !errors.As(err, &failureErr) || failureErr.Kind != failure.VerifierUnavailable {
		t.Fatalf("service auth key mismatch error = %T %[1]v, want %v", err, failure.VerifierUnavailable)
	}
}

func TestMTLSIssuerVerifierTransportDoesNotFollowRedirects(t *testing.T) {
	service := verifierServiceRecord()
	serviceSigner := attachVerifierServiceSigningKey(t, &service)
	server, client := startVerifierServiceTLSServer(t, &service, serviceSigner, serviceSigner)
	defer server.Close()

	redirected := make(chan struct{}, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected <- struct{}{}
	}))
	defer destination.Close()
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	})

	_, err := (MTLSIssuerVerifierTransport{Client: client}).ExchangeIssuerVerifier(service, verifierTransportRequest(t, service))
	if err == nil {
		t.Fatalf("redirecting verifier response was accepted")
	}
	select {
	case <-redirected:
		t.Fatalf("verifier request followed an untrusted redirect")
	default:
	}
}

func TestMTLSIssuerVerifierTransportBoundsDefaultRequestLifetime(t *testing.T) {
	service := verifierServiceRecord()
	serviceSigner := attachVerifierServiceSigningKey(t, &service)
	server, client := startVerifierServiceTLSServer(t, &service, serviceSigner, serviceSigner)
	defer server.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	releaseServer := func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}
	defer releaseServer()
	server.Config.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})

	request := verifierTransportRequest(t, service)
	result := make(chan error, 1)
	go func() {
		_, err := (MTLSIssuerVerifierTransport{Client: client}).ExchangeIssuerVerifier(service, request)
		result <- err
	}()
	select {
	case <-started:
	case err := <-result:
		t.Fatalf("verifier request completed before reaching service: %v", err)
	case <-time.After(time.Second):
		t.Fatalf("verifier request did not reach TLS service")
	}
	select {
	case err := <-result:
		releaseServer()
		if err == nil {
			t.Fatalf("slow verifier response was accepted")
		}
	case <-time.After(issuerVerifierRequestTimeout + 2*time.Second):
		releaseServer()
		<-result
		t.Fatalf("verifier transport has no bounded default request lifetime")
	}
}

func verifierTransportRequest(t *testing.T, service protocol.IssuerVerifierServiceRecord) protocol.IssuerVerifierRequest {
	t.Helper()
	req, _, err := BuildIssuerVerifierRequest(verifierServiceVerificationRequest(t, service))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestIssuerVerifierEndpointRejectsURLComponentsInAuthority(t *testing.T) {
	for _, authority := range []string{
		":443",
		"verifier.example/path",
		"user@verifier.example",
		"verifier.example?query=yes",
		"verifier.example#fragment",
		"//verifier.example",
	} {
		t.Run(authority, func(t *testing.T) {
			service := verifierServiceRecord()
			service.ServiceLocator = protocol.RoutingRecord{
				LocatorType: registry.LocatorAuthority,
				LocatorBody: []byte(authority),
			}
			if _, err := issuerVerifierEndpoint(service); err == nil {
				t.Fatalf("authority %q with URL components was accepted", authority)
			}
		})
	}
}

func TestIssuerVerifierHTTPClientRejectsUnverifiedTLS(t *testing.T) {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := issuerVerifierHTTPClient(client); err == nil {
		t.Fatalf("verifier client accepted disabled certificate verification")
	}
}

func TestIssuerVerifierHTTPClientClonesTLSConstraints(t *testing.T) {
	sourceTLS := &tls.Config{}
	source := &http.Client{
		Transport: &http.Transport{TLSClientConfig: sourceTLS},
		Timeout:   10 * time.Second,
	}
	client, err := issuerVerifierHTTPClient(source)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("verifier client did not require TLS 1.3")
	}
	if client.Timeout != issuerVerifierRequestTimeout {
		t.Fatalf("verifier client timeout = %v, want %v", client.Timeout, issuerVerifierRequestTimeout)
	}
	if sourceTLS.MinVersion != 0 || source.Timeout != 10*time.Second {
		t.Fatalf("verifier client mutated caller configuration")
	}
}

func TestReadIssuerVerifierResponseRejectsOversizedBody(t *testing.T) {
	for _, response := range []*http.Response{
		{
			Body:          io.NopCloser(strings.NewReader("x")),
			ContentLength: issuerVerifierMaxResponseSize + 1,
		},
		{
			Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", issuerVerifierMaxResponseSize+1))),
			ContentLength: -1,
		},
	} {
		if _, err := readIssuerVerifierResponse(response); err == nil {
			t.Fatalf("oversized verifier response was accepted")
		}
	}
}

func verifierServiceVerificationRequest(t *testing.T, service protocol.IssuerVerifierServiceRecord) IssuerVerifierRequestInput {
	t.Helper()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)
	return IssuerVerifierRequestInput{
		Service:                   service,
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        rb(0x30, 48),
		RelayDescriptorHash:       rb(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		RelayEpochValidUntilUnix:  900,
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
	}
}

func startVerifierServiceTLSServer(t *testing.T, service *protocol.IssuerVerifierServiceRecord, serverKey, responseKey *ecdsa.PrivateKey) (*httptest.Server, *http.Client) {
	t.Helper()
	serverCert := selfSignedTLSTestCertificate(t, serverKey)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := selfSignedTLSTestCertificate(t, clientKey)
	roots := x509.NewCertPool()
	roots.AddCert(serverCert.Leaf)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 {
			t.Errorf("request did not use TLS 1.3 mutual authentication")
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		reader := wire.NewReader(body)
		req := protocol.DecodeIssuerVerifierRequest(reader)
		if reader.Err() != nil || !reader.EOF() {
			t.Errorf("decode verifier request failed: err=%v eof=%v", reader.Err(), reader.EOF())
			return
		}
		requestHash, err := IssuerVerifierRequestHash(req)
		if err != nil {
			t.Errorf("request hash failed: %v", err)
			return
		}
		resp := protocol.IssuerVerifierResponse{
			ResponseVersion: registry.Version20,
			ServiceID:       append([]byte(nil), service.ServiceID...),
			RequestHash:     requestHash,
			Decision:        registry.VerifierDecisionAccept,
			TokenSpentKey:   append([]byte(nil), req.TokenSpentKey...),
			ValidUntilUnix:  req.RequestTimeUnix + 100,
			ResponseNonce:   rb(0x40, 32),
		}
		signVerifierResponse(t, responseKey, &resp)
		encoded, err := protocol.Encode(resp)
		if err != nil {
			t.Errorf("encode verifier response failed: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	service.ServiceLocator = protocol.RoutingRecord{
		RoutingRecordID:   rb(0x70, 16),
		TransportFamilyID: registry.IssuerVerifierVOPRFMTLS13,
		LocatorType:       registry.LocatorAuthority,
		LocatorBody:       []byte(server.Listener.Addr().String()),
		Priority:          1,
		NotBeforeUnix:     10,
		NotAfterUnix:      900,
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots,
			Certificates: []tls.Certificate{clientCert},
		}},
	}
	return server, client
}

func selfSignedTLSTestCertificate(t *testing.T, priv *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
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

type retentionRecordingCache struct{ deadlines []uint64 }

func (*retentionRecordingCache) InsertIfAbsent([]byte) (bool, error) { return true, nil }
func (*retentionRecordingCache) Has([]byte) bool                     { return false }
func (c *retentionRecordingCache) InsertIfAbsentUntil(_ []byte, deadline, _ uint64) (bool, error) {
	c.deadlines = append(c.deadlines, deadline)
	return true, nil
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
		PublicKey:       mustECDSAPublicKeyBytes(t, &priv.PublicKey),
	}
	return priv
}

func mustECDSAPublicKeyBytes(t testing.TB, key *ecdsa.PublicKey) []byte {
	t.Helper()
	encoded, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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
