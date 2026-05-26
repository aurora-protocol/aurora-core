package relay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/failure"
	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestRelayFailureKindsUseCoreClassifier(t *testing.T) {
	var kind failure.Kind = FailureBadAccessHint
	got := failure.Classify(kind)
	if got.Action != failure.CoverOrigin || got.LogKey != "f0001" {
		t.Fatalf("relay failure kind is not core-classified: %+v", got)
	}
}

func TestInvalidProbeResponsesAreCoverNeutral(t *testing.T) {
	g := Gateway{Origin: StaticOrigin{Status: 200, Body: []byte("<html>ok</html>")}}
	cases := []FailureKind{FailureBadAccessHint, FailureReplayedHint, FailureBadAEADTag, FailureWrongSuite, FailureMalformedFlowOpen, FailureMalformedKeyUpdate}
	first := g.HandleFailure(cases[0])
	for _, kind := range cases[1:] {
		got := g.HandleFailure(kind)
		if got.Status != first.Status || string(got.Body) != string(first.Body) || got.CloseCode != first.CloseCode {
			t.Fatalf("failure %v produced distinguishable response %+v vs %+v", kind, got, first)
		}
		if strings.Contains(strings.ToLower(string(got.Body)), "aurora") {
			t.Fatalf("cover response leaked protocol name")
		}
	}
}

func TestRelaySessionDoesNotReleaseAdmissionBeforePreludeVerification(t *testing.T) {
	s := NewSession()
	if err := s.ReceiveAdmission([]byte("proof")); err == nil {
		t.Fatalf("admission accepted before prelude verification")
	}
	if err := s.MarkPreludeVerified(registry.SuiteHybrid768AESGCM); err != nil {
		t.Fatal(err)
	}
	if err := s.ReceiveAdmission([]byte("proof")); err != nil {
		t.Fatalf("admission after prelude verification failed: %v", err)
	}
}

func TestExitPolicyBlocksPrivateTargetsByDefault(t *testing.T) {
	p := DefaultExitPolicy()
	for _, target := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "192.168.1.1", "100.64.0.1", "198.18.0.1", "203.0.113.1", "224.0.0.1"} {
		if p.AllowIP(target) {
			t.Fatalf("private target %s allowed by default", target)
		}
	}
	if !p.AllowIP("93.184.216.34") {
		t.Fatalf("public target unexpectedly rejected")
	}
}

func TestExitFlowHandlerRejectsPolicyDeniedFlowBeforeOpen(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	open := relayUDPFlowOpen(20, []byte{10, 0, 0, 1})
	frames, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100)
	if err == nil {
		t.Fatalf("private target flow was accepted")
	}
	if len(frames) != 0 {
		t.Fatalf("policy denied flow emitted frames: %+v", frames)
	}
	if _, ok := handler.FlowState(20); ok {
		t.Fatalf("policy denied flow mutated state")
	}
}

func TestExitFlowHandlerEmitsUDPTargetConfirmForClientSuppliedIP(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	handler.UDPConfirmTTLSeconds = 120
	open := relayUDPFlowOpen(21, []byte{93, 184, 216, 34})
	frames, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected one UDP target confirm frame, got %+v", frames)
	}
	confirm := protocol.DecodeUDPTargetConfirm(wire.NewReader(frames[0].Payload))
	if frames[0].FrameType != registry.FrameUDPTargetConfirm || frames[0].FlowID != 21 {
		t.Fatalf("unexpected UDP target confirm frame: %+v", frames[0])
	}
	if confirm.FlowID != 21 || confirm.TargetKind != coreflow.TargetKindIPv4 || string(confirm.SelectedIP) != string([]byte{93, 184, 216, 34}) || confirm.SelectedPort != 443 {
		t.Fatalf("unexpected UDP target confirm payload: %+v", confirm)
	}
	if confirm.TTLSeconds != 120 || confirm.ResolutionSource != protocol.UDPResolutionClientSuppliedIP {
		t.Fatalf("unexpected UDP target confirm metadata: %+v", confirm)
	}
	if _, ok := handler.FlowState(21); !ok {
		t.Fatalf("accepted UDP flow was not tracked")
	}
}

func TestExitFlowHandlerCapsUDPTargetConfirmTTL(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	handler.UDPConfirmTTLSeconds = 90000
	open := relayUDPFlowOpen(22, []byte{93, 184, 216, 35})
	frames, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100)
	if err != nil {
		t.Fatal(err)
	}
	confirm := protocol.DecodeUDPTargetConfirm(wire.NewReader(frames[0].Payload))
	if confirm.TTLSeconds != 86400 {
		t.Fatalf("UDP target confirm TTL was not capped: %d", confirm.TTLSeconds)
	}
	state, ok := handler.FlowState(22)
	if !ok {
		t.Fatalf("accepted UDP flow was not tracked")
	}
	if state.TTLSeconds != 86400 {
		t.Fatalf("flow TTL was not capped: %d", state.TTLSeconds)
	}
}

func TestExitFlowHandlerRejectsMismatchedFlowIDBeforeOpen(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	open := relayUDPFlowOpen(30, []byte{93, 184, 216, 34})
	frame := flowOpenFrame(t, open)
	frame.FlowID = 31
	if _, err := handler.HandleFlowOpenFrame(frame, 100); err == nil {
		t.Fatalf("mismatched flow_id was accepted")
	}
	if _, ok := handler.FlowState(30); ok {
		t.Fatalf("mismatched flow_id mutated payload flow state")
	}
	if _, ok := handler.FlowState(31); ok {
		t.Fatalf("mismatched flow_id mutated frame flow state")
	}
}

func TestAdmissionPolicyRejectsVOPRFWithoutVerifierService(t *testing.T) {
	proof := relayAdmissionProof(registry.ProofVOPRFP384SHA384)
	if err := (AdmissionPolicy{NowUnix: 20}).AllowsProof(proof); err == nil {
		t.Fatalf("VOPRF proof accepted without verifier service")
	}
	service := protocol.IssuerVerifierServiceRecord{
		ServiceID:             []byte("service-id-0001"),
		ServiceKind:           registry.VerifierServiceKindVOPRF,
		ServiceProtocolID:     registry.IssuerVerifierVOPRFMTLS13,
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{proof.RelayBucketID},
		RequestAuthPolicyID:   7,
		ValidFromUnix:         10,
		ValidUntilUnix:        30,
		ServiceStatus:         registry.IssuerStatusActive,
	}
	policy := AdmissionPolicy{
		VerifierServices: []protocol.IssuerVerifierServiceRecord{service},
		RequestAuth:      map[uint64]bool{7: true},
		NowUnix:          20,
	}
	if err := policy.AllowsProof(proof); err == nil {
		t.Fatalf("VOPRF proof accepted without verifier client")
	}
	verifier := &recordingVOPRFVerifier{}
	policy.VOPRFVerifier = verifier
	if err := policy.AllowsProof(proof); err != nil {
		t.Fatalf("authorized VOPRF proof rejected: %v", err)
	}
	if verifier.calls != 1 || string(verifier.serviceID) != string(service.ServiceID) {
		t.Fatalf("VOPRF verifier was not called with matched service: %+v", verifier)
	}
	verifier.err = errors.New("bad token")
	if err := policy.AllowsProof(proof); err == nil {
		t.Fatalf("VOPRF verifier rejection was ignored")
	}
}

func TestAdmissionPolicyRequiresBlindRSAVerifier(t *testing.T) {
	proof := relayAdmissionProof(registry.ProofBlindRSA2048)
	if err := (AdmissionPolicy{}).AllowsProof(proof); err == nil {
		t.Fatalf("Blind RSA proof accepted without verifier")
	}
	verifier := &recordingBlindRSAVerifier{}
	if err := (AdmissionPolicy{BlindRSAVerifier: verifier}).AllowsProof(proof); err != nil {
		t.Fatalf("verified Blind RSA proof rejected: %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("Blind RSA verifier was not called")
	}
	verifier.err = errors.New("bad token")
	if err := (AdmissionPolicy{BlindRSAVerifier: verifier}).AllowsProof(proof); err == nil {
		t.Fatalf("Blind RSA verifier rejection was ignored")
	}
}

func TestAdmissionPolicyBlindRSAUsesIssuerMetadataVerifier(t *testing.T) {
	proof, metadata := relayBlindRSAProofAndMetadata(t)
	verifier := MetadataBlindRSAVerifier{IssuerMetadata: []protocol.IssuerMetadata{metadata}, NowUnix: 100}
	if err := (AdmissionPolicy{BlindRSAVerifier: verifier, NowUnix: 100}).AllowsProof(proof); err != nil {
		t.Fatalf("metadata-backed Blind RSA proof rejected: %v", err)
	}
	verifier.IssuerMetadata = nil
	if err := (AdmissionPolicy{BlindRSAVerifier: verifier, NowUnix: 100}).AllowsProof(proof); err == nil {
		t.Fatalf("Blind RSA proof accepted without issuer metadata")
	}
	verifier.IssuerMetadata = []protocol.IssuerMetadata{metadata, metadata}
	if err := (AdmissionPolicy{BlindRSAVerifier: verifier, NowUnix: 100}).AllowsProof(proof); err == nil {
		t.Fatalf("Blind RSA proof accepted with ambiguous issuer metadata")
	}
}

func TestAdmissionPolicyRejectsStructurallyInvalidProofBeforeVerifier(t *testing.T) {
	for name, mutate := range map[string]func(*protocol.AdmissionProof){
		"expired": func(proof *protocol.AdmissionProof) {
			proof.ExpiryUnix = 20
		},
		"unsupported version": func(proof *protocol.AdmissionProof) {
			proof.ProofVersion = 0
		},
		"bad redemption hash": func(proof *protocol.AdmissionProof) {
			proof.RedemptionContextHash = bytesOf(0x55, 47)
		},
		"bad token nonce": func(proof *protocol.AdmissionProof) {
			proof.TokenNonce = bytesOf(0x56, 31)
		},
		"unknown critical extension": func(proof *protocol.AdmissionProof) {
			proof.Extensions = []protocol.Extension{{
				ExtensionType: 0x7002,
				Critical:      true,
				Body:          []byte("required"),
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			proof := relayAdmissionProof(registry.ProofBlindRSA2048)
			mutate(&proof)
			verifier := &recordingBlindRSAVerifier{}
			if err := (AdmissionPolicy{BlindRSAVerifier: verifier, NowUnix: 20}).AllowsProof(proof); err == nil {
				t.Fatalf("structurally invalid admission proof accepted")
			}
			if verifier.calls != 0 {
				t.Fatalf("structurally invalid proof reached verifier")
			}
		})
	}
}

func TestGatewayOwnedCapsuleFailureDoesNotForwardBody(t *testing.T) {
	origin := &recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}
	g := Gateway{Origin: origin}
	resp := g.HandleCoverRequest(CoverRequest{
		Template: coverTemplateForRelayTest(),
		ClassID:  1,
		Kind:     CoverRequestCapsule,
		Body:     []byte("encrypted-bootstrap-body"),
		Failure:  FailureBadAEADTag,
	})
	if resp.Status != 200 || string(resp.Body) != "cover" {
		t.Fatalf("unexpected cover response: %+v", resp)
	}
	if origin.forwarded != 0 {
		t.Fatalf("failed gateway-owned capsule body was forwarded upstream")
	}
}

type recordingBlindRSAVerifier struct {
	calls int
	err   error
}

func (v *recordingBlindRSAVerifier) VerifyBlindRSA2048(_ protocol.AdmissionProof) error {
	v.calls++
	return v.err
}

type recordingVOPRFVerifier struct {
	calls     int
	serviceID []byte
	err       error
}

func (v *recordingVOPRFVerifier) VerifyVOPRF(_ protocol.AdmissionProof, service protocol.IssuerVerifierServiceRecord) error {
	v.calls++
	v.serviceID = append([]byte(nil), service.ServiceID...)
	return v.err
}

func TestOriginPassThroughForwardsVerbatim(t *testing.T) {
	origin := &recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}
	g := Gateway{Origin: origin}
	body := []byte("ordinary-origin-body")
	resp := g.HandleCoverRequest(CoverRequest{
		Template: coverTemplateForRelayTest(),
		ClassID:  2,
		Kind:     CoverRequestOrdinary,
		Body:     body,
	})
	if resp.Status != 204 || origin.forwarded != 1 || string(origin.lastBody) != string(body) {
		t.Fatalf("pass-through request was not forwarded verbatim: resp=%+v origin=%+v", resp, origin)
	}
}

func TestSidecarOriginOrdinaryRequestForwardsToTrustedSidecar(t *testing.T) {
	origin := &recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}
	g := Gateway{Origin: origin}
	body := []byte("ordinary-sidecar-body")
	resp := g.HandleCoverRequest(CoverRequest{
		Template: coverTemplateForRelayTest(),
		ClassID:  3,
		Kind:     CoverRequestOrdinary,
		Body:     body,
	})
	if resp.Status != 206 || origin.sidecarForwarded != 1 || string(origin.sidecarBody) != string(body) {
		t.Fatalf("sidecar ordinary request was not forwarded to trusted sidecar: resp=%+v origin=%+v", resp, origin)
	}
}

func TestSidecarOriginFailureConsumesBodyAndRecordsRedactedLog(t *testing.T) {
	origin := &recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}
	g := Gateway{Origin: origin}
	resp := g.HandleCoverRequest(CoverRequest{
		Template: coverTemplateForRelayTest(),
		ClassID:  3,
		Kind:     CoverRequestCapsule,
		Body:     []byte("raw sensitive bootstrap body"),
		Failure:  FailureBadAEADTag,
	})
	if resp.Status != 200 || string(resp.Body) != "cover" {
		t.Fatalf("unexpected sidecar cover response: %+v", resp)
	}
	if origin.sidecarForwarded != 0 {
		t.Fatalf("failed sidecar capsule body was forwarded upstream")
	}
	if origin.failureLogs != 1 || origin.lastFailureLog.Code != failure.BadAEADTag.LogKey() {
		t.Fatalf("redacted sidecar failure log mismatch: %+v", origin)
	}
	if len(origin.lastFailureLog.Body) != 0 {
		t.Fatalf("sidecar failure log retained raw body: %+v", origin.lastFailureLog)
	}
}

type recordingOrigin struct {
	normal           Response
	forwarded        int
	lastBody         []byte
	sidecarForwarded int
	sidecarBody      []byte
	failureLogs      int
	lastFailureLog   RedactedFailureLog
}

func (o *recordingOrigin) NormalResponse() Response {
	return o.normal
}

func (o *recordingOrigin) ForwardRequest(body []byte) Response {
	o.forwarded++
	o.lastBody = append([]byte(nil), body...)
	return Response{Status: 204}
}

func (o *recordingOrigin) ForwardSidecarRequest(body []byte) Response {
	o.sidecarForwarded++
	o.sidecarBody = append([]byte(nil), body...)
	return Response{Status: 206}
}

func (o *recordingOrigin) RecordSidecarFailure(log RedactedFailureLog) {
	o.failureLogs++
	o.lastFailureLog = log
}

func coverTemplateForRelayTest() protocol.CoverTemplate {
	return protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{{
		ClassID:         1,
		ClassType:       registry.RequestGatewayOwnedSlot,
		MayCarryPrelude: true,
		MayCarryCapsule: true,
	}, {
		ClassID:   2,
		ClassType: registry.RequestOriginPassThrough,
	}, {
		ClassID:         3,
		ClassType:       registry.RequestSidecarOriginSlot,
		MayCarryPrelude: true,
		MayCarryCapsule: true,
	}}}
}

func relayUDPFlowOpen(flowID uint64, target []byte) protocol.FlowOpen {
	return protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         coreflow.FlowKindUDPAssociation,
		TargetKind:       coreflow.TargetKindIPv4,
		TargetHost:       append([]byte(nil), target...),
		TargetPort:       443,
		UDPFQDNMode:      coreflow.UDPFQDNClientResolvedNameBinding,
		NameBindingID:    []byte("binding-id-00001"),
		DNSAnswerSetHash: bytesOf(0xdd, 48),
		LocalBindingMode: coreflow.LocalBindingTransparentFakeIP,
		PriorityClass:    coreflow.PriorityRealtime,
	}
}

func flowOpenFrame(t *testing.T, open protocol.FlowOpen) protocol.AuroraFrame {
	t.Helper()
	payload, err := protocol.Encode(open)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.AuroraFrame{
		FrameType: registry.FrameFlowOpen,
		FlowID:    open.FlowID,
		Payload:   payload,
	}
}

func relayAdmissionProof(proofType uint64) protocol.AdmissionProof {
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             proofType,
		IssuerID:              bytesOf(0x10, 16),
		TokenKeyID:            bytesOf(0x11, 32),
		RelayBucketID:         []byte("1234567890abcdef"),
		TokenScopeID:          bytesOf(0x12, 16),
		ExpiryUnix:            200,
		TokenNonce:            bytesOf(0x13, 32),
		RedemptionContextHash: bytesOf(0x14, 48),
		TokenAuthenticator:    []byte("authenticator"),
	}
	switch proofType {
	case registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048:
		proof.TokenPublicMetadata = relayTokenMetadataForProof(proof)
	}
	return proof
}

func relayTokenMetadataForProof(proof protocol.AdmissionProof) []byte {
	metadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: bytesOf(0x90, 32),
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             []byte("issuer.example"),
		OriginInfo:             []byte("origin.example"),
		IssuerMetadataHash:     bytesOf(0x91, 48),
	}
	encoded, err := protocol.Encode(metadata)
	if err != nil {
		panic(err)
	}
	return encoded
}

func relayBlindRSAProofAndMetadata(t *testing.T) (protocol.AdmissionProof, protocol.IssuerMetadata) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := relayRSAPSSPublicKeyForTest(t, &priv.PublicKey)
	keyID := sha256.Sum256(keyDER)
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              bytesOf(0xa0, 16),
		TokenKeyID:            keyID[:],
		RelayBucketID:         bytesOf(0xa1, 16),
		TokenScopeID:          bytesOf(0xa2, 16),
		ExpiryUnix:            200,
		TokenNonce:            bytesOf(0xa3, 32),
		RedemptionContextHash: bytesOf(0xa4, 48),
	}
	metadata := protocol.IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            append([]byte(nil), proof.IssuerID...),
		ValidFromUnix:       10,
		ValidUntilUnix:      200,
		IssuerName:          []byte("issuer.example"),
		SupportedProofTypes: []uint64{registry.ProofBlindRSA2048},
		TokenKeyMappings: []protocol.IssuerTokenKeyRecord{{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: append([]byte(nil), proof.TokenKeyID...),
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       append([]byte(nil), keyDER...),
			},
			ValidFromUnix:  10,
			ValidUntilUnix: 200,
			KeyStatus:      registry.IssuerStatusActive,
		}},
		OriginInfoPolicies: []protocol.OriginInfoPolicy{{
			PolicyID:       1,
			OriginInfo:     []byte("origin.example"),
			ValidFromUnix:  10,
			ValidUntilUnix: 200,
		}},
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         append([]byte(nil), proof.RelayBucketID...),
			TokenScopeID:          append([]byte(nil), proof.TokenScopeID...),
			AllowedOriginPolicyID: []uint64{1},
			ValidFromUnix:         10,
			ValidUntilUnix:        200,
		}},
		MetadataSigningKeyID: bytesOf(0xa5, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
	challengeDigest, err := admission.RFC9577TokenChallengeDigest(proof.ProofType, metadata.IssuerName, []byte("origin.example"), proof.RedemptionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	metadataHash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		t.Fatal(err)
	}
	tokenMetadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: challengeDigest,
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             append([]byte(nil), metadata.IssuerName...),
		OriginInfo:             []byte("origin.example"),
		IssuerMetadataHash:     metadataHash,
	}
	proof.TokenPublicMetadata, err = protocol.Encode(tokenMetadata)
	if err != nil {
		t.Fatal(err)
	}
	authenticatorInput, err := admission.RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(authenticatorInput)
	proof.TokenAuthenticator, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA384, digest[:], &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       crypto.SHA384,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof, metadata
}

func relayRSAPSSPublicKeyForTest(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	rsaKey, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
		},
		SubjectPublicKey: asn1.BitString{Bytes: rsaKey, BitLength: len(rsaKey) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
