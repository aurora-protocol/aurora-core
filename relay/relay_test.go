package relay

import (
	"errors"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/failure"
	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
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

type recordingOrigin struct {
	normal    Response
	forwarded int
	lastBody  []byte
}

func (o *recordingOrigin) NormalResponse() Response {
	return o.normal
}

func (o *recordingOrigin) ForwardRequest(body []byte) Response {
	o.forwarded++
	o.lastBody = append([]byte(nil), body...)
	return Response{Status: 204}
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
	return protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             proofType,
		IssuerID:              bytesOf(0x10, 16),
		TokenKeyID:            bytesOf(0x11, 32),
		RelayBucketID:         []byte("1234567890abcdef"),
		TokenScopeID:          bytesOf(0x12, 16),
		ExpiryUnix:            200,
		TokenNonce:            bytesOf(0x13, 32),
		RedemptionContextHash: bytesOf(0x14, 48),
		TokenPublicMetadata:   []byte("metadata"),
		TokenAuthenticator:    []byte("authenticator"),
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
