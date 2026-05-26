package relay

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/failure"
	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/ops"
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

func TestGatewayActiveProbeHarnessConsumesFailuresAsCoverOrigin(t *testing.T) {
	report, err := RunGatewayActiveProbeHarness(failure.ActiveProbeCases())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("gateway active-probe harness failed: %+v", report)
	}
	if report.NormalResponses != len(failure.ActiveProbeCases()) || report.ForwardedRequests != 0 || report.SidecarForwardedRequests != 0 || report.FailureLogs != 0 {
		t.Fatalf("gateway active-probe side effects were not cover-neutral: %+v", report)
	}
	for _, finding := range report.Cases {
		if !finding.Passed {
			t.Fatalf("gateway active-probe case failed: %+v", finding)
		}
		if finding.Response.Status != report.CanonicalResponse.Status || !bytes.Equal(finding.Response.Body, report.CanonicalResponse.Body) || finding.Response.CloseCode != report.CanonicalResponse.CloseCode {
			t.Fatalf("gateway active-probe case was distinguishable: %+v canonical=%+v", finding, report.CanonicalResponse)
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

func TestExitFlowHandlerRejectsLoopbackDomainBeforeOpen(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	open := relayTCPFlowOpen(23, "localhost")
	frames, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100)
	if err == nil {
		t.Fatalf("loopback domain flow was accepted")
	}
	if len(frames) != 0 {
		t.Fatalf("policy denied domain emitted frames: %+v", frames)
	}
	if _, ok := handler.FlowState(23); ok {
		t.Fatalf("policy denied domain mutated state")
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

func TestExitFlowHandlerProcessesFrameBlockOpenThenStreamData(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	open := relayTCPFlowOpen(40, "example.com")
	data, err := protocol.NewStreamDataFrame(40, []byte("GET / HTTP/2\r\n\r\n"), 0x01)
	if err != nil {
		t.Fatal(err)
	}

	result, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		flowOpenFrame(t, open),
		data,
	}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.OutboundFrames) != 0 {
		t.Fatalf("TCP frame block emitted unexpected response frames: %+v", result.OutboundFrames)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected open and stream events, got %+v", result.Events)
	}
	if result.Events[0].Kind != ExitEventFlowOpened || result.Events[0].FlowID != 40 || result.Events[0].Flow.Kind != coreflow.FlowKindTCPStream {
		t.Fatalf("unexpected flow-open event: %+v", result.Events[0])
	}
	if result.Events[1].Kind != ExitEventStreamData || result.Events[1].FlowID != 40 || !bytes.Equal(result.Events[1].Data, []byte("GET / HTTP/2\r\n\r\n")) {
		t.Fatalf("unexpected stream-data event: %+v", result.Events[1])
	}
	result.Events[1].Data[0] = 'X'
	if bytes.Equal(data.Payload, result.Events[1].Data) {
		t.Fatalf("exit event reused caller-owned data slice")
	}
}

func TestExitFlowHandlerProcessesUDPBlockWithTargetConfirmAndDatagramEvent(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	handler.UDPConfirmTTLSeconds = 120
	open := relayUDPFlowOpen(41, []byte{93, 184, 216, 34})
	datagram, err := protocol.NewDatagramDataFrame(41, []byte("payload"), 0)
	if err != nil {
		t.Fatal(err)
	}

	result, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		flowOpenFrame(t, open),
		datagram,
	}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.OutboundFrames) != 1 || result.OutboundFrames[0].FrameType != registry.FrameUDPTargetConfirm || result.OutboundFrames[0].FlowID != 41 {
		t.Fatalf("UDP frame block did not emit target confirmation: %+v", result.OutboundFrames)
	}
	if len(result.Events) != 2 || result.Events[0].Kind != ExitEventFlowOpened || result.Events[1].Kind != ExitEventDatagramData {
		t.Fatalf("unexpected UDP frame block events: %+v", result.Events)
	}
	if result.Events[1].Flow.Kind != coreflow.FlowKindUDPAssociation || !bytes.Equal(result.Events[1].Data, []byte("payload")) {
		t.Fatalf("datagram event lost flow state or payload: %+v", result.Events[1])
	}
}

func TestExitFlowHandlerRejectsDataBeforeFlowOpen(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	data, err := protocol.NewStreamDataFrame(42, []byte("early"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{data}}, 100); err == nil {
		t.Fatalf("stream data before FLOW_OPEN was accepted")
	}
	if _, ok := handler.FlowState(42); ok {
		t.Fatalf("data-only frame block mutated flow state")
	}
}

func TestExitFlowHandlerIgnoresPaddingInFrameBlock(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	open := relayTCPFlowOpen(43, "example.com")
	data, err := protocol.NewStreamDataFrame(43, []byte("payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		{FrameType: registry.FramePadding},
		flowOpenFrame(t, open),
		{FrameType: registry.FramePadding},
		data,
	}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 2 || result.Events[0].Kind != ExitEventFlowOpened || result.Events[1].Kind != ExitEventStreamData {
		t.Fatalf("padding changed exit frame events: %+v", result.Events)
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

func TestExitFlowHandlerAppliesFlowOpenRateLimitBeforeStateMutation(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	handler.RateLimit = ExitRateLimit{
		WindowSeconds: 60,
		MaxFlowOpens:  1,
	}
	first := relayTCPFlowOpen(50, "example.com")
	if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, first), 100); err != nil {
		t.Fatal(err)
	}
	second := relayTCPFlowOpen(51, "example.net")
	_, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, second), 101)
	var failureErr *failure.Error
	if !errors.As(err, &failureErr) || failureErr.Kind != failure.RateLimited {
		t.Fatalf("second flow open error = %v, want rate-limit failure", err)
	}
	if _, ok := handler.FlowState(51); ok {
		t.Fatalf("rate-limited flow open mutated state")
	}
	if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, second), 161); err != nil {
		t.Fatalf("flow open after rate-limit window rejected: %v", err)
	}
}

func TestExitFlowHandlerAppliesByteRateLimitBeforeActivityMutation(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	handler.RateLimit = ExitRateLimit{
		WindowSeconds: 60,
		MaxFlowOpens:  10,
		MaxBytes:      4,
	}
	open := relayUDPFlowOpen(52, []byte{93, 184, 216, 34})
	if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100); err != nil {
		t.Fatal(err)
	}
	datagram, err := protocol.NewDatagramDataFrame(52, []byte("1234"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{datagram}}, 101); err != nil {
		t.Fatal(err)
	}
	state, ok := handler.FlowState(52)
	if !ok {
		t.Fatalf("accepted flow missing after first datagram")
	}
	if state.LastActivityUnix != 101 {
		t.Fatalf("first datagram activity = %d, want 101", state.LastActivityUnix)
	}
	datagram, err = protocol.NewDatagramDataFrame(52, []byte("5"), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{datagram}}, 102)
	var failureErr *failure.Error
	if !errors.As(err, &failureErr) || failureErr.Kind != failure.RateLimited {
		t.Fatalf("second datagram error = %v, want rate-limit failure", err)
	}
	state, ok = handler.FlowState(52)
	if !ok {
		t.Fatalf("rate-limited flow disappeared")
	}
	if state.LastActivityUnix != 101 {
		t.Fatalf("rate-limited datagram changed activity to %d", state.LastActivityUnix)
	}
}

func TestAdmissionPolicyRejectsVOPRFWithoutVerifierService(t *testing.T) {
	proof := relayAdmissionProof(registry.ProofVOPRFP384SHA384)
	if err := (AdmissionPolicy{NowUnix: 20}).AllowsProof(proof); err == nil {
		t.Fatalf("VOPRF proof accepted without verifier service")
	}
	service, _ := relayVerifierService(t, proof.RelayBucketID)
	policy := AdmissionPolicy{
		VerifierServices: []protocol.IssuerVerifierServiceRecord{service},
		RequestAuth:      map[uint64]bool{7: true},
		NowUnix:          20,
	}
	if err := policy.AllowsProof(proof); err == nil {
		t.Fatalf("proof-only VOPRF path accepted without replay-aware verifier service request")
	}
}

func TestAdmissionPolicyUsesVerifierServiceRequestForVOPRF(t *testing.T) {
	admissionContextHash := bytesOf(0x14, 48)
	issuerMetadataHash := bytesOf(0x91, 48)
	proof := relayVOPRFAdmissionProof(t, issuerMetadataHash, admissionContextHash)
	service, serviceSigner := relayVerifierService(t, proof.RelayBucketID)
	transport := &recordingIssuerVerifierTransport{t: t, signer: serviceSigner}
	tokenCache := admission.NewMemoryReplayCache()
	policy := AdmissionPolicy{
		VerifierServices: []protocol.IssuerVerifierServiceRecord{service},
		RequestAuth:      map[uint64]bool{7: true},
		NowUnix:          20,
		VOPRFTransport:   transport,
	}
	replay := relayReplayProof(t, proof, 77, 1, bytesOf(0x21, 48), admissionContextHash)
	redemptionHash, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	err = policy.AllowsVerifierServiceAdmission(VerifierServiceAdmissionInput{
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        issuerMetadataHash,
		RelayDescriptorHash:       bytesOf(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   bytesOf(0x21, 48),
		AdmissionContextHash:      admissionContextHash,
		RequestNonce:              bytesOf(0x34, 32),
		RequestTimeUnix:           20,
		TokenSpentCache:           tokenCache,
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
	})
	if err != nil {
		t.Fatalf("verifier-service VOPRF admission rejected: %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("verifier transport calls = %d, want 1", transport.calls)
	}
	if !bytes.Equal(transport.request.TokenSpentKey, transport.response.TokenSpentKey) {
		t.Fatalf("verifier response token_spent_key did not use relayed request")
	}
	replay.ClientReplayNonce = bytesOf(0x42, 32)
	replayHash, err := admission.ReplayContextHash(redemptionHash, replay, 77, 1, bytesOf(0x21, 48), admissionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	replay.ReplayContextHash = replayHash
	err = policy.AllowsVerifierServiceAdmission(VerifierServiceAdmissionInput{
		AdmissionProof:            proof,
		ReplayProof:               replay,
		IssuerMetadataHash:        issuerMetadataHash,
		RelayDescriptorHash:       bytesOf(0x31, 48),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ReplayEpochValidUntilUnix: 800,
		HandshakeBindingContext:   bytesOf(0x21, 48),
		AdmissionContextHash:      admissionContextHash,
		RequestNonce:              bytesOf(0x35, 32),
		RequestTimeUnix:           21,
		TokenSpentCache:           tokenCache,
		BootstrapDedupCache:       admission.NewMemoryReplayCache(),
	})
	if err == nil {
		t.Fatalf("replayed VOPRF token with changed replay nonce accepted")
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
	} else {
		var failureErr *failure.Error
		if !errors.As(err, &failureErr) || failureErr.Kind != failure.WrongToken {
			t.Fatalf("Blind RSA verifier rejection = %T %[1]v, want wrong-token failure", err)
		}
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
	} else {
		var failureErr *failure.Error
		if !errors.As(err, &failureErr) || failureErr.Kind != failure.WrongToken {
			t.Fatalf("missing issuer metadata rejection = %T %[1]v, want wrong-token failure", err)
		}
	}
	verifier.IssuerMetadata = []protocol.IssuerMetadata{metadata, metadata}
	if err := (AdmissionPolicy{BlindRSAVerifier: verifier, NowUnix: 100}).AllowsProof(proof); err == nil {
		t.Fatalf("Blind RSA proof accepted with ambiguous issuer metadata")
	} else {
		var failureErr *failure.Error
		if !errors.As(err, &failureErr) || failureErr.Kind != failure.WrongToken {
			t.Fatalf("ambiguous issuer metadata rejection = %T %[1]v, want wrong-token failure", err)
		}
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

type recordingIssuerVerifierTransport struct {
	t        *testing.T
	signer   *ecdsa.PrivateKey
	calls    int
	request  protocol.IssuerVerifierRequest
	response protocol.IssuerVerifierResponse
}

func (v *recordingIssuerVerifierTransport) ExchangeIssuerVerifier(service protocol.IssuerVerifierServiceRecord, req protocol.IssuerVerifierRequest) (protocol.IssuerVerifierResponse, error) {
	v.t.Helper()
	v.calls++
	v.request = req
	requestHash, err := ops.IssuerVerifierRequestHash(req)
	if err != nil {
		v.t.Fatal(err)
	}
	resp := protocol.IssuerVerifierResponse{
		ResponseVersion: registry.Version20,
		ServiceID:       append([]byte(nil), service.ServiceID...),
		RequestHash:     requestHash,
		Decision:        registry.VerifierDecisionAccept,
		TokenSpentKey:   append([]byte(nil), req.TokenSpentKey...),
		ValidUntilUnix:  req.RequestTimeUnix + 100,
		ResponseNonce:   bytesOf(0x40, 32),
	}
	input, err := auroratrust.IssuerVerifierResponseSignatureInput(requestHash, resp)
	if err != nil {
		v.t.Fatal(err)
	}
	resp.ServiceSignature, err = ecdsa.SignASN1(rand.Reader, v.signer, input)
	if err != nil {
		v.t.Fatal(err)
	}
	v.response = resp
	return resp, nil
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

func TestHTTPGatewayForwardsOriginPassThroughRoute(t *testing.T) {
	origin := &recordingHTTPOrigin{recordingOrigin: recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}}
	handler := HTTPGatewayHandler{
		Gateway:  Gateway{Origin: origin},
		Template: coverTemplateForRelayTest(),
		Routes: []HTTPGatewayRoute{{
			Path:    "/assets/app.bin",
			ClassID: 2,
			Kind:    CoverRequestOrdinary,
		}},
	}
	body := []byte("ordinary-origin-body")
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/assets/app.bin", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent || origin.httpForwarded != 1 || origin.lastPath != "/assets/app.bin" || !bytes.Equal(origin.lastHTTPBody, body) {
		t.Fatalf("origin pass-through route was not forwarded verbatim: code=%d origin=%+v", rec.Code, origin)
	}
}

func TestHTTPGatewayOwnedFailureConsumesBodyAtHTTPBoundary(t *testing.T) {
	origin := &recordingHTTPOrigin{recordingOrigin: recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}}
	handler := HTTPGatewayHandler{
		Gateway:  Gateway{Origin: origin},
		Template: coverTemplateForRelayTest(),
		Routes: []HTTPGatewayRoute{{
			Path:    "/bootstrap.bin",
			ClassID: 1,
			Kind:    CoverRequestCapsule,
			Failure: FailureBadAEADTag,
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/bootstrap.bin", strings.NewReader("raw sensitive capsule"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "cover" {
		t.Fatalf("gateway-owned failure did not return ordinary origin response: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if origin.httpForwarded != 0 || origin.httpSidecarForwarded != 0 || origin.forwarded != 0 || origin.sidecarForwarded != 0 {
		t.Fatalf("failed gateway-owned body reached an upstream origin: %+v", origin)
	}
}

func TestHTTPGatewaySidecarFailureRedactsBodyAtHTTPBoundary(t *testing.T) {
	origin := &recordingHTTPOrigin{recordingOrigin: recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}}
	handler := HTTPGatewayHandler{
		Gateway:  Gateway{Origin: origin},
		Template: coverTemplateForRelayTest(),
		Routes: []HTTPGatewayRoute{{
			Path:    "/sidecar/upload",
			ClassID: 3,
			Kind:    CoverRequestCapsule,
			Failure: FailureBadAEADTag,
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/sidecar/upload", strings.NewReader("raw sensitive sidecar capsule"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "cover" {
		t.Fatalf("sidecar failure did not return ordinary origin response: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if origin.httpSidecarForwarded != 0 || origin.sidecarForwarded != 0 {
		t.Fatalf("failed sidecar body was forwarded upstream: %+v", origin)
	}
	if origin.failureLogs != 1 || origin.lastFailureLog.Code != failure.BadAEADTag.LogKey() || len(origin.lastFailureLog.Body) != 0 {
		t.Fatalf("sidecar failure log was not redacted: %+v", origin.lastFailureLog)
	}
}

func TestHTTPGatewayOversizeBodyMapsToCoverOriginWithoutForwarding(t *testing.T) {
	origin := &recordingHTTPOrigin{recordingOrigin: recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}}
	handler := HTTPGatewayHandler{
		Gateway:      Gateway{Origin: origin},
		Template:     coverTemplateForRelayTest(),
		MaxBodyBytes: 4,
		Routes: []HTTPGatewayRoute{{
			Path:    "/assets/app.bin",
			ClassID: 2,
			Kind:    CoverRequestOrdinary,
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/assets/app.bin", strings.NewReader("too-large"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "cover" {
		t.Fatalf("oversize body did not map to cover response: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if origin.httpForwarded != 0 || origin.forwarded != 0 {
		t.Fatalf("oversize body was forwarded upstream: %+v", origin)
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

type recordingHTTPOrigin struct {
	recordingOrigin
	httpForwarded        int
	httpSidecarForwarded int
	lastPath             string
	lastHTTPBody         []byte
}

func (o *recordingHTTPOrigin) ForwardHTTPRequest(req *http.Request, body []byte) Response {
	o.httpForwarded++
	o.lastPath = req.URL.Path
	o.lastHTTPBody = append([]byte(nil), body...)
	return Response{Status: http.StatusNoContent}
}

func (o *recordingHTTPOrigin) ForwardSidecarHTTPRequest(req *http.Request, body []byte) Response {
	o.httpSidecarForwarded++
	o.lastPath = req.URL.Path
	o.lastHTTPBody = append([]byte(nil), body...)
	return Response{Status: http.StatusPartialContent}
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

func relayTCPFlowOpen(flowID uint64, domain string) protocol.FlowOpen {
	return protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         coreflow.FlowKindTCPStream,
		TargetKind:       coreflow.TargetKindDomainName,
		TargetHost:       []byte(domain),
		TargetPort:       443,
		UDPFQDNMode:      coreflow.UDPFQDNNoneIPAuthoritative,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
		LocalBindingMode: coreflow.LocalBindingExplicitProxyAPI,
		PriorityClass:    coreflow.PriorityInteractive,
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

func relayVOPRFAdmissionProof(t *testing.T, issuerMetadataHash, admissionContextHash []byte) protocol.AdmissionProof {
	t.Helper()
	proof := relayAdmissionProof(registry.ProofVOPRFP384SHA384)
	proof.RedemptionContextHash = append([]byte(nil), admissionContextHash...)
	issuerName := []byte("issuer.example")
	originInfo := []byte("origin.example")
	challengeDigest, err := admission.RFC9577TokenChallengeDigest(proof.ProofType, issuerName, originInfo, proof.RedemptionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	metadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: challengeDigest,
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             issuerName,
		OriginInfo:             originInfo,
		IssuerMetadataHash:     append([]byte(nil), issuerMetadataHash...),
	}
	encoded, err := protocol.Encode(metadata)
	if err != nil {
		t.Fatal(err)
	}
	proof.TokenPublicMetadata = encoded
	return proof
}

func relayReplayProof(t *testing.T, proof protocol.AdmissionProof, routeInstanceID uint64, hopIndex uint8, handshakeBinding, admissionContextHash []byte) protocol.ReplayProof {
	t.Helper()
	redemptionHash, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	replay := protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		TokenRedemptionHash: redemptionHash,
		ClientReplayNonce:   bytesOf(0x15, 32),
		ReplayEpochID:       22,
		ReplayWindowID:      bytesOf(0x16, 16),
	}
	replay.ReplayContextHash, err = admission.ReplayContextHash(redemptionHash, replay, routeInstanceID, hopIndex, handshakeBinding, admissionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	return replay
}

func relayVerifierService(t *testing.T, relayBucketID []byte) (protocol.IssuerVerifierServiceRecord, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.IssuerVerifierServiceRecord{
		ServiceID:         []byte("service-id-00001"),
		ServiceKind:       registry.VerifierServiceKindVOPRF,
		ServiceProtocolID: registry.IssuerVerifierVOPRFMTLS13,
		ServiceLocator: protocol.RoutingRecord{
			RoutingRecordID:   bytesOf(0x70, 16),
			TransportFamilyID: registry.IssuerVerifierVOPRFMTLS13,
			LocatorType:       registry.LocatorAuthority,
			LocatorBody:       []byte("verifier.example:443"),
			Priority:          1,
			NotBeforeUnix:     10,
			NotAfterUnix:      900,
		},
		ServiceAuthKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
		},
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{append([]byte(nil), relayBucketID...)},
		RequestAuthPolicyID:   7,
		ValidFromUnix:         10,
		ValidUntilUnix:        900,
		ServiceStatus:         registry.IssuerStatusActive,
	}, priv
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
