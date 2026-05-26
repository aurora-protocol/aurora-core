package relay

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/aurora-protocol/aurora-core/cover"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
)

type CoverOriginDeploymentProfile struct {
	Template     protocol.CoverTemplate
	Routes       []HTTPGatewayRoute
	NowUnix      uint64
	MaxBodyBytes int64
	NormalStatus int
	NormalBody   []byte
}

type CoverOriginDeploymentReport struct {
	Passed                     bool
	TemplateValidated          bool
	GatewayOwnedFailureNeutral bool
	SidecarFailureSanitized    bool
	PassThroughForwarded       bool
	OversizeFailureNeutral     bool
	ActiveProbeNeutral         bool
	Findings                   []string
}

func RunCoverOriginDeploymentHarness(nowUnix uint64) (CoverOriginDeploymentReport, error) {
	profile, err := DefaultCoverOriginDeploymentProfile(nowUnix)
	if err != nil {
		return CoverOriginDeploymentReport{}, err
	}
	return VerifyCoverOriginDeployment(profile)
}

func DefaultCoverOriginDeploymentProfile(nowUnix uint64) (CoverOriginDeploymentProfile, error) {
	tpl, err := coverOriginDeploymentTemplate()
	if err != nil {
		return CoverOriginDeploymentProfile{}, err
	}
	return CoverOriginDeploymentProfile{
		Template: tpl,
		Routes: []HTTPGatewayRoute{{
			Path:    "/bootstrap.bin",
			ClassID: 1,
			Kind:    CoverRequestCapsule,
			Failure: FailureBadAEADTag,
		}, {
			Path:    "/assets/app.bin",
			ClassID: 2,
			Kind:    CoverRequestOrdinary,
		}, {
			Path:    "/sidecar/upload",
			ClassID: 3,
			Kind:    CoverRequestCapsule,
			Failure: FailureBadAEADTag,
		}},
		NowUnix:      nowUnix,
		MaxBodyBytes: defaultHTTPGatewayMaxBodyBytes,
		NormalStatus: http.StatusOK,
		NormalBody:   []byte("cover"),
	}, nil
}

func VerifyCoverOriginDeployment(profile CoverOriginDeploymentProfile) (CoverOriginDeploymentReport, error) {
	report := CoverOriginDeploymentReport{}
	if err := cover.ValidateTemplate(profile.Template, cover.ValidationOptions{NowUnix: profile.NowUnix, MaxFutureSkew: 120}); err != nil {
		report.addFinding("cover template validation failed")
	} else {
		report.TemplateValidated = true
	}

	origin := &coverDeploymentProbeOrigin{normal: normalDeploymentResponse(profile)}
	handler := HTTPGatewayHandler{
		Gateway:      Gateway{Origin: origin},
		Template:     profile.Template,
		Routes:       profile.Routes,
		MaxBodyBytes: profile.MaxBodyBytes,
	}
	report.GatewayOwnedFailureNeutral = verifyGatewayOwnedDeploymentFailure(handler, origin, profile, &report)
	report.SidecarFailureSanitized = verifySidecarDeploymentFailure(handler, origin, profile, &report)
	report.PassThroughForwarded = verifyPassThroughDeployment(handler, origin, &report)
	report.OversizeFailureNeutral = verifyOversizeDeploymentFailure(handler, origin, profile, &report)
	report.ActiveProbeNeutral = verifyDeploymentActiveProbes(handler, origin, profile, &report)

	report.Passed = report.TemplateValidated &&
		report.GatewayOwnedFailureNeutral &&
		report.SidecarFailureSanitized &&
		report.PassThroughForwarded &&
		report.OversizeFailureNeutral &&
		report.ActiveProbeNeutral
	return report, nil
}

func verifyGatewayOwnedDeploymentFailure(handler HTTPGatewayHandler, origin *coverDeploymentProbeOrigin, profile CoverOriginDeploymentProfile, report *CoverOriginDeploymentReport) bool {
	route, ok := deploymentRouteForClassType(profile.Template, profile.Routes, registry.RequestGatewayOwnedSlot, CoverRequestCapsule)
	if !ok {
		report.addFinding("no gateway-owned capsule route configured")
		return false
	}
	before := origin.snapshot()
	resp := serveDeploymentRequest(handler, route.Path, "raw sensitive gateway capsule")
	after := origin.snapshot()
	if !sameGatewayResponse(resp, origin.normal) {
		report.addFinding("gateway-owned failure did not return ordinary origin response")
		return false
	}
	if after.anyForwardedDelta(before) || after.failureLogs != before.failureLogs {
		report.addFinding("gateway-owned failure leaked body to upstream origin")
		return false
	}
	return true
}

func verifySidecarDeploymentFailure(handler HTTPGatewayHandler, origin *coverDeploymentProbeOrigin, profile CoverOriginDeploymentProfile, report *CoverOriginDeploymentReport) bool {
	route, ok := deploymentRouteForClassType(profile.Template, profile.Routes, registry.RequestSidecarOriginSlot, CoverRequestCapsule)
	if !ok {
		return true
	}
	before := origin.snapshot()
	resp := serveDeploymentRequest(handler, route.Path, "raw sensitive sidecar capsule")
	after := origin.snapshot()
	if !sameGatewayResponse(resp, origin.normal) {
		report.addFinding("sidecar failure did not return ordinary origin response")
		return false
	}
	if after.httpSidecarForwarded != before.httpSidecarForwarded || after.sidecarForwarded != before.sidecarForwarded {
		report.addFinding("sidecar failure forwarded failed capsule body")
		return false
	}
	if after.failureLogs != before.failureLogs+1 || len(after.lastFailureLog.Body) != 0 || after.lastFailureLog.Code == "" {
		report.addFinding("sidecar failure log was not redacted")
		return false
	}
	return true
}

func verifyPassThroughDeployment(handler HTTPGatewayHandler, origin *coverDeploymentProbeOrigin, report *CoverOriginDeploymentReport) bool {
	route, ok := deploymentRouteForClassType(handler.Template, handler.Routes, registry.RequestOriginPassThrough, CoverRequestOrdinary)
	if !ok {
		report.addFinding("no origin pass-through route configured")
		return false
	}
	before := origin.snapshot()
	body := "ordinary-origin-body"
	resp := serveDeploymentRequest(handler, route.Path, body)
	after := origin.snapshot()
	if resp.Status != http.StatusNoContent {
		report.addFinding("origin pass-through route did not forward ordinary request")
		return false
	}
	if after.httpForwarded != before.httpForwarded+1 || after.lastPath != route.Path || !bytes.Equal(after.lastHTTPBody, []byte(body)) {
		report.addFinding("origin pass-through request was not forwarded verbatim")
		return false
	}
	return true
}

func verifyOversizeDeploymentFailure(handler HTTPGatewayHandler, origin *coverDeploymentProbeOrigin, profile CoverOriginDeploymentProfile, report *CoverOriginDeploymentReport) bool {
	route, ok := deploymentRouteForClassType(profile.Template, profile.Routes, registry.RequestOriginPassThrough, CoverRequestOrdinary)
	if !ok {
		return false
	}
	handler.MaxBodyBytes = 4
	before := origin.snapshot()
	resp := serveDeploymentRequest(handler, route.Path, "too-large")
	after := origin.snapshot()
	if !sameGatewayResponse(resp, origin.normal) {
		report.addFinding("oversize request did not map to ordinary origin response")
		return false
	}
	if after.anyForwardedDelta(before) {
		report.addFinding("oversize request was forwarded upstream")
		return false
	}
	return true
}

func verifyDeploymentActiveProbes(handler HTTPGatewayHandler, origin *coverDeploymentProbeOrigin, profile CoverOriginDeploymentProfile, report *CoverOriginDeploymentReport) bool {
	routeIndex, ok := deploymentRouteIndexForClassType(profile.Template, profile.Routes, registry.RequestGatewayOwnedSlot, CoverRequestCapsule)
	if !ok {
		return false
	}
	passed := true
	for _, tc := range failure.ActiveProbeCases() {
		handler.Routes = append([]HTTPGatewayRoute(nil), profile.Routes...)
		handler.Routes[routeIndex].Failure = tc.Kind
		before := origin.snapshot()
		resp := serveDeploymentRequest(handler, handler.Routes[routeIndex].Path, "active probe body")
		after := origin.snapshot()
		if !sameGatewayResponse(resp, origin.normal) || after.normalResponses != before.normalResponses+1 || after.anyForwardedDelta(before) || after.failureLogs != before.failureLogs {
			report.addFinding("active probe produced distinguishable deployment behavior")
			passed = false
		}
	}
	return passed
}

func deploymentRouteForClassType(tpl protocol.CoverTemplate, routes []HTTPGatewayRoute, classType uint64, kind CoverRequestKind) (HTTPGatewayRoute, bool) {
	index, ok := deploymentRouteIndexForClassType(tpl, routes, classType, kind)
	if !ok {
		return HTTPGatewayRoute{}, false
	}
	return routes[index], true
}

func deploymentRouteIndexForClassType(tpl protocol.CoverTemplate, routes []HTTPGatewayRoute, classType uint64, kind CoverRequestKind) (int, bool) {
	for i, route := range routes {
		class, ok := findRequestClass(tpl, route.ClassID)
		if !ok || class.ClassType != classType || route.Kind != kind {
			continue
		}
		return i, true
	}
	return 0, false
}

func serveDeploymentRequest(handler HTTPGatewayHandler, path, body string) Response {
	req := httptest.NewRequest(http.MethodPost, "https://cover.example"+path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return Response{Status: rec.Code, Body: rec.Body.Bytes()}
}

func normalDeploymentResponse(profile CoverOriginDeploymentProfile) Response {
	status := profile.NormalStatus
	if status == 0 {
		status = http.StatusOK
	}
	body := profile.NormalBody
	if body == nil {
		body = []byte("cover")
	}
	return Response{Status: status, Body: append([]byte(nil), body...)}
}

type coverDeploymentProbeOrigin struct {
	normal               Response
	normalResponses      int
	forwarded            int
	sidecarForwarded     int
	httpForwarded        int
	httpSidecarForwarded int
	failureLogs          int
	lastPath             string
	lastBody             []byte
	lastSidecarBody      []byte
	lastHTTPBody         []byte
	lastFailureLog       RedactedFailureLog
}

func (o *coverDeploymentProbeOrigin) NormalResponse() Response {
	o.normalResponses++
	return Response{Status: o.normal.Status, Body: append([]byte(nil), o.normal.Body...), CloseCode: o.normal.CloseCode}
}

func (o *coverDeploymentProbeOrigin) ForwardRequest(body []byte) Response {
	o.forwarded++
	o.lastBody = append([]byte(nil), body...)
	return Response{Status: http.StatusNoContent}
}

func (o *coverDeploymentProbeOrigin) ForwardSidecarRequest(body []byte) Response {
	o.sidecarForwarded++
	o.lastSidecarBody = append([]byte(nil), body...)
	return Response{Status: http.StatusPartialContent}
}

func (o *coverDeploymentProbeOrigin) RecordSidecarFailure(log RedactedFailureLog) {
	o.failureLogs++
	o.lastFailureLog = log
}

func (o *coverDeploymentProbeOrigin) ForwardHTTPRequest(req *http.Request, body []byte) Response {
	o.httpForwarded++
	o.lastPath = req.URL.Path
	o.lastHTTPBody = append([]byte(nil), body...)
	return Response{Status: http.StatusNoContent}
}

func (o *coverDeploymentProbeOrigin) ForwardSidecarHTTPRequest(req *http.Request, body []byte) Response {
	o.httpSidecarForwarded++
	o.lastPath = req.URL.Path
	o.lastHTTPBody = append([]byte(nil), body...)
	return Response{Status: http.StatusPartialContent}
}

func (o *coverDeploymentProbeOrigin) snapshot() coverDeploymentProbeOrigin {
	out := *o
	out.lastBody = append([]byte(nil), o.lastBody...)
	out.lastSidecarBody = append([]byte(nil), o.lastSidecarBody...)
	out.lastHTTPBody = append([]byte(nil), o.lastHTTPBody...)
	out.lastFailureLog.Body = append([]byte(nil), o.lastFailureLog.Body...)
	return out
}

func (o coverDeploymentProbeOrigin) anyForwardedDelta(before coverDeploymentProbeOrigin) bool {
	return o.forwarded != before.forwarded ||
		o.sidecarForwarded != before.sidecarForwarded ||
		o.httpForwarded != before.httpForwarded ||
		o.httpSidecarForwarded != before.httpSidecarForwarded
}

func coverOriginDeploymentTemplate() (protocol.CoverTemplate, error) {
	tpl := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       repeatedRelayByte(0x01, 16),
		TemplateFamilyID: repeatedRelayByte(0x02, 16),
		ValidFromUnix:    100,
		ValidUntilUnix:   300,
		OriginSPKIHash:   repeatedRelayByte(0x03, 48),
		PublicNameHash:   repeatedRelayByte(0x04, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             1,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      repeatedRelayByte(0x05, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}, {
			ClassID:             2,
			ClassType:           registry.RequestOriginPassThrough,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      repeatedRelayByte(0x06, 16),
		}, {
			ClassID:             3,
			ClassType:           registry.RequestSidecarOriginSlot,
			AllowedMethodFamily: registry.MethodShadowOrigin,
			PathTemplateID:      repeatedRelayByte(0x07, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{repeatedRelayByte(0x08, 48)},
		OriginPassThroughSlotCommitments: [][]byte{repeatedRelayByte(0x09, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1200,
			MaxRequestBodySize:         1536,
			RequestSizeDistributionID:  repeatedRelayByte(0x0a, 16),
			MinResponseBodySize:        5000,
			MaxResponseBodySize:        6144,
			ResponseSizeDistributionID: repeatedRelayByte(0x0b, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               repeatedRelayByte(0x0c, 16),
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   repeatedRelayByte(0x0d, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                1,
			RecordSizeDistributionID: repeatedRelayByte(0x0e, 16),
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  2,
			DatagramSizeDistributionID: repeatedRelayByte(0x0f, 16),
			DatagramRateDistributionID: repeatedRelayByte(0x10, 16),
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               3,
			FrameSizeDistributionID: repeatedRelayByte(0x11, 16),
		},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: repeatedRelayByte(0x12, 16)},
	}
	commitment, err := trust.CoverOriginCommitment(tpl)
	if err != nil {
		return protocol.CoverTemplate{}, err
	}
	tpl.CoverOriginCommitment = commitment
	return tpl, nil
}

func (r *CoverOriginDeploymentReport) addFinding(finding string) {
	r.Findings = append(r.Findings, finding)
}

func repeatedRelayByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
