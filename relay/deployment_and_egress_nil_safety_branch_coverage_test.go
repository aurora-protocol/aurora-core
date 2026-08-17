package relay

// Adversarial white-box coverage for two count-0 nil-safety guards in the
// relay package: a nil-body default in the cover-origin deployment response
// builder and a nil-flow early return in the socket egress close handler.
//
//   - cover_deployment.go:239 normalDeploymentResponse
//     body == nil -> body = []byte("cover") (fires after the status == 0
//     default at :235, before the Response construction at :242).
//   - socket_egress.go:529 (*SocketEgress).handleFlowClosed
//     flow == nil -> return nil (fires after the FlowID mismatch guard at
//     :523, the e.mu.Lock at :526, the flows map lookup at :527, and the
//     e.mu.Unlock at :528, before the close-code / kind branch at :532).
//
// The existing relay tests drive normalDeploymentResponse only with a profile
// that carries a real NormalBody (so :235 is covered but :239 stays count-0),
// and drive handleFlowClosed only on an egress with a registered flow (so the
// flow lookup at :527 returns a non-nil flow and :529 stays count-0), even
// though each guard is plainly reachable on a zero-value input.
//
// Proof technique:
//
//   - normalDeploymentResponse (nil-field default): a zero-value
//     CoverOriginDeploymentProfile has NormalStatus == 0 (so :235 sets status =
//     http.StatusOK) and NormalBody == nil (so :239 sets body = []byte("cover")).
//     The returned Response has Status == 200 and Body == "cover"; the Body
//     assertion uniquely proves the :239 default ran (the only site that sets
//     body to "cover"). Pure (no IO; it only assembles a Response).
//
//   - handleFlowClosed (nil-field clean return): a zero-value &SocketEgress{}
//     has flows == nil and a usable zero-value mu. An ExitFrameEvent with
//     matching FlowID and Close.FlowID (both 1) passes the :523 mismatch guard,
//     the :527 nil-map lookup returns the zero value (nil), and :529 returns
//     nil before the close-code / kind branch at :532 ever touches the flow.
//     Reading a nil map is a well-defined no-op, so the lookup is safe. The
//     err == nil result uniquely proves :529 ran: with matching FlowIDs and a
//     nil flow, :523 does not fire (it returns ErrExitEventInvalid, non-nil) and
//     :529 is the only nil-return on this path. Pure (no network — the egress
//     has no dialer / sink and the guard returns before any flow field is
//     touched).
//
// Neither guard involves a context at the guard site, so there is no SA1012
// surface. In-package (package relay) because normalDeploymentResponse and
// handleFlowClosed are unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (normalDeploymentResponse, handleFlowClosed,
// CoverOriginDeploymentProfile, SocketEgress, ExitFrameEvent) symbols and the
// exported protocol.FlowClose type, so it adds no U1000 surface.

import (
	"net/http"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestNormalDeploymentResponseNilBodyDefaultGuard(t *testing.T) {
	// 239: a zero-value CoverOriginDeploymentProfile has NormalStatus == 0
	// (so :235 sets status = http.StatusOK) and NormalBody == nil (so :239 sets
	// body = []byte("cover")). The Body == "cover" assertion uniquely proves the
	// :239 default ran.
	got := normalDeploymentResponse(CoverOriginDeploymentProfile{})
	if got.Status != http.StatusOK {
		t.Fatalf("normalDeploymentResponse(zero profile) Status = %d, want %d (:235 status default)", got.Status, http.StatusOK)
	}
	if string(got.Body) != "cover" {
		t.Fatalf("normalDeploymentResponse(zero profile) Body = %q, want \"cover\" (:239 body default)", string(got.Body))
	}
}

func TestSocketEgressHandleFlowClosedNilFlowGuard(t *testing.T) {
	// 529: a zero-value SocketEgress has flows == nil and a usable zero-value
	// mu. An ExitFrameEvent with matching FlowID / Close.FlowID (both 1) passes
	// the :523 mismatch guard; the :527 nil-map lookup returns nil; :529 returns
	// nil before the close-code / kind branch at :532. err == nil uniquely proves
	// :529 ran (with matching FlowIDs :523 does not fire, and :529 is the only
	// nil-return on this path).
	e := &SocketEgress{}
	err := e.handleFlowClosed(ExitFrameEvent{FlowID: 1, Close: protocol.FlowClose{FlowID: 1}})
	if err != nil {
		t.Fatalf("handleFlowClosed(zero egress, unknown flow) err = %v, want nil (:529 returns nil for an unknown flow)", err)
	}
}
