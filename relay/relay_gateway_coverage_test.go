package relay

// Adversarial coverage for the pure dispatch / state / policy functions in
// relay/relay.go that the existing relay_test.go HTTP-gateway and active-probe
// tests do not reach. Every case starts from a minimal crafted CoverTemplate /
// CoverRequest / ExitPolicy and asserts the resulting response, with no
// LocalProxy flow or network state touched.
//
// Branch routing note: every rejection path in the dispatch helpers ends in
// g.HandleFailure(FailureInvalidCoverSlot). HandleFailure (96-105) returns the
// 404 "not found" cover only when g.Origin is nil; with a present Origin it
// returns g.Origin.NormalResponse() (the cover-neutral response). So tests that
// exercise a dispatch rejection with no Origin dependency use Gateway{} (nil
// Origin) and assert 404, while tests that need a present, interface-satisfying
// Origin (the SidecarOrigin/ForwardingOrigin type-assertion-fail branches) use a
// real Origin and assert its NormalResponse, additionally checking that no
// forwarding counter advanced to prove the rejection branch — not a forward —
// produced the response.
//
// Dead by design (documented, not contrived):
//   - Gateway.HandleFailure:98-100 (classification.Action != CoverOrigin):
//     failure.Classify (failure/failure.go:90-99) hardcodes Action: CoverOrigin
//     for every Kind, so the non-cover-origin branch is unreachable. Only the
//     nil-Origin guard (101-102) is exercised here.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// coverClassForCoverage builds a single RequestClass for the dispatch tests. It is
// called once per subtest with distinct flags so the targeted branch is reached.
func coverClassForCoverage(id, classType uint64, prelude, capsule bool) protocol.RequestClass {
	return protocol.RequestClass{
		ClassID:         id,
		ClassType:       classType,
		MayCarryPrelude: prelude,
		MayCarryCapsule: capsule,
	}
}

// templateWithSingleClassForCoverage wraps one class in a CoverTemplate so the
// dispatch helpers have exactly one matching slot (or none, for the miss case).
func templateWithSingleClassForCoverage(class protocol.RequestClass) protocol.CoverTemplate {
	return protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{class}}
}

func TestStaticOriginNormalResponseDefaultsStatusToOK(t *testing.T) {
	t.Run("zero status defaults to 200", func(t *testing.T) {
		resp := StaticOrigin{Status: 0, Body: []byte("cover")}.NormalResponse()
		if resp.Status != 200 || string(resp.Body) != "cover" {
			t.Fatalf("zero-status NormalResponse = %+v, want status 200 body %q", resp, "cover")
		}
	})
	t.Run("explicit status passes through", func(t *testing.T) {
		resp := StaticOrigin{Status: 206, Body: []byte("partial")}.NormalResponse()
		if resp.Status != 206 || string(resp.Body) != "partial" {
			t.Fatalf("explicit-status NormalResponse = %+v, want status 206 body %q", resp, "partial")
		}
	})
}

func TestGatewayHandleFailureRejectsNilOrigin(t *testing.T) {
	// A Gateway with no Origin must return the not-found cover response. (The
	// classification.Action != CoverOrigin branch at 98-100 is dead by design —
	// see file header — so only the nil-Origin guard is exercised.)
	resp := Gateway{}.HandleFailure(FailureBadAccessHint)
	if resp.Status != 404 || string(resp.Body) != "not found" {
		t.Fatalf("nil-origin HandleFailure = %+v, want 404 not found", resp)
	}
}

func TestHandleCoverRequestRejectsMissingAndUnknownClass(t *testing.T) {
	// nil Origin so every rejection resolves to the 404 cover response.
	g := Gateway{}
	t.Run("class id not in template", func(t *testing.T) {
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestGatewayOwnedSlot, true, true))
		resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 999, Kind: CoverRequestCapsule})
		if resp.Status != 404 {
			t.Fatalf("unknown class-id produced status %d, want 404", resp.Status)
		}
	})
	t.Run("unknown class type", func(t *testing.T) {
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, 0x09, true, true))
		resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestCapsule})
		if resp.Status != 404 {
			t.Fatalf("unknown class-type produced status %d, want 404", resp.Status)
		}
	})
}

func TestHandleGatewayOwnedRejectsDisallowedKinds(t *testing.T) {
	// nil Origin: every rejection resolves to the 404 cover response, distinct
	// from the present-Origin 200 cover path exercised by the existing tests.
	g := Gateway{}
	t.Run("ordinary request", func(t *testing.T) {
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestGatewayOwnedSlot, true, true))
		if resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestOrdinary}); resp.Status != 404 {
			t.Fatalf("gateway-owned ordinary produced status %d, want 404", resp.Status)
		}
	})
	t.Run("prelude not allowed", func(t *testing.T) {
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestGatewayOwnedSlot, false, true))
		if resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestPrelude}); resp.Status != 404 {
			t.Fatalf("gateway-owned prelude (not allowed) produced status %d, want 404", resp.Status)
		}
	})
	t.Run("capsule not allowed", func(t *testing.T) {
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestGatewayOwnedSlot, true, false))
		if resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestCapsule}); resp.Status != 404 {
			t.Fatalf("gateway-owned capsule (not allowed) produced status %d, want 404", resp.Status)
		}
	})
	t.Run("capsule allowed without failure falls through", func(t *testing.T) {
		// MayCarryCapsule passes and no Failure is set, so the switch falls out
		// and the final HandleFailure(InvalidCoverSlot) at line 156 fires.
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestGatewayOwnedSlot, true, true))
		if resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestCapsule}); resp.Status != 404 {
			t.Fatalf("gateway-owned capsule (no failure) produced status %d, want 404", resp.Status)
		}
	})
}

func TestHandleSidecarOriginRejectsNonSidecarAndDisallowedKinds(t *testing.T) {
	t.Run("origin is not a sidecar", func(t *testing.T) {
		// StaticOrigin implements Origin but not SidecarOrigin, so the type
		// assertion at line 160 fails before any sidecar forwarding; the cover
		// response is produced via HandleFailure -> NormalResponse.
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestSidecarOriginSlot, true, true))
		g := Gateway{Origin: StaticOrigin{Status: 200, Body: []byte("cover")}}
		resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestCapsule})
		if resp.Status != 200 || string(resp.Body) != "cover" {
			t.Fatalf("non-sidecar origin produced %+v, want 200 cover", resp)
		}
	})
	t.Run("prelude not allowed", func(t *testing.T) {
		// A real SidecarOrigin so the type assertion at 160 passes and the Kind
		// switch reaches the MayCarryPrelude guard at 168.
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestSidecarOriginSlot, false, true))
		origin := &recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}
		resp := Gateway{Origin: origin}.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestPrelude})
		if resp.Status != 200 || string(resp.Body) != "cover" {
			t.Fatalf("sidecar prelude (not allowed) produced %+v, want 200 cover", resp)
		}
		if origin.sidecarForwarded != 0 {
			t.Fatalf("disallowed sidecar prelude forwarded %d request(s)", origin.sidecarForwarded)
		}
	})
	t.Run("capsule not allowed", func(t *testing.T) {
		template := templateWithSingleClassForCoverage(
			coverClassForCoverage(1, registry.RequestSidecarOriginSlot, true, false))
		origin := &recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}
		resp := Gateway{Origin: origin}.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestCapsule})
		if resp.Status != 200 || string(resp.Body) != "cover" {
			t.Fatalf("sidecar capsule (not allowed) produced %+v, want 200 cover", resp)
		}
		if origin.sidecarForwarded != 0 {
			t.Fatalf("disallowed sidecar capsule forwarded %d request(s)", origin.sidecarForwarded)
		}
	})
}

func TestForwardVerbatimRejectsNonForwardingOrigin(t *testing.T) {
	// StaticOrigin implements Origin but not ForwardingOrigin, so the pass-through
	// route's type assertion (line 182) fails and HandleFailure -> NormalResponse
	// returns the cover response without forwarding. StaticOrigin has no
	// ForwardRequest method, so this response can only come from line 185.
	template := templateWithSingleClassForCoverage(
		coverClassForCoverage(1, registry.RequestOriginPassThrough, true, true))
	g := Gateway{Origin: StaticOrigin{Status: 200, Body: []byte("cover")}}
	resp := g.HandleCoverRequest(CoverRequest{Template: template, ClassID: 1, Kind: CoverRequestOrdinary, Body: []byte("body")})
	if resp.Status != 200 || string(resp.Body) != "cover" {
		t.Fatalf("non-forwarding pass-through produced %+v, want 200 cover", resp)
	}
}

func TestCoverRequestFailureOrDefault(t *testing.T) {
	t.Run("zero failure defaults to invalid slot", func(t *testing.T) {
		if got := (CoverRequest{}).failureOrDefault(); got != FailureInvalidCoverSlot {
			t.Fatalf("failureOrDefault(zero) = %v, want FailureInvalidCoverSlot", got)
		}
	})
	t.Run("explicit failure preserved", func(t *testing.T) {
		if got := (CoverRequest{Failure: FailureBadAEADTag}).failureOrDefault(); got != FailureBadAEADTag {
			t.Fatalf("failureOrDefault(BadAEADTag) = %v, want FailureBadAEADTag", got)
		}
	})
}

func TestFindRequestClassMissesUnknownID(t *testing.T) {
	template := templateWithSingleClassForCoverage(
		coverClassForCoverage(1, registry.RequestGatewayOwnedSlot, true, true))
	if _, ok := findRequestClass(template, 999); ok {
		t.Fatal("findRequestClass reported a hit for an unknown class id")
	}
}

func TestSessionMarkPreludeVerifiedRejectsUnsupportedSuite(t *testing.T) {
	s := NewSession()
	if err := s.MarkPreludeVerified(0xdeadbeef); err == nil {
		t.Fatal("MarkPreludeVerified accepted an unsupported suite")
	}
	if s.preludeVerified {
		t.Fatal("unsupported-suite MarkPreludeVerified left preludeVerified set")
	}
}

func TestExitPolicyAllowIPEdgeCases(t *testing.T) {
	t.Run("allow private when permitted", func(t *testing.T) {
		policy := ExitPolicy{AllowPrivate: true}
		if !policy.AllowIP("127.0.0.1") {
			t.Fatal("AllowPrivate policy rejected a loopback address")
		}
	})
	t.Run("reject malformed address", func(t *testing.T) {
		if DefaultExitPolicy().AllowIP("not-an-ip-address") {
			t.Fatal("AllowIP accepted a malformed address")
		}
	})
}

func TestExitPolicyAllowDomainEdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		policy  ExitPolicy
		domain  string
		allowed bool
	}{
		{"empty rejected", DefaultExitPolicy(), "", false},
		{"allow private overrides localhost", ExitPolicy{AllowPrivate: true}, "localhost", true},
		{"localhost rejected", DefaultExitPolicy(), "localhost", false},
		{"localhost subdomain rejected", DefaultExitPolicy(), "svc.localhost", false},
		{"local rejected", DefaultExitPolicy(), "local", false},
		{"local subdomain rejected", DefaultExitPolicy(), "host.local", false},
		{"home.arpa rejected", DefaultExitPolicy(), "home.arpa", false},
		{"home.arpa subdomain rejected", DefaultExitPolicy(), "node.home.arpa", false},
		{"normal domain allowed", DefaultExitPolicy(), "example.com", true},
		{"trailing dot stripped to allowed", DefaultExitPolicy(), "example.com.", true},
		{"uppercase normalized to allowed", DefaultExitPolicy(), "  Example.COM  ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.AllowDomain(tc.domain); got != tc.allowed {
				t.Fatalf("AllowDomain(%q) AllowPrivate=%v = %v, want %v", tc.domain, tc.policy.AllowPrivate, got, tc.allowed)
			}
		})
	}
}
