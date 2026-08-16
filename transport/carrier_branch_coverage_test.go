package transport

// Adversarial white-box coverage for the uncovered branches of
// transport/carrier.go. carrier.go builds the visible HTTP/WebSocket/HTTP3/
// MASQUE carrier requests; the uncovered branches are its input-validation
// guards and helper edge cases, not the live network path. Every test below
// drives a guard that returns BEFORE any real HTTP request is constructed (the
// cover-gated and url/header validators) or calls a pure helper directly, so
// no connection is opened and no goroutine is spawned. The single crypto
// surface is websocketKey(nil), which calls crypto/rand.Read — that succeeds
// deterministically and returns a valid base64 key (the rand.Read FAILURE branch
// is dead-by-design and documented below).
//
// Targets covered:
//
// Pure validation helpers (direct white-box calls):
//   - carrierURL:287-288 — the `authority == ""` guard. The existing suite
//     always passes a non-empty authority, so the empty-authority return is
//     unreached.
//   - carrierURL:290-291 — the `!strings.HasPrefix(path, "/")` guard. The
//     existing suite always passes a slash-leading path.
//   - initialPayloads:275-276 — the `len(payload) == 0` short-circuit returning
//     nil. The existing suite passes non-empty payloads.
//   - validateMasque:242-243 — the `in.Plan.UDPMode != UDPNativeDatagram`
//     guard, reached after the visible-opt-in check (239) passes. The existing
//     MASQUE conformance case always uses native datagram mode.
//   - validateH3ExtDatagram:249-250 — the `in.Plan.UDPMode != UDPNativeDatagram`
//     guard. The existing H3 conformance case uses native datagram mode.
//   - validateH3ExtDatagram:259-260 — the `profile.WebTransportProfileID == 0`
//     guard, reached after SupportsH3Datagram and SupportsWebTransportH3 pass.
//     The existing H3 conformance template sets a non-zero profile id.
//   - ValidateVisibleHeaders:337-338 — the public wrapper's body. The existing
//     suite exercises the unexported validateVisibleHeaders via the builders
//     and never calls the exported wrapper directly, so its body is unreached.
//   - websocketKey:367-371 — the empty-seed branch, which mints a fresh 16-byte
//     seed via rand.Read. The existing suite always passes an explicit 16-byte
//     seed, so the empty-seed branch is unreached.
//   - websocketKey:373-374 — the `len(seed) != 16` guard. The existing suite
//     always passes a 16-byte seed (or none, handled above), so the wrong-length
//     return is unreached.
//
// Cover-gated builder error returns (no network: the error returns before any
// HTTP request is constructed):
//   - BuildStreamingH2CarrierRequest:73-74 — the cover.SelectCarrierClass error
//     propagation. The existing streaming-H2 suite always passes a template
//     whose class matches the request, so SelectCarrierClass succeeds and the
//     propagation return is unreached. An empty template (no request classes)
//     makes SelectGatewayOwnedClass report "request class not found", which the
//     streaming builder surfaces after its three easy guards (method family,
//     stream-fallback mode, empty payload) pass.
//   - BuildCarrierRequest:162-163 — the websocketKey error propagation on the
//     H1 WebSocket path. The existing H1WS conformance case passes a nil seed
//     (minted to 16 bytes), so the wrong-length propagation is unreached. A
//     valid H1WS cover template plus a 3-byte WebSocketKeySeed reaches
//     websocketKey:373 and the builder propagates it.
//   - BuildCarrierRequest:212-213 — the `default` "unsupported method" return.
//     The existing suite drives every real method family, so the default is
//     unreached. A template whose request class advertises AllowedMethodFamily
//     0xBAD lets cover selection succeed for an otherwise-unknown method, after
//     which the builder switch falls through to the default rejection.
//
// Dead-by-design (documented, NOT claimed):
//   - newCarrierHTTPRequest:304-305 and every BuildCarrierRequest/
//     buildMasqueRequest/BuildStreamingH2CarrierRequest newCarrierHTTPRequest
//     propagation (93, 132, 145, 167, 180, 196, 224) — http.NewRequest fails
//     only on a malformed URL or an invalid method. The URL is built by
//     carrierURL (which already rejects non-https schemes, empty authority,
//     non-slash paths, paths with ?# delimiters, and forbidden wire markers)
//     and the methods are the valid POST/GET/CONNECT constants, so the request
//     constructor cannot fail once carrierURL has validated the target.
//     Validated-input-can't-fail.
//   - websocketKey:369-370 — the crypto/rand.Read error. rand.Read fails only
//     on a system entropy shortage that a unit test cannot induce and that does
//     not occur in the CI environment. System-entropy-gated.
//
// The single new package-level helper gatewayOwnedClassTemplate is referenced by
// both builder tests below, so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no real network or
// filesystem.

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// gatewayOwnedClassTemplate builds a CoverTemplate whose single request class
// advertises the given method family, used to drive cover selection to success
// for an otherwise-unusual method (so the carrier builder reaches the branch
// under test rather than failing inside SelectCarrierClass).
func gatewayOwnedClassTemplate(methodFamily uint64) protocol.CoverTemplate {
	return protocol.CoverTemplate{
		RequestClasses: []protocol.RequestClass{{
			ClassID:             1,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: methodFamily,
			PathTemplateID:      bytes.Repeat([]byte{0x11}, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
	}
}

func TestCarrierURLRejectsEmptyAuthority(t *testing.T) {
	// 287-288: a valid https scheme and slash-leading path but an empty
	// authority fails the authority guard before the path/marker checks.
	_, err := carrierURL("https", "", "/x")
	if err == nil || !strings.Contains(err.Error(), "authority is empty") {
		t.Fatalf("carrierURL(empty authority) err = %v, want substring \"authority is empty\"", err)
	}
}

func TestCarrierURLRejectsNonSlashPath(t *testing.T) {
	// 290-291: a non-empty authority but a path that does not start with '/'
	// fails the path guard. (The scheme check at 284 and the authority check at
	// 287 both pass for these inputs.)
	_, err := carrierURL("https", "cover.example", "no-slash")
	if err == nil || !strings.Contains(err.Error(), "path must start with /") {
		t.Fatalf("carrierURL(non-slash path) err = %v, want substring \"path must start with /\"", err)
	}
}

func TestInitialPayloadsReturnsNilForEmpty(t *testing.T) {
	// 275-276: an empty payload short-circuits to nil rather than a one-element
	// slice holding an empty byte slice.
	if got := initialPayloads(nil); got != nil {
		t.Fatalf("initialPayloads(nil) = %v, want nil", got)
	}
	if got := initialPayloads([]byte{}); got != nil {
		t.Fatalf("initialPayloads(empty) = %v, want nil", got)
	}
	// Non-empty payload still yields a single independent copy.
	got := initialPayloads([]byte{0x41})
	if len(got) != 1 || len(got[0]) != 1 || got[0][0] != 0x41 {
		t.Fatalf("initialPayloads(non-empty) = %v, want [[0x41]]", got)
	}
}

func TestValidateMasqueRejectsNonNativeDatagramMode(t *testing.T) {
	// 242-243: the visible-opt-in check (239) passes, then the UDP-mode guard
	// rejects a non-native datagram mode.
	err := validateMasque(CarrierRequestInput{
		AllowVisibleProxySemantics: true,
		Plan:                       CarrierPlan{UDPMode: UDPOverStreamFallback},
	})
	if err == nil || !strings.Contains(err.Error(), "native datagram mode") {
		t.Fatalf("validateMasque(stream fallback) err = %v, want substring \"native datagram mode\"", err)
	}
}

func TestValidateH3ExtDatagramRejectsNonNativeDatagramMode(t *testing.T) {
	// 249-250: a non-native UDP mode fails the first H3-ext-datagram guard
	// before the profile fields are inspected.
	err := validateH3ExtDatagram(CarrierRequestInput{
		Plan: CarrierPlan{UDPMode: UDPOverStreamFallback},
	})
	if err == nil || !strings.Contains(err.Error(), "native datagram mode") {
		t.Fatalf("validateH3ExtDatagram(stream fallback) err = %v, want substring \"native datagram mode\"", err)
	}
}

func TestValidateH3ExtDatagramRejectsMissingWebTransportProfileID(t *testing.T) {
	// 259-260: native datagram mode plus a profile that supports datagrams and
	// WebTransport but carries a zero WebTransportProfileID fails the
	// profile-id guard.
	err := validateH3ExtDatagram(CarrierRequestInput{
		Plan: CarrierPlan{UDPMode: UDPNativeDatagram},
		Template: protocol.CoverTemplate{H3Profile: protocol.H3CoverProfile{
			SupportsH3Datagram:     true,
			SupportsWebTransportH3: true,
			WebTransportProfileID:  0,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "missing WebTransport profile id") {
		t.Fatalf("validateH3ExtDatagram(zero profile id) err = %v, want substring \"missing WebTransport profile id\"", err)
	}
}

func TestValidateVisibleHeadersPassesForCleanHeader(t *testing.T) {
	// 337-338: the exported wrapper forwards to the unexported validator; a
	// header free of forbidden wire markers passes, exercising the wrapper
	// body (the existing suite calls the unexported form directly).
	if err := ValidateVisibleHeaders(http.Header{"Content-Type": []string{"application/octet-stream"}}); err != nil {
		t.Fatalf("ValidateVisibleHeaders(clean) err = %v, want nil", err)
	}
}

func TestWebsocketKeyMintsSeedWhenEmpty(t *testing.T) {
	// 367-371: a nil/empty seed is replaced by a fresh 16-byte random seed
	// (rand.Read succeeds deterministically) and encoded to a 24-byte base64
	// key. Two empty-seed calls mint independent keys.
	first, err := websocketKey(nil)
	if err != nil {
		t.Fatalf("websocketKey(nil) err = %v, want nil", err)
	}
	if len(first) != 24 {
		t.Fatalf("websocketKey(nil) len = %d, want 24 (base64 of 16 bytes)", len(first))
	}
	second, err := websocketKey([]byte{})
	if err != nil {
		t.Fatalf("websocketKey(empty) err = %v, want nil", err)
	}
	if first == second {
		t.Fatalf("two empty-seed keys matched (%q), want independent random keys", first)
	}
}

func TestWebsocketKeyRejectsWrongSeedLength(t *testing.T) {
	// 373-374: a non-empty seed whose length is not 16 fails the length guard.
	_, err := websocketKey([]byte{0x01, 0x02, 0x03})
	if err == nil || !strings.Contains(err.Error(), "WebSocket key seed length 3, want 16") {
		t.Fatalf("websocketKey(short seed) err = %v, want substring \"WebSocket key seed length 3, want 16\"", err)
	}
}

func TestBuildStreamingH2CarrierRequestSurfacesCoverSelectionError(t *testing.T) {
	// 73-74: the streaming-H2 builder's three easy guards (H2 method family,
	// stream-fallback mode, empty payload) pass, then SelectCarrierClass fails
	// because the template has no request class for the requested id. The
	// cover error is surfaced before any URL or header validation runs.
	_, err := BuildStreamingH2CarrierRequest(CarrierRequestInput{
		Plan:           CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream}, UDPMode: UDPOverStreamFallback},
		Template:       protocol.CoverTemplate{},
		RequestClassID: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "request class not found") {
		t.Fatalf("BuildStreamingH2CarrierRequest(empty template) err = %v, want substring \"request class not found\"", err)
	}
}

func TestBuildCarrierRequestPropagatesWebsocketKeyErrorOnH1WS(t *testing.T) {
	// 162-163: a valid H1WS cover template lets SelectCarrierClass succeed, the
	// URL and visible-header checks pass, then websocketKey fails on a 3-byte
	// seed and the builder propagates the error.
	_, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:             CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH1WS}, UDPMode: UDPOverStreamFallback},
		Template:         gatewayOwnedClassTemplate(registry.MethodWebH1WS),
		RequestClassID:   1,
		NeedCapsule:      true,
		Scheme:           "https",
		Authority:        "cover.example",
		Path:             "/session",
		WebSocketKeySeed: []byte{0x01, 0x02, 0x03},
	})
	if err == nil || !strings.Contains(err.Error(), "WebSocket key seed length 3, want 16") {
		t.Fatalf("BuildCarrierRequest(H1WS short seed) err = %v, want substring \"WebSocket key seed length 3, want 16\"", err)
	}
}

func TestBuildCarrierRequestRejectsUnsupportedMethod(t *testing.T) {
	// 212-213: a template whose request class advertises AllowedMethodFamily
	// 0xBAD lets cover selection succeed for that method (the method-family
	// check inside SelectCarrierClass matches), after which the builder switch
	// falls through to the default rejection.
	_, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:           CarrierPlan{Carrier: Carrier{MethodID: 0xBAD}, UDPMode: UDPOverStreamFallback},
		Template:       gatewayOwnedClassTemplate(0xBAD),
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "cover.example",
		Path:           "/session",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported for method 0xbad") {
		t.Fatalf("BuildCarrierRequest(0xBAD) err = %v, want substring \"unsupported for method 0xbad\"", err)
	}
}
