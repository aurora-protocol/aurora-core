package client

// Adversarial white-box coverage for three count-0 nil-field lazy-init guards
// in the client options normalizers. Each `normalize*` function applies a
// default to an unexported function-typed field when the caller left it nil.
// The existing client tests only ever drive these normalizers through the
// production entry points that already populate `now` / `start` / `Now`, so the
// `== nil` lazy-init branch stayed count-0 even though each is plainly
// reachable by passing a zero-value options struct.
//
//   - provisioned_session.go:306 normalizeProvisionedSessionOptions
//     options.now == nil -> options.now = time.Now (fires before the
//     options.start == nil guard at :312 and the final return at :315).
//   - provisioned_session.go:312 normalizeProvisionedSessionOptions
//     options.start == nil -> options.start = startProvisionedSession (fires
//     after the :306 now guard, before the final return at :315).
//   - packet_tun_runtime.go:70 normalizePacketTUNRuntimeOptions
//     options.Now == nil -> options.Now = time.Now (fires after the
//     ReadBufferBytes default at :65 and the range check at :67, before the
//     final return at :73).
//
// Proof technique (nil-field lazy-init, matches the AuthorizeRelayClientKey
// proof): pass a zero-value options struct so the field is nil, invoke the
// normalizer, and assert the returned field is non-nil. With a nil input field
// the `== nil` branch MUST run (nothing else sets the field), so a non-nil
// output uniquely proves the lazy-init branch executed — the fall-through would
// leave the field nil. The function-typed fields are the only sites that
// populate now / start / Now, so the non-nil output cannot come from any other
// path.
//
// No context is involved (the normalize functions take none), so there is no
// SA1012 surface. No network, no goroutine, no real device — each guard only
// assigns a function value, so the test is pure. In-package (package client)
// because normalizeProvisionedSessionOptions / normalizePacketTUNRuntimeOptions
// and the now / start fields (and the provisionedSessionStarter type) are
// unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package symbols, so it adds no U1000 surface.

import (
	"testing"
)

func TestNormalizeProvisionedSessionOptionsNilNowLazyInit(t *testing.T) {
	// 306: a zero-value options has now == nil, so the :306 lazy-init branch
	// runs and sets now = time.Now. The proof is the returned now is non-nil:
	// nothing else in the normalizer populates now, so a non-nil output can
	// only come from the :306 branch.
	got := normalizeProvisionedSessionOptions(ProvisionedSessionOptions{})
	if got.now == nil {
		t.Fatal("normalizeProvisionedSessionOptions() now = nil, want non-nil (:306 lazy-init should set time.Now)")
	}
}

func TestNormalizeProvisionedSessionOptionsNilStartLazyInit(t *testing.T) {
	// 312: a zero-value options has start == nil, so the :312 lazy-init branch
	// runs and sets start = startProvisionedSession. The proof is the returned
	// start is non-nil: nothing else in the normalizer populates start.
	got := normalizeProvisionedSessionOptions(ProvisionedSessionOptions{})
	if got.start == nil {
		t.Fatal("normalizeProvisionedSessionOptions() start = nil, want non-nil (:312 lazy-init should set startProvisionedSession)")
	}
}

func TestNormalizePacketTUNRuntimeOptionsNilNowLazyInit(t *testing.T) {
	// 70: a zero-value options has ReadBufferBytes == 0 (-> default at :65,
	// which passes the :67 range check) and Now == nil, so the :70 lazy-init
	// branch runs and sets Now = time.Now. The proof is the returned Now is
	// non-nil and err is nil (the default buffer size is within the valid
	// range, so the :67 validation does not reject).
	got, err := normalizePacketTUNRuntimeOptions(PacketTUNRuntimeOptions{})
	if err != nil {
		t.Fatalf("normalizePacketTUNRuntimeOptions() err = %v, want nil (zero-value ReadBufferBytes should default to a valid size)", err)
	}
	if got.Now == nil {
		t.Fatal("normalizePacketTUNRuntimeOptions() Now = nil, want non-nil (:70 lazy-init should set time.Now)")
	}
}
