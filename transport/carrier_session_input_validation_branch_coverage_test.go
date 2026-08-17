package transport

// Adversarial white-box coverage for the five count-0 input-validation guards
// of CarrierSession construction and send (transport/session.go:30 / :36 /
// :74 / :85 / :94). The existing transport tests drive the happy paths
// (NewCarrierSession with a properly-built BuiltCarrierRequest; SendStream /
// SendDatagram with non-empty data on a configured session), so the
// construction-failure guards (:30 / :36) and the empty-payload / no-path
// fallbacks (:74 / :85 / :94) stayed COUNT 0 in the baseline.
//
// NewCarrierSession(built BuiltCarrierRequest) (CarrierSession, error) (:29):
//   - :30  built.MethodID == 0
//            -> "transport: carrier session missing method id"
//   - :33  built.StreamFallback && built.NativeDatagrams   (COVERED, :33)
//   - :36  !built.StreamFallback && !built.NativeDatagrams
//            -> "transport: carrier session missing datagram mode"
//
// SendStream(data []byte) (CarrierPayload, error) (:73):
//   - :74  len(data) == 0 -> "transport: empty carrier stream payload"
//
// SendDatagram(data []byte) (CarrierPayload, error) (:84):
//   - :85  len(data) == 0 -> "transport: empty carrier datagram payload"
//   - :88  s.nativeDatagrams -> happy path                 (COVERED)
//   - :91  s.streamFallback  -> SendStream happy path      (COVERED)
//   - :94  fallthrough (neither flag)
//            -> "transport: carrier session has no datagram path"
//
// None of these are dead-by-design. :30 / :36 are the FIRST guards of
// NewCarrierSession — nothing runs before :30, and :33 (both-flags) does not
// dominate :36 (neither-flags); they are defensive validation of a
// hand-built/zero-value BuiltCarrierRequest (all fields exported, so a caller
// can bypass BuildCarrierRequest entirely — the constructor is a separate
// entry point, not in SendDatagram's path, same reasoning that makes :94
// reachable despite NewCarrierSession rejecting a neither-flag session).
// :74 / :85 / :94 are the send methods' own first/fallback guards. None are
// re-validation of an upstream check IN THE SAME call path (contrast with the
// switch-fallthrough-dominated class, e.g. protocol/records.go:59, where the
// dominating default runs in the same function before the switch).
//
// All five are pure (value receiver / value arg, no crypto, no network, no
// cgo, no finalizers). The per-line coverage flip (0 -> 1+ per guard body) is
// the rigorous proof.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestCarrierSessionRejectsInvalidConstructionAndSendInput(t *testing.T) {
	// A zero-value CarrierSession has neither nativeDatagrams nor
	// streamFallback; a zero-value BuiltCarrierRequest has MethodID == 0 and
	// neither flag. These are exactly the inputs the guards under test defend
	// against.
	cases := []struct {
		name    string
		call    func() error
		wantSub string
	}{
		{
			// session.go:30 — NewCarrierSession's FIRST guard; a zero-value
			// BuiltCarrierRequest has MethodID == 0.
			name:    "carrier session missing method id",
			call:    func() error { _, err := NewCarrierSession(BuiltCarrierRequest{}); return err },
			wantSub: "transport: carrier session missing method id",
		},
		{
			// session.go:36 — MethodID set (passes :30), not both flags (passes
			// :33), neither flag -> :36 fires before validateCarrierSessionMode
			// (:39, which would otherwise report "requires stream fallback").
			name: "carrier session missing datagram mode",
			call: func() error {
				_, err := NewCarrierSession(BuiltCarrierRequest{MethodID: registry.MethodWebH2Stream})
				return err
			},
			wantSub: "transport: carrier session missing datagram mode",
		},
		{
			// session.go:74 — SendStream's FIRST guard; empty data.
			name:    "empty carrier stream payload",
			call:    func() error { _, err := CarrierSession{}.SendStream(nil); return err },
			wantSub: "transport: empty carrier stream payload",
		},
		{
			// session.go:85 — SendDatagram's FIRST guard; empty data fires
			// before the nativeDatagrams/streamFallback checks.
			name:    "empty carrier datagram payload",
			call:    func() error { _, err := CarrierSession{}.SendDatagram(nil); return err },
			wantSub: "transport: empty carrier datagram payload",
		},
		{
			// session.go:94 — non-empty data passes :85; the zero-value session
			// has nativeDatagrams == false (skips :88) and streamFallback == false
			// (skips :91), so the :94 no-datagram-path fallback fires.
			name:    "carrier session has no datagram path",
			call:    func() error { _, err := CarrierSession{}.SendDatagram([]byte("x")); return err },
			wantSub: "transport: carrier session has no datagram path",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.call()
			if err == nil || !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("%s: err = %v, want non-nil containing %q", c.name, err, c.wantSub)
			}
		})
	}
}
