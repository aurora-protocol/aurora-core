package main

// Adversarial white-box coverage for two count-0 nil-safety guards in the
// auroractl CLI: a nil-argument guard in the load-check subcommand runner and
// a nil-field guard in the visible-carrier-marker formatter.
//
//   - main.go:1170 loadCheckWithRunner
//     runner == nil -> "load-check: carrier load failed" (fires after the
//     flags.Parse / NArg guard at :1164 and the url == "" guard at :1167,
//     before the context.WithTimeout at :1174 and the runner(...) call at
//     :1176, so a nil runner is never invoked).
//   - main.go:1374 visibleCarrierMarker
//     built.Request == nil -> "missing request" (first statement; fires before
//     the built.Request.Host / built.Request.URL dereferences at :1377).
//
// The existing auroractl tests drive loadCheckWithRunner only through
// loadCheck with the real auroraperf.RunCarrierLoad runner (so :1164 / :1167
// are covered but :1170 stays count-0), and drive visibleCarrierMarker only
// with a fully-built carrier request (so :1374 stays count-0 even though it is
// plainly reachable with a zero-value BuiltCarrierRequest).
//
// Proof technique:
//
//   - loadCheckWithRunner (nil-argument clean return): pass args containing a
//     valid --url flag (so flags.Parse at :1164 succeeds with NArg == 0 and the
//     url == "" guard at :1167 passes) and a nil runner. The :1170 guard returns
//     the "carrier load failed" error before the context is created at :1174
//     and before the runner is called at :1176, so no network or goroutine is
//     touched and the test is pure. The assertion on the "carrier load failed"
//     substring uniquely identifies :1170 (the earlier :1164 / :1167 guards
//     return different messages and are not reached because --url is valid and
//     no positional args are passed).
//
//   - visibleCarrierMarker (nil-field clean return): pass a zero-value
//     transport.BuiltCarrierRequest (Request == nil). The :1374 guard returns
//     "missing request" before the built.Request dereferences at :1377, so the
//     test is pure. The equality assertion on "missing request" uniquely proves
//     the :1374 guard ran.
//
// Neither guard involves a context at the guard site (the :1170 guard fires
// before context.WithTimeout at :1174; the :1374 guard takes none), so there is
// no SA1012 surface. In-package (package main) because loadCheckWithRunner and
// visibleCarrierMarker are unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (loadCheckWithRunner, visibleCarrierMarker) symbols and
// the exported transport.BuiltCarrierRequest type, so it adds no U1000 surface.

import (
	"io"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/transport"
)

func TestLoadCheckWithRunnerNilRunnerGuard(t *testing.T) {
	// 1170: a valid --url flag makes flags.Parse at :1164 succeed with NArg == 0
	// and makes *url non-empty so the :1167 url == "" guard passes, so a nil
	// runner reaches :1170, which returns "carrier load failed" before the
	// context is created at :1174 and before the runner is called at :1176. No
	// network or goroutine is touched.
	err := loadCheckWithRunner([]string{"--url=http://example.invalid"}, io.Discard, nil)
	if err == nil {
		t.Fatal("loadCheckWithRunner(nil runner) err = nil, want non-nil (:1170 should reject)")
	} else if !strings.Contains(err.Error(), "carrier load failed") {
		t.Fatalf("loadCheckWithRunner(nil runner) err = %q, want substring \"carrier load failed\" (:1170)", err.Error())
	}
}

func TestVisibleCarrierMarkerNilRequestGuard(t *testing.T) {
	// 1374: a zero-value transport.BuiltCarrierRequest has Request == nil, so
	// the :1374 guard returns "missing request" before the built.Request
	// dereferences at :1377.
	got := visibleCarrierMarker(transport.BuiltCarrierRequest{})
	if got != "missing request" {
		t.Fatalf("visibleCarrierMarker(zero BuiltCarrierRequest) = %q, want \"missing request\" (:1374)", got)
	}
}
